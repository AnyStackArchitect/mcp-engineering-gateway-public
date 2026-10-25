"""Independently enforce every candidate neverallow against an offline model.

This does not turn a failed whole-policy strict build into a PASS. It reports
candidate constraints separately, conservatively including all boolean branches.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import setools
from setools.exception import InvalidType

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--policy', type=Path, required=True)
parser.add_argument('--candidate', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
SOURCE = args.candidate
content = SOURCE.read_text()
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == '5e330cd3472e6a7ef001dc97b730f343b58b7a24f6b383f56410ccd4820e6e26'
tokens = re.findall(r'"(?:\\.|[^"\\])*"|[()]|[^\s()]+', re.sub(r';[^\n]*', '', content))
position = 0


def parse():
    global position
    assert tokens[position] == '('
    position += 1
    value = []
    while tokens[position] != ')':
        if tokens[position] == '(':
            value.append(parse())
        else:
            value.append(tokens[position])
            position += 1
    position += 1
    return value


forms = []
while position < len(tokens):
    forms.append(parse())
assertions = [form for form in forms if form[0] == 'neverallow']
assert len(assertions) == 16
definitions = {}
for form in forms:
    if form[0] == 'typeattributeset' and form[1].startswith('engbox_'):
        definitions.setdefault(form[1], []).append(form[2])


def evaluate(policy_path, constraints):
    policy = setools.SELinuxPolicy(str(policy_path))
    all_types = {str(t) for t in policy.types()}
    cache = {}
    def expand(symbol):
        if symbol not in cache:
            if symbol in definitions:
                cache[symbol] = set().union(*(expression(e) for e in definitions[symbol]))
            else:
                try:
                    cache[symbol] = {str(policy.lookup_type(symbol))}
                except InvalidType:
                    cache[symbol] = {str(t) for t in policy.lookup_typeattr(symbol).expand()}
        return cache[symbol]
    def expression(node):
        if isinstance(node, str):
            return expand(node)
        assert isinstance(node, list) and node
        if node[0] == 'not':
            assert len(node) == 2
            return all_types - expression(node[1])
        if node[0] == 'all':
            assert len(node) == 1
            return all_types
        if node[0] in ('and', 'or', 'xor'):
            assert len(node) == 3
            left, right = expression(node[1]), expression(node[2])
            return {'and': left & right, 'or': left | right, 'xor': left ^ right}[node[0]]
        return set().union(*(expression(x) for x in node))

    access = {}
    expanded_symbols = {}
    for rule in policy.terules():
        if str(rule.ruletype) != 'allow':
            continue
        key = str(rule.source)
        if key not in expanded_symbols:
            expanded_symbols[key] = {str(t) for t in rule.source.expand()}
        if 'engbox_worker_t' not in expanded_symbols[key]:
            continue
        for target in rule.target.expand():
            access.setdefault((str(target), str(rule.tclass)), set()).update(rule.perms)
    results = []
    for number, form in enumerate(constraints, 1):
        assert len(form) == 4 and form[1] == 'engbox_worker_t', 'Unsupported source fails closed'
        target = {'engbox_worker_t'} if form[2] == 'self' else expression(form[2])
        cls, perms = form[3]
        assert isinstance(cls, str) and isinstance(perms, list) and all(isinstance(p, str) for p in perms)
        forbidden = set(perms)
        violations = []
        for name in sorted(target):
            overlap = access.get((name, cls), set()) & forbidden
            if overlap:
                violations.append({'target': name, 'class': cls, 'permissions': sorted(overlap)})
        results.append({'assertion': number, 'source_form': form, 'target_count': len(target),
                        'permission_pairs_checked': len(target) * len(perms), 'violations': violations})
    return results


new = evaluate(args.policy, assertions)
assert not any(entry['violations'] for entry in new), 'Candidate constraint violated'
negative = evaluate(args.policy, [['neverallow', 'engbox_worker_t', 'bin_t', ['file', ['open']]]])
assert negative[0]['violations'], 'Validator must reject observed forbidden access'
result = {'status': 'ALL_16_CANDIDATE_ASSERTIONS_SEMANTICALLY_ENFORCED',
    'candidate_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
    'policy_sha256': hashlib.sha256(args.policy.read_bytes()).hexdigest(),
    'assertion_count': len(assertions), 'negative_impossible_constraint_rejected': True,
    'conditional_branches': 'conservative union of all branches', 'checks': new}
args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k: v for k, v in result.items() if k != 'checks'}))
