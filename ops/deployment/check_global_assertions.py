"""Check every exact vendor assertion against a supplied binary policy snapshot."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import setools

def check(policy_path, base_path, guard_path):
    policy = setools.SELinuxPolicy(str(policy_path))
    content = base_path.read_text()
    guard = guard_path.read_text()
    forms = [x.strip() for x in guard.splitlines() if x.strip() and not x.lstrip().startswith(';')]
    assert len(forms) == len(set(forms)) == 13
    pattern = r'\(deny (base_typeattr_\d+) (memory_device_t|fixed_disk_device_t|scsi_generic_device_t|unlabeled_t) \((chr_file|blk_file|file) \((read|write append|entrypoint)\)\)\)'
    all_types = {str(t) for t in policy.types()}
    constraints = []
    for form in forms:
        match = re.fullmatch(pattern, form)
        assert match, 'Unsupported guard fails closed'
        source, target, cls, perms = match.groups()
        definition = re.findall(r'^\(typeattributeset ' + source + r' (.*)\)$', content, re.M)
        assert len(definition) == 1
        if definition[0] == '(all)':
            sources = set(all_types)
        else:
            expr = re.fullmatch(r'\(not \(([a-zA-Z0-9_ ]+)\) \)', definition[0])
            assert expr, 'Unsupported source expression fails closed'
            symbols = expr[1].split()
            assert len(symbols) == 2
            exempt = set().union(*({str(t) for t in policy.lookup_typeattr(a).expand()} for a in symbols))
            sources = all_types - exempt
        original = form.replace('(deny ', '(neverallow ', 1)
        assert original in content, 'Guard must match an actual native neverallow'
        constraints.append((form, sources, target, cls, set(perms.split())))
    access = {}
    cache = {}
    for rule in policy.terules():
        if str(rule.ruletype) != 'allow':
            continue
        cls, perms = str(rule.tclass), set(rule.perms)
        relevant = [c for c in constraints if c[3] == cls and c[4] & perms]
        if not relevant:
            continue
        dest = {str(t) for t in rule.target.expand()}
        relevant = [c for c in relevant if c[2] in dest]
        if not relevant:
            continue
        key = str(rule.source)
        if key not in cache:
            cache[key] = {str(t) for t in rule.source.expand()}
        for c in relevant:
            for p in c[4] & perms:
                access.setdefault((c[2], cls, p), set()).update(cache[key])
    checks = []
    for form, sources, target, cls, perms in constraints:
        violations = {p: sorted(sources & access.get((target, cls, p), set())) for p in sorted(perms)}
        violations = {p: values for p, values in violations.items() if values}
        checks.append({'constraint': form, 'source_types_checked': len(sources), 'violations': violations})
    return {'status': 'ALL_13_VENDOR_ASSERTIONS_PASS' if all(not c['violations'] for c in checks) else 'VENDOR_ASSERTIONS_FAIL',
        'assertion_count': 13, 'violation_count': sum(bool(c['violations']) for c in checks),
        'conditional_branches': 'conservative union of all branches',
        'policy_sha256': hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        'guard_sha256': hashlib.sha256(guard_path.read_bytes()).hexdigest(), 'checks': checks}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--guard', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = check(args.policy, args.base, args.guard)
    args.output.write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps({k:v for k,v in value.items() if k != 'checks'}))
    sys.exit(0 if value['violation_count'] == 0 else 1)
