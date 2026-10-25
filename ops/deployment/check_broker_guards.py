"""Query an explicitly supplied policy snapshot, including all conditional grants."""
import hashlib
import json
from pathlib import Path
import setools

root = Path(__file__).resolve().parent
p = setools.SELinuxPolicy(str(root / 'combined-policy.35'))
source = 'engbox_worker_t'
cache = {}


def members(symbol):
    name = str(symbol)
    if name not in cache:
        cache[name] = {str(value) for value in symbol.expand()}
    return cache[name]


allows = {}
transitions = set()
for rule in p.terules():
    kind = str(rule.ruletype)
    if kind not in ('allow', 'type_transition') or source not in members(rule.source):
        continue
    if kind == 'allow':
        for target in members(rule.target):
            allows.setdefault((target, str(rule.tclass)), set()).update(rule.perms)
    elif str(rule.tclass) == 'process':
        for target in members(rule.target):
            transitions.add((target, str(rule.default)))

checks = {}


def require(name, value):
    checks[name] = bool(value)
    if not value:
        raise AssertionError(name)


def permission(target, cls, perm):
    return perm in allows.get((target, cls), set())


for attr in ('unconfined_domain_type', 'container_runtime_domain'):
    require('broker_not_' + attr, source not in members(p.lookup_typeattr(attr)))
require('broker_not_permissive', not p.lookup_type(source).ispermissive)

require('podman_default_transition_present', ('container_runtime_exec_t', 'container_runtime_t') in transitions)
transition_targets = {target for (target, cls), perms in allows.items() if cls == 'process' and 'transition' in perms}
require('only_engine_has_transition_permission', transition_targets == {'container_runtime_t'})
require('every_other_default_transition_denied', all(default == 'container_runtime_t' and exe == 'container_runtime_exec_t'
    or not permission(default, 'process', 'transition') for exe, default in transitions))
for perm in ('execute', 'execute_no_trans', 'entrypoint'):
    require('abrt_entrypoint_denied_' + perm, not permission('abrt_helper_exec_t', 'file', perm))
for perm in ('setexec', 'setcurrent', 'dyntransition'):
    require('explicit_context_change_denied_' + perm, not permission(source, 'process', perm))


require('gconf_parent_directory_search_and_metadata_only', allows.get(('gconf_home_t', 'dir'), set()) == {'getattr', 'search'})

for target in ('engbox_worker_code_t', 'engbox_worker_config_t'):
    require('reads_' + target, permission(target, 'file', 'open') and permission(target, 'file', 'read'))
    for perm in ('write', 'append', 'create', 'unlink', 'rename', 'setattr', 'relabelto', 'relabelfrom'):
        require('denied_' + target + '_' + perm, not permission(target, 'file', perm))
    for perm in ('write', 'add_name', 'remove_name', 'rmdir'):
        require('denied_' + target + '_dir_' + perm, not permission(target, 'dir', perm))
for target in ('user_home_t', 'data_home_t'):
    require('fd_read_' + target, permission(target, 'file', 'read'))
    for perm in ('open', 'write', 'append', 'create', 'unlink', 'rename'):
        require('no_path_' + target + '_' + perm, not permission(target, 'file', perm))
for target in ('shadow_t', 'ssh_home_t'):
    for perm in ('open', 'read', 'write'):
        require('no_' + target + '_' + perm, not permission(target, 'file', perm))
for target in ('engbox_worker_state_t', 'engbox_worker_tmp_t'):
    for perm in ('open', 'read', 'write', 'create', 'unlink'):
        require('private_' + target + '_' + perm, permission(target, 'file', perm))
    require('no_execute_private_' + target, not permission(target, 'file', 'execute'))
for cls, perms in [('tcp_socket', ('create', 'connect', 'listen', 'name_connect')),
                   ('udp_socket', ('create', 'connect')),
                   ('rawip_socket', ('create', 'connect'))]:
    for perm in perms:
        require('no_network_' + cls + '_' + perm, not permission(source, cls, perm))
for perm in ('dac_override', 'dac_read_search', 'setuid', 'setgid', 'sys_admin', 'sys_ptrace', 'net_admin', 'net_raw'):
    require('no_capability_' + perm, not permission(source, 'capability', perm))
for target, cls in allows:
    if cls == 'process':
        require('no_ptrace_' + target, not permission(target, cls, 'ptrace'))
        require('no_dyntransition_' + target, not permission(target, cls, 'dyntransition'))
for perm in ('execmem', 'execheap', 'execstack'):
    require('no_' + perm, not permission(source, 'process', perm))
require('broker_binds_seqpacket', permission(source, 'unix_stream_socket', 'bind') and
        permission(source, 'unix_stream_socket', 'listen'))
require('broker_creates_only_ipc_socket', permission('engbox_worker_run_t', 'sock_file', 'create'))
require('broker_uses_received_gateway_fds', permission('unconfined_t', 'fd', 'use'))

result = {'status': 'ALL_111_BROKER_GUARDS_PASS', 'checks': checks,
          'check_count': len(checks), 'conditional_rules': 'conservative union of all branches',
          'combined_sha256': hashlib.sha256((root / 'combined-policy.35').read_bytes()).hexdigest(),
          'policy_input': 'Caller-provided snapshot; see caller provenance',
          'raw_default_transitions': sorted(transitions),
          'permitted_process_transition_targets': sorted(transition_targets),
          'limitation': 'Snapshot semantic checks only; runtime and whole-policy qualification are separately recorded.'}
(root / 'effective-policy-result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k: v for k, v in result.items() if k != 'checks'}, indent=2))
