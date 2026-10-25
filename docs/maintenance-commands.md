# Parameterized maintenance command transcript

[Operations](operations-runbook.md) / [Installation](install-from-source.md) / [Reader acceptance](reader-validation.md)

These are **unexecuted source-bound templates for a stopped, approved dedicated site**, not a new runtime CLI. Review the selected values and exact candidate before any command. Read-only steps do not authorize later mutations. State capture, restore, service changes, replacement and removal need an approved maintenance window/disposable-target rehearsal. No production restore, purge or arbitrary-version migration is implied. Commands use Bash and the target's root administrator; signing keys remain on their separate custodian workstation.

## 1. Bind this terminal to the actual transaction

Read `site` in the retained root-private `TRANSACTION/journal.json`; use the exact fields below, never guessed IDs. Set each placeholder to its reviewed absolute path/value. `PRIVATE_OUTPUT` is a NEW root-private directory outside source, code, homes and transaction. `SOURCE_ROOT` is a complete verified new source tree, not `/opt/rocky-eng` (which contains only runtime modules).

```sh
set -eu
umask 077
TRANSACTION='/root/ACTUAL_RETAINED_TRANSACTION'
SOURCE_ROOT='/root/ACTUAL_VERIFIED_SOURCE/source'
PRIVATE_OUTPUT='/root/NEW_MAINTENANCE_OUTPUT'
SITE_ID='ACTUAL_SITE_ID'
GATEWAY_NAME='ACTUAL_GATEWAY_NAME'
GATEWAY_HOME='/home/ACTUAL_GATEWAY_NAME'
WORKER_NAME='rocky-eng-worker'
WORKER_HOME='/home/rocky-eng-worker'
WORKER_UID='ACTUAL_WORKER_UID'
UNIT="engbox-worker-${SITE_ID}.service"
test "$(id -u)" = 0
test ! -e "$PRIVATE_OUTPUT"
mkdir -m 0700 "$PRIVATE_OUTPUT"
python3 -B - "$TRANSACTION/journal.json" "$SITE_ID" "$GATEWAY_NAME" "$GATEWAY_HOME" "$WORKER_NAME" "$WORKER_HOME" "$WORKER_UID" <<'PY'
import json,pwd,re,sys
from pathlib import Path
j=json.loads(Path(sys.argv[1]).read_text());s=j['site'];g=s['gateway'];w=s['worker']
assert sys.argv[2:]==[s['site_id'],g['name'],g['home'],w['name'],w['home'],str(w['uid'])]
assert re.fullmatch(r'[a-z][a-z0-9_-]{0,30}',s['site_id'])
for a in (g,w):
    p=pwd.getpwnam(a['name']);assert (p.pw_uid,p.pw_gid,p.pw_dir)==(a['uid'],a['gid'],a['home'])
assert w['name']=='rocky-eng-worker' and w['home']=='/home/rocky-eng-worker'
print('SITE_IDENTITIES_MATCH')
PY
worker() {
  /usr/sbin/runuser -u "$WORKER_NAME" -- /usr/bin/env -i \
    HOME="$WORKER_HOME" PATH=/usr/bin:/bin LANG=C.UTF-8 \
    XDG_RUNTIME_DIR="/run/user/$WORKER_UID" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$WORKER_UID/bus" "$@"
}
worker /usr/bin/systemctl --user show "$UNIT" --property=MainPID,ActiveState,SubState,UnitFileState
worker /usr/bin/journalctl --user -u "$UNIT" --no-pager -n 100 > "$PRIVATE_OUTPUT/worker-journal.txt"
```

Require SITE_IDENTITIES_MATCH, the reviewed unit and expected live/disabled state. This uses the same user-manager environment as native activation; root's own `systemctl --user` would inspect the wrong manager. If the retained journal, account or manager is missing/changed, stop. Keep journal output private; command arguments and excerpts may be sensitive. The initial root-private transaction/source ancestry and hashes must already have passed installer/audit verification.

## 2. Quiesce — state-changing, stop before uncertain cleanup

Use the site's existing authorized access controls to block new gateway sessions; close all MCP/SSH clients and drain/cancel fixed and signed work deliberately. Stop the owned gateway foreground processor only after its queue is drained. Access-control policy is site-specific; this manual does not disable global sshd or alter unrelated firewall rules. As gateway before blocking access, retain job_list/execution statuses and terminal results. Do not mark unfinished work terminal by editing SQLite.

After that approved drain, in the bound root terminal:

```sh
worker /usr/bin/systemctl --user disable --now "$UNIT"
if worker /usr/bin/systemctl --user is-active --quiet "$UNIT"; then
  echo 'Worker still active; stop maintenance' >&2; exit 1
fi
test ! -S /run/rocky-eng/execution.sock
worker /usr/bin/podman ps --all --format json > "$PRIVATE_OUTPUT/containers.json"
python3 -B - "$PRIVATE_OUTPUT/containers.json" "$GATEWAY_NAME" <<'PY'
import json,pwd,sys
from pathlib import Path
assert json.loads(Path(sys.argv[1]).read_text())==[], 'owned container remains: reviewed recovery required'
uid=pwd.getpwnam(sys.argv[2]).pw_uid
active=[]
for p in Path('/proc').iterdir():
    if p.name.isdigit():
        try:
            if p.stat().st_uid==uid:active.append(p.name)
        except FileNotFoundError:pass
assert not active, 'gateway processes remain: close/drain them through the owning sessions'
print('QUIESCED_OBSERVATIONS_PASS')
PY
```

Require disabled/inactive worker, no socket, no owned container and no gateway process. These observations depend on the access block remaining in force; they do not replace it. Any residual/uncertain creator is a recovery stop, not permission to kill broadly or remove a marker. Preserve user lingering/accounts and unrelated services. Never stop the entire user manager to make this pass.

## 3. Coherent quiesced capture — private data and metadata

Allow space for all selected stores **and** the retained image archive in the transaction. Choose storage/failure domain explicitly. No runtime socket or whole Podman storage is captured. This populated-site rehearsal requires both exercised job/execution DBs; an empty fresh-site backup is a different explicitly recorded scope. Intermediate home/.local parent directories are structural extraction parents, not a live account restore; the transaction/site identity and approved target setup determine their ownership/labels before any recovered service startup. The selection includes gateway/worker stores and configs, gateway SSH enrollment, root code/config/trust, the transaction (which holds `activation-image.oci.tar`) and this site's unit/drop-ins. Private signing keys are not on the host and need separate custodian backup.

The following read-only inventory fails on links/special files; pending-state and integrity checks run only on isolated scratch copies after capture. It records complete file bytes, ownership/mode and xattr hashes without exposing values. Review its root selection before tar. Run after section2, with the access block still held:

```sh
python3 -B - "$PRIVATE_OUTPUT" "$GATEWAY_HOME" "$WORKER_HOME" "$TRANSACTION" "$UNIT" <<'PY'
import hashlib,json,os,pwd,stat,sys
from pathlib import Path
out,g,w,tx=map(Path,sys.argv[1:5]);unit=sys.argv[5]
roots=[Path('/opt/rocky-eng'),Path('/etc/rocky-eng'),tx,
       Path('/etc/systemd/user')/unit,Path('/etc/systemd/user')/(unit+'.d'),
       Path('/etc/tmpfiles.d/rocky-eng-ipc.conf'),
       Path('/etc/systemd/system')/('user-'+str(pwd.getpwnam(w.name).pw_uid)+'.slice.d')/'50-engbox-limits.conf']
for home,db in ((g,'jobs.sqlite3'),(w,'execution.sqlite3')):
    assert (home/'.local/share/rocky-mcp-gateway'/db).is_file(), 'populated site DB required for this rehearsal'
    for suffix in ('.local/share/rocky-mcp-gateway','.local/state/rocky-mcp-gateway','.config/rocky-mcp-gateway'):
        p=home/suffix
        if p.exists():roots.append(p)
if (g/'.ssh').exists():roots.append(g/'.ssh')
for p in roots:
    assert p.is_absolute() and p.exists() and not p.is_symlink()
    assert out!=p and not out.is_relative_to(p)
    assert not any(a.is_symlink() for a in p.parents)
records={}
for root in roots:
    for p in [root,*sorted(root.rglob('*'))] if root.is_dir() else [root]:
        st=p.lstat();assert stat.S_ISDIR(st.st_mode) or (stat.S_ISREG(st.st_mode) and st.st_nlink==1)
        row={'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),
             'xattrs':{n:hashlib.sha256(os.getxattr(p,n,follow_symlinks=False)).hexdigest() for n in os.listxattr(p,follow_symlinks=False)}}
        if p.is_file():row['sha256']=hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
        records[str(p.relative_to('/'))]=row
with (out/'capture-manifest.json').open('x') as f:json.dump(records,f,sort_keys=True)
with (out/'capture-paths.txt').open('x') as f:f.write(''.join(str(p.relative_to('/'))+'\n' for p in roots))
print('CAPTURE_SELECTION_REVIEW_REQUIRED')
PY
tar --acls --xattrs --xattrs-include='*' --selinux --numeric-owner -C / -cpf "$PRIVATE_OUTPUT/site-capture.tar" --verbatim-files-from -T "$PRIVATE_OUTPUT/capture-paths.txt"
sha256sum "$PRIVATE_OUTPUT/site-capture.tar" "$PRIVATE_OUTPUT/capture-manifest.json" > "$PRIVATE_OUTPUT/capture-checksums.txt"
```

Require every command exit0. Inspect selection and artifact sizes; no symlink is followed to rescue an unexpected layout. Keep the source block/readers stopped until the archive and hashes are complete. If any DB/process/file changes during capture, retain that failed attempt and restart with a NEW output directory after correcting quiescence. The manifest contains private paths/hashes and is not a publication asset. Preserve root policy/SELinux/subid inventory and prior/new runtime manifests alongside this capture in the maintenance record; OS policy/account recreation is a separately reviewed recovery step, not performed by extraction below.

## 4. Restore into a new isolated directory — never over live state

Set RESTORE to a NEW private directory outside all captured roots. Verify the approved capture/checksum identity independently, then (from PRIVATE_OUTPUT):

```sh
RESTORE='/root/NEW_ISOLATED_RESTORE'
cd "$PRIVATE_OUTPUT"
sha256sum --check capture-checksums.txt
test ! -e "$RESTORE"
mkdir -m 0700 "$RESTORE"
tar --acls --xattrs --xattrs-include='*' --selinux --same-owner --keep-old-files -xpf site-capture.tar -C "$RESTORE"
python3 -B - "$RESTORE" "$PRIVATE_OUTPUT/capture-manifest.json" <<'PY'
import hashlib,json,os,stat,sys
from pathlib import Path
root=Path(sys.argv[1]);expected=json.loads(Path(sys.argv[2]).read_text())
allowed=set(expected)
for name in expected:
    allowed.update(str(p) for p in Path(name).parents if str(p)!='.')
assert {str(p.relative_to(root)) for p in root.rglob('*')}==allowed, 'unexpected or omitted restored entry'
for name,row in expected.items():
    p=root/name;assert p.is_relative_to(root) and not any(a.is_symlink() for a in (p,*p.parents))
    st=p.lstat();assert (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(row['uid'],row['gid'],row['mode'])
    assert {n:hashlib.sha256(os.getxattr(p,n,follow_symlinks=False)).hexdigest() for n in os.listxattr(p,follow_symlinks=False)}==row['xattrs']
    if 'sha256' in row:assert stat.S_ISREG(st.st_mode) and hashlib.file_digest(p.open('rb'),'sha256').hexdigest()==row['sha256']
    else:assert stat.S_ISDIR(st.st_mode)
print('RESTORED_BYTES_AND_METADATA_PASS')
PY
```

Before using any restored DB, verify the complete captured file set and metadata. Run integrity/pending-state checks only on NEW scratch copies, not on live or metadata-verified restored stores: even a read-only SQLite connection can affect shared-memory sidecars. This command copies each registered SQLite DB and its WAL/SHM companions into separate private scratch folders, then checks that copy:

```sh
python3 -B - "$RESTORE" "$PRIVATE_OUTPUT/capture-manifest.json" "$PRIVATE_OUTPUT/db-checks" <<'PY'
import json,shutil,sqlite3,sys
from pathlib import Path
root=Path(sys.argv[1]);manifest=json.loads(Path(sys.argv[2]).read_text());out=Path(sys.argv[3]);out.mkdir(mode=0o700)
results=[]
for number,name in enumerate(sorted(manifest)):
    if not name.endswith(('.sqlite3','.sqlite','.db')):continue
    source=root/name
    if not source.is_file():continue
    folder=out/str(number);folder.mkdir(mode=0o700);copy=folder/source.name
    for suffix in ('','-wal','-shm'):
        part=Path(str(source)+suffix)
        if part.exists():shutil.copy2(part,Path(str(copy)+suffix))
    with sqlite3.connect(copy.as_uri()+'?mode=ro',uri=True) as c:
        assert c.execute('PRAGMA integrity_check').fetchall()==[('ok',)]
        tables=[r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        counts={n:c.execute('SELECT COUNT(*) FROM "'+n.replace('"','""')+'"').fetchone()[0] for n in tables}
        if source.name in ('jobs.sqlite3','execution.sqlite3'):
            table='jobs' if source.name=='jobs.sqlite3' else 'plans'
            states={r[0] for r in c.execute('SELECT DISTINCT state FROM '+table)}
            assert states<={'SUCCEEDED','FAILED','CANCELLED','INTERRUPTED','DENIED','EXPIRED'}, 'pending work: capture is not accepted'
    results.append({'path':name,'integrity':'ok','table_counts':counts})
with (out/'results.json').open('x') as f:json.dump(results,f,sort_keys=True)
assert results, 'expected nonempty qualified stores are missing'
print('SCRATCH_SQLITE_CHECKS_PASS')
PY
```

Require nonempty expected job/plan/nonce rows from the exercised site, not merely a created empty DB. Original capture-manifest byte/metadata equality is required and preserves all rows, not replaced by counts. The acceptance exercise must additionally compare complete logical tables privately to its retained pre-capture known results, and resolve every registered artifact/source reference; these workload-specific expected results come from the retained first-use IDs and hashes. Do not print nonce values or raw job/script data. Omitted data, references, pending states or a corrupt original fail acceptance; retain the failed capture rather than editing it. Query the restored public JobStore/result/source-locator interface under an approved isolated recovery layout and correct identities during acceptance; do not start a service from this root-private extraction.

Extraction is not a production restore or replay-safe boot decision. Live restoration needs approved source/schema/image/policy/account compatibility and proof current nonce/history has not advanced beyond the capture. Never copy these ledgers over active state or automatically resubmit work. The reader rehearsal must record the chosen stopped recovery target and exact final placement/startup procedure; this manual deliberately refuses a generic live overwrite command.

## 5. Code-only update — mutations require exact reviewed plan

Set PRIOR_MANIFEST to the exact old57-module JSON; SOURCE_ROOT is the independently verified compatible new candidate. From SOURCE_ROOT, use the [lifecycle plan command](operations-runbook.md). Keep the plan outside source. With section2 quiescence, verified capture and compatible-schema decision held, copy only the plan's reviewed runtime modules. The template below refuses plan mismatch/drift and preserves old files in PRIVATE_OUTPUT; it does not touch state, trust, image or policy:

```sh
python3 -B - "$SOURCE_ROOT" "$PRIOR_MANIFEST" "$PRIVATE_OUTPUT/update-plan.json" "$PRIVATE_OUTPUT" <<'PY'
import hashlib,json,os,stat,sys
from pathlib import Path
src=Path(sys.argv[1]);old=json.loads(Path(sys.argv[2]).read_text());plan=json.loads(Path(sys.argv[3]).read_text());out=Path(sys.argv[4])
sys.path.insert(0,str(src/'tools'));from lifecycle import plan as make_plan
assert plan==make_plan('update',Path('/opt/rocky-eng'),old)
saved=out/'prior-code';saved.mkdir(mode=0o700)
for row in plan['files']:
    p=Path('/opt/rocky-eng')/row['name'];st=p.lstat()
    assert st.st_uid==0 and st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o644
    b=p.read_bytes();assert hashlib.sha256(b).hexdigest()==row['prior_sha256']
    with (saved/row['name']).open('xb') as f:f.write(b)
for row in plan['files']:
    p=Path('/opt/rocky-eng')/row['name'];b=(src/row['name']).read_bytes()
    assert hashlib.sha256(b).hexdigest()==row['candidate_sha256']
    # Preserve existing labels/ACLs/inode; quiescence is mandatory. A partial write leaves the site stopped.
    with p.open('r+b') as f:f.write(b);f.truncate();f.flush();os.fsync(f.fileno())
    assert hashlib.sha256(p.read_bytes()).hexdigest()==row['candidate_sha256']
print('CODE_COPY_COMPLETE_REVERIFY_BEFORE_START')
PY
```

Do not run this merely because a plan exists. It imports only verified source, requires a fully stopped site and is not crash-atomic across 57 files. On failure keep worker disabled and use reviewed prior-code hashes/schema compatibility for code rollback; never roll replay state back. Independently verify all 57 new module hashes, root ownership0644 and SELinux labels, state/trust/image/history unchanged. Then, only under the approved restart policy:

```sh
worker /usr/bin/systemctl --user daemon-reload
worker /usr/bin/systemctl --user enable --now "$UNIT"
worker /usr/bin/systemctl --user show "$UNIT" --property=MainPID,ActiveState,SubState,UnitFileState
```

Retain lingering as previously approved; do not change it as a shortcut. Complete actual MCP, signed positive/negative/replay and existing case/job/history checks plus deploy audit before reopening gateway access. Image/policy/trust changes and arbitrary schemas are outside this update path.

## 6. Retained-state uninstall — destructive only to verified owned code/unit files

Use the exact prior manifest and read-only uninstall plan, section2 quiescence and verified capture. Validate installed bytes with the lifecycle planner again immediately before removal. Remove only the plan's 57 files plus the reviewed site's three unit/drop-in files; verify those unit files against the transaction's original file-operation hashes. If any differs, stop rather than infer ownership:

```sh
python3 -B - "$SOURCE_ROOT" "$PRIOR_MANIFEST" "$PRIVATE_OUTPUT/uninstall-plan.json" "$TRANSACTION/journal.json" "$UNIT" <<'PY'
import hashlib,json,stat,sys
from pathlib import Path
src=Path(sys.argv[1]);old=json.loads(Path(sys.argv[2]).read_text());plan=json.loads(Path(sys.argv[3]).read_text());j=json.loads(Path(sys.argv[4]).read_text());unit=sys.argv[5]
sys.path.insert(0,str(src/'tools'));from lifecycle import plan as make_plan
assert unit=='engbox-worker-'+j['site']['site_id']+'.service'
assert plan==make_plan('uninstall',Path('/opt/rocky-eng'),old)
paths=[Path('/opt/rocky-eng')/r['name'] for r in plan['files']]
units=[Path('/etc/systemd/user')/unit,*[Path('/etc/systemd/user')/(unit+'.d')/n for n in ('50-engbox-hardening.conf','60-engbox-availability.conf')]]
expected={op['path']:op['sha256'] for op in j['operations'] if op['kind']=='file' and op.get('complete')}
for p in units:
    st=p.lstat();assert not any(a.is_symlink() for a in (p,*p.parents))
    assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==0 and st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o644
    assert hashlib.sha256(p.read_bytes()).hexdigest()==expected[str(p)]
for p in paths+units:p.unlink()
print('REMOVED_60_VERIFIED_OWNED_FILES')
PY
worker /usr/bin/systemctl --user daemon-reload
```

No directory tree is recursively removed. Preserve all case data, private/public trust, nonce/history, accounts/subids, SELinux policy, image stores, transaction journals, cgroup/tmpfiles policy and lingering by default. Confirm disabled unit/no socket/container, retained file/state hashes, and unrelated services unchanged. A fresh installer will correctly refuse retained accounts/paths. Purging or reusing the site is a separate explicit decision. Exact module/unit before/after hashes, failure receipts and rollback copies remain private maintenance evidence.
