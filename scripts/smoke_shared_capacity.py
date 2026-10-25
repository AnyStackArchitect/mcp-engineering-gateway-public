#!/usr/bin/env python3
"""Disposable CI-only root orchestrator: actual two-UID aggregate admission."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import capacitywork
import sharedcapacity
import resumable_transfer
import transfer_bridge
from casework import CaseStore,CaseError,FREE_RESERVE

GATEWAY_UID=62011
WORKER_UID=62012
SHARED_GID=62013


def child(uid,operation,*,killed=False):
    reader,writer=os.pipe()
    pid=os.fork()
    if pid==0:
        os.close(reader)
        try:
            os.setgroups([SHARED_GID]);os.setgid(SHARED_GID);os.setuid(uid)
            result=operation()
            payload={'ok':True,'result':result}
        except BaseException as exc:
            payload={'ok':False,'error':type(exc).__name__+': '+str(exc)}
        os.write(writer,json.dumps(payload).encode());os.close(writer);os._exit(0)
    os.close(writer)
    data=b''
    while True:
        part=os.read(reader,4096)
        if not part:break
        data+=part
    os.close(reader)
    _,status=os.waitpid(pid,0)
    if killed:
        if not os.WIFSIGNALED(status) or os.WTERMSIG(status)!=signal.SIGKILL:
            raise RuntimeError('Expected real SIGKILL inside guarded publication')
        return None
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status)!=0 or not data:
        raise RuntimeError('Synthetic UID fixture exited unexpectedly')
    payload=json.loads(data)
    if not payload['ok']:raise RuntimeError(payload['error'])
    return payload['result']


def main():
    if os.geteuid()!=0:raise RuntimeError('Disposable CI root orchestrator only')
    control=Path(tempfile.mkdtemp(prefix='eng-capacity-ci-',dir='/run'))
    homes=Path(tempfile.mkdtemp(prefix='eng-capacity-ci-homes-',dir='/var/tmp'))
    try:
        os.chown(control,0,SHARED_GID);control.chmod(0o750);homes.chmod(0o711)
        stores={}
        for name,uid in [('gateway',GATEWAY_UID),('worker',WORKER_UID)]:
            home=homes/name;home.mkdir();os.chown(home,uid,SHARED_GID);home.chmod(0o700)
            stores[uid]=CaseStore(home)
            folder=control/sharedcapacity.slot_id(stores[uid].base)
            folder.mkdir();os.chown(folder,uid,SHARED_GID);folder.chmod(0o750)
        lock=control/'admission.lock';lock.write_bytes(b'');os.chown(lock,0,SHARED_GID);lock.chmod(0o640)
        policy={'schema':1,'group_gid':SHARED_GID,'filesystem_device':homes.stat().st_dev,
            'state_dir':str(control),'stores':[{'base':str(s.base),'uid':uid} for uid,s in stores.items()]}
        path=control/'policy.json';path.write_text(json.dumps(policy));path.chmod(0o640);os.chown(path,0,SHARED_GID)
        sharedcapacity.POLICY_FILE=path
        def ready(uid,missing=False):
            store=stores[uid];store._ensure_store()
            try:
                with capacitywork.admission_lock(store):capacitywork.verify_committed_reserve(store)
            except CaseError:
                if missing:return 'NOT_READY_REFUSED'
                raise
            if missing:raise RuntimeError('Missing peer mirror was accepted')
            return 'READY'
        child(GATEWAY_UID,lambda:ready(GATEWAY_UID,True))
        child(WORKER_UID,lambda:ready(WORKER_UID))
        child(GATEWAY_UID,lambda:ready(GATEWAY_UID))
        token='.upload-'+'a'*32
        child(GATEWAY_UID,lambda:resumable_transfer.begin(stores[GATEWAY_UID],token,2*1024**2,hashlib.sha256(b'synthetic').hexdigest()))
        def guarded(uid,free,extra,refuse=False,kill=False):
            with patch.object(capacitywork.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(free+1024,1024,free)):
                try:
                    with capacitywork.admission_lock(stores[uid]):
                        pending=capacitywork.verify_committed_reserve(stores[uid],extra_bytes=extra)
                        if kill:os.kill(os.getpid(),signal.SIGKILL)
                except CaseError:
                    if refuse:return 'CAPACITY_REFUSED'
                    raise
            if refuse:raise RuntimeError('Foreign upload promise was consumed')
            return pending
        child(WORKER_UID,lambda:guarded(WORKER_UID,FREE_RESERVE+2*1024**2,1,refuse=True))
        if child(WORKER_UID,lambda:guarded(WORKER_UID,FREE_RESERVE+3*1024**2,1024**2))!=2*1024**2:
            raise RuntimeError('Worker did not see gateway reservation')
        def isolated(uid,other):
            mirror=control/sharedcapacity.slot_id(stores[other].base)/'reservation.json'
            try:
                with mirror.open('wb'):pass
            except PermissionError:pass
            else:raise RuntimeError('One UID could alter another reservation')
            try:list(stores[other].inbox.iterdir())
            except PermissionError:return True
            raise RuntimeError('Raw other-UID inbox was exposed')
        child(WORKER_UID,lambda:isolated(WORKER_UID,GATEWAY_UID))
        child(GATEWAY_UID,lambda:isolated(GATEWAY_UID,WORKER_UID))
        child(WORKER_UID,lambda:guarded(WORKER_UID,FREE_RESERVE+3*1024**2,1024**2,kill=True),killed=True)
        child(GATEWAY_UID,lambda:guarded(GATEWAY_UID,FREE_RESERVE+3*1024**2,1,refuse=True))
        child(WORKER_UID,lambda:ready(WORKER_UID))
        mirror=control/sharedcapacity.slot_id(stores[GATEWAY_UID].base)/'reservation.json'
        mirror.unlink()
        child(WORKER_UID,lambda:ready(WORKER_UID,True))
        child(GATEWAY_UID,lambda:ready(GATEWAY_UID))
        child(WORKER_UID,lambda:ready(WORKER_UID))
        foreign=control/sharedcapacity.slot_id(stores[WORKER_UID].base)/'reservation.json'
        foreign.chmod(0o660)
        child(GATEWAY_UID,lambda:ready(GATEWAY_UID,True));foreign.chmod(0o640)
        os.chown(foreign,GATEWAY_UID,SHARED_GID)
        child(GATEWAY_UID,lambda:ready(GATEWAY_UID,True));os.chown(foreign,WORKER_UID,SHARED_GID)
        extra_link=control/'synthetic-link';os.link(foreign,extra_link)
        child(GATEWAY_UID,lambda:ready(GATEWAY_UID,True));extra_link.unlink()
        backup=foreign.with_name('synthetic-backup');foreign.rename(backup);foreign.symlink_to(backup)
        child(GATEWAY_UID,lambda:ready(GATEWAY_UID,True));foreign.unlink();backup.rename(foreign)
        foreign.write_text('{malformed')
        child(GATEWAY_UID,lambda:ready(GATEWAY_UID,True))
        child(WORKER_UID,lambda:ready(WORKER_UID))
        child(GATEWAY_UID,lambda:transfer_bridge.abort(stores[GATEWAY_UID],token))
        if child(WORKER_UID,lambda:guarded(WORKER_UID,FREE_RESERVE+1024**2,1024**2))!=0:
            raise RuntimeError('Completed upload reservation did not reconcile')
        print(json.dumps({'status':'OFF_HOST_SHARED_CAPACITY_TWO_UID_PASS',
            'foreign_promise_refused':True,'private_inboxes_isolated':True,
            'cross_uid_mirror_mutation_refused':True,'real_sigkill_conservative_publication':True,
            'missing_peer_fail_closed':True,'owner_reconciliation_verified':True,
            'malformed_wrong_owner_mode_link_peer_refused':True,
            'production_policy_enrolled':False,'hostile_uid_disk_quota_claim':False,'rocky_qualified':False},sort_keys=True))
    finally:
        shutil.rmtree(control);shutil.rmtree(homes)
    return 0


if __name__=='__main__':raise SystemExit(main())
