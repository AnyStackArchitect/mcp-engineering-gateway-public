"""Optional administrator-enrolled cross-UID capacity admission; no evidence access.

Only opaque aggregate byte promises are shared. Every participant owns only its
mirror directory. A root-owned read-only lock serializes cooperating writers.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time

POLICY_FILE=Path('/etc/rocky-eng/capacity-policy.json')
MAX_POLICY=16384
MAX_MIRROR=1024
_active=threading.local()


def error(message):
    from casework import CaseError
    return CaseError(message)


def trusted_root(path,file=True):
    if not path.is_absolute():raise error('Capacity policy path must be absolute')
    for item in [*reversed(path.parents),path]:
        info=item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise error('Capacity policy path is not administrator controlled')
        if item!=path and not stat.S_ISDIR(info.st_mode):raise error('Invalid capacity path parent')
    if file and (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1):raise error('Unsafe capacity policy file')
    if not file and not stat.S_ISDIR(info.st_mode):raise error('Unsafe capacity state directory')
    return info


def slot_id(base):return hashlib.sha256(str(base).encode()).hexdigest()


def load_policy(store):
    try:POLICY_FILE.lstat()
    except FileNotFoundError:return None
    try:
        info=trusted_root(POLICY_FILE)
        if not 0<info.st_size<=MAX_POLICY:raise error('Capacity policy size invalid')
        raw=POLICY_FILE.read_bytes()
        data=json.loads(raw)
        if type(data) is not dict or set(data)!={'schema','group_gid','filesystem_device','state_dir','stores'} or type(data['schema']) is not int or data['schema']!=1:
            raise error('Capacity policy schema invalid')
        if any(type(data[k]) is not int or data[k]<0 for k in ('group_gid','filesystem_device')) or data['group_gid']<100:
            raise error('Capacity policy identities invalid')
        if type(data['stores']) is not list or not 2<=len(data['stores'])<=16:raise error('Capacity participants invalid')
        slots={}
        for item in data['stores']:
            if type(item) is not dict or set(item)!={'base','uid'} or type(item['base']) is not str or type(item['uid']) is not int or item['uid']<100:
                raise error('Capacity participant schema invalid')
            path=Path(item['base'])
            if not path.is_absolute() or '..' in path.parts or str(path)!=item['base']:
                raise error('Capacity participant path invalid')
            key=slot_id(path)
            if key in slots:raise error('Duplicate capacity participant')
            slots[key]=item
        key=slot_id(store.base.resolve())
        if key not in slots or slots[key]['uid']!=os.getuid() or store.inbox.stat().st_dev!=data['filesystem_device']:
            raise error('Store not enrolled on capacity policy filesystem')
        directory=Path(data['state_dir']);trusted_root(directory,file=False)
        lock=directory/'admission.lock';meta=trusted_root(lock)
        if meta.st_gid!=data['group_gid'] or stat.S_IMODE(meta.st_mode)!=0o640 or meta.st_size!=0:
            raise error('Capacity shared lock identity invalid')
        for name,item in slots.items():
            folder=directory/name;meta=folder.lstat()
            if (not stat.S_ISDIR(meta.st_mode) or folder.is_symlink() or meta.st_uid!=item['uid'] or
                    meta.st_gid!=data['group_gid'] or stat.S_IMODE(meta.st_mode)!=0o750):
                raise error('Capacity participant mirror directory unsafe')
        return {'directory':directory,'slots':slots,'key':key,'gid':data['group_gid'],
            'policy_sha256':hashlib.sha256(raw).hexdigest(),'lock_info':lock.lstat()}
    except (OSError,ValueError,TypeError,KeyError) as exc:
        raise error('Shared capacity policy unavailable or malformed') from exc


def read_mirror(state,key):
    path=state['directory']/key/'reservation.json'
    try:
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
        with os.fdopen(fd,'rb') as source:
            info=os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=state['slots'][key]['uid'] or
                    info.st_gid!=state['gid'] or stat.S_IMODE(info.st_mode)!=0o640 or not 0<info.st_size<=MAX_MIRROR):
                raise error('Shared capacity mirror identity invalid')
            raw=source.read(MAX_MIRROR+1)
            if len(raw)!=info.st_size:raise error('Shared capacity mirror length changed')
        data=json.loads(raw)
        if (type(data) is not dict or set(data)!={'schema','slot','policy_sha256','reserved_bytes'} or
                type(data['schema']) is not int or data['schema']!=1 or data['slot']!=key or
                data['policy_sha256']!=state['policy_sha256'] or type(data['reserved_bytes']) is not int or
                not 0<=data['reserved_bytes']<=2**48):
            raise error('Shared capacity mirror schema invalid')
        return data['reserved_bytes']
    except (OSError,ValueError,TypeError,KeyError) as exc:
        raise error('Shared capacity participant not ready; owner reconciliation required') from exc


def publish(state,amount):
    if type(amount) is not int or not 0<=amount<=2**48:raise error('Shared capacity promise invalid')
    directory=state['directory']/state['key']
    temporary=directory/('.pending-'+secrets.token_hex(16))
    data={'schema':1,'slot':state['key'],'policy_sha256':state['policy_sha256'],'reserved_bytes':amount}
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as target:
            target.write(json.dumps(data,sort_keys=True).encode());target.flush()
            os.fchown(target.fileno(),-1,state['gid'])
            os.fchmod(target.fileno(),0o640);os.fsync(target.fileno())
        if temporary.stat().st_gid!=state['gid']:raise error('Shared mirror has wrong group')
        os.replace(temporary,directory/'reservation.json')
        descriptor=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    finally:temporary.unlink(missing_ok=True)


def current(store):return getattr(_active,'states',{}).get(str(store.base.resolve()))


def aggregate(store,local):
    state=current(store)
    if state is None:
        if POLICY_FILE.exists():raise error('Enrolled capacity read requires shared admission')
        return local
    return local+sum(read_mirror(state,key) for key in state['slots'] if key!=state['key'])


def reserve_extra(store,local,extra):
    state=current(store)
    if state is not None:publish(state,local+extra)


@contextmanager
def admission(store,local_pending):
    state=load_policy(store)
    if state is None:
        yield False
        return
    if getattr(_active,'states',{}):raise error('Nested shared capacity admission is unsupported')
    lock=state['directory']/'admission.lock'
    fd=os.open(lock,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    try:
        before=state['lock_info'];info=os.fstat(fd)
        if (info.st_ino,info.st_dev)!=(before.st_ino,before.st_dev):raise error('Shared admission lock changed')
        deadline=time.monotonic()+90
        while True:
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                if time.monotonic()>deadline:raise error('Shared admission busy; retry')
                time.sleep(0.05)
        if hashlib.sha256(POLICY_FILE.read_bytes()).hexdigest()!=state['policy_sha256']:
            raise error('Capacity policy changed during admission')
        publish(state,local_pending(store))
        _active.states={str(store.base.resolve()):state}
        try:
            aggregate(store,local_pending(store))
            yield True
        finally:
            try:publish(state,local_pending(store))
            finally:_active.states={}
    finally:os.close(fd)
