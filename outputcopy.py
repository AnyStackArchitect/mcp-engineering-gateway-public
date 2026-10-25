"""Bounded allowlisted regular-file stream from disposable container tmpfs.

No tar extraction or recursive host allocation. Untrusted extra entries/types
are refused inside the container before any declared file is streamed.
"""
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

from capacitywork import admission_lock,verify_committed_reserve
from podman_policy import PODMAN,PYTHON,container_name

PROGRAM=r'''
import json,os,stat,sys
allowed=json.loads(sys.argv[1]);limit=int(sys.argv[2]);opened=[];used=0
try:
    names=[]
    with os.scandir('/output') as entries:
        for entry in entries:
            if entry.name not in allowed or len(names)>=len(allowed):raise ValueError('unapproved output')
            names.append(entry.name)
    for name in sorted(names):
        fd=os.open('/output/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_uid!=os.getuid() or meta.st_size>limit-used:
            os.close(fd);raise ValueError('unsafe output')
        used+=meta.st_size;opened.append((name,fd,meta))
    header=json.dumps([{'name':name,'bytes':meta.st_size} for name,fd,meta in opened],separators=(',',':')).encode()
    sys.stdout.buffer.write(len(header).to_bytes(4,'big')+header);sys.stdout.buffer.flush()
    for name,fd,meta in opened:
        count=0
        while count<meta.st_size:
            block=os.read(fd,min(1048576,meta.st_size-count))
            if not block:raise ValueError('truncated output')
            count+=len(block);sys.stdout.buffer.write(block)
        if os.read(fd,1):raise ValueError('grown output')
        after=os.fstat(fd)
        if (after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=(meta.st_size,meta.st_mtime_ns,meta.st_ctime_ns):raise ValueError('changed output')
        sys.stdout.buffer.flush()
finally:
    for name,fd,meta in opened:os.close(fd)
'''


class CopyError(Exception):pass


def stream_command(plan):
    return [PODMAN,'exec',container_name(plan['id']),PYTHON,'-I','-B','-c',PROGRAM,
        json.dumps(plan['output_names'],separators=(',',':')),str(plan['disk_mib']*1024**2)]


def copy_outputs(cases,plan,destination,*,env=None):
    """Copy only validated bounded streams under cooperating capacity admission."""
    maximum=plan['disk_mib']*1024**2
    with admission_lock(cases):
        verify_committed_reserve(cases,extra_bytes=maximum+65536)
        process=subprocess.Popen(stream_command(plan),stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env)
        selector=selectors.DefaultSelector()
        try:
            assert process.stdout is not None
            os.set_blocking(process.stdout.fileno(),False)
            selector.register(process.stdout,selectors.EVENT_READ)
            deadline=time.monotonic()+45
            def read(amount,*,eof=False):
                chunks=bytearray()
                while len(chunks)<amount:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:raise CopyError('Output copy timeout')
                    if not selector.select(remaining):raise CopyError('Output copy timeout')
                    block=os.read(process.stdout.fileno(),min(1048576,amount-len(chunks)))
                    if not block:
                        if eof and not chunks:return b''
                        raise CopyError('Output copy truncated')
                    chunks.extend(block)
                return bytes(chunks)
            length=int.from_bytes(read(4),'big')
            if not 0<length<=4096:raise CopyError('Output inventory length invalid')
            inventory=json.loads(read(length))
            if type(inventory) is not list or len(inventory)>len(plan['output_names']):raise CopyError('Output inventory count invalid')
            used=0;seen=set()
            for item in inventory:
                if (type(item) is not dict or set(item)!={'name','bytes'} or type(item['name']) is not str or
                    item['name'] not in plan['output_names'] or item['name'] in seen or
                    type(item['bytes']) is not int or not 0<=item['bytes']<=maximum-used):
                    raise CopyError('Output stream identity or quota invalid')
                used+=item['bytes'];seen.add(item['name'])
            for item in inventory:
                path=destination/item['name']
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
                with os.fdopen(fd,'wb') as target:
                    remaining=item['bytes']
                    while remaining:
                        block=read(min(1048576,remaining));target.write(block);remaining-=len(block)
                    target.flush();os.fsync(target.fileno())
            if read(1,eof=True):raise CopyError('Output stream has trailing bytes')
            if process.wait(timeout=max(0.1,deadline-time.monotonic()))!=0:raise CopyError('Container refused unsafe output')
        finally:
            selector.close()
            if process.poll() is None:
                process.kill();process.wait(timeout=10)
            if process.stdout is not None:process.stdout.close()
