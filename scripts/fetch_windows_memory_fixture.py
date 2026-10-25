#!/usr/bin/env python3
"""Pinned public Volatility fixture fetch on disposable hosted CI only.

Never prints memory, names, paths from memory or raw Volatility output. No upload.
"""
import gzip,hashlib,json,os
from pathlib import Path
import sys,time,urllib.request

BASE='https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/'
SYMBOL=('symbols_win-10_19041-2025_03.zip',789065,'abd6500fba6a59c9a7c21f2c4b8a4d7edc2da417ec3161311a19a0e0beffd94e')
DUMP=('win-10_19041-2025_03.dmp.gz',693221397,'b377ecd13bf40c90f59a8c41ffc8bc81166462627a7800ec82a67a73520c7f9d')


def fetch(asset,path):
    name,maximum,expected=asset
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);size=0;sha=hashlib.sha256()
    with os.fdopen(fd,'wb') as stream:
        with urllib.request.urlopen(urllib.request.Request(BASE+name,headers={'User-Agent':'Eng-Box-public-qualification'}),timeout=90) as response:
            for block in iter(lambda:response.read(1024*1024),b''):
                size+=len(block)
                if size>maximum:raise RuntimeError('Public fixture download size exceeded')
                sha.update(block);stream.write(block)
        stream.flush();os.fsync(stream.fileno())
    if size!=maximum or sha.hexdigest()!=expected:raise RuntimeError('Pinned public fixture digest mismatch')
    return {'release_asset':name,'bytes':size,'sha256':sha.hexdigest()}


def main():
    if os.geteuid()==0 or os.environ.get('GITHUB_ACTIONS')!='true' or len(sys.argv)!=3:
        raise RuntimeError('Disposable hosted CI fixture fetch only')
    symbols=Path(sys.argv[1]);dump=Path(sys.argv[2]);compressed=dump.with_suffix(dump.suffix+'.gz')
    if any(p.exists() or p.is_symlink() for p in (symbols,dump,compressed)):raise RuntimeError('Refuse fixture overwrite')
    start=time.monotonic();s=fetch(SYMBOL,symbols);d=fetch(DUMP,compressed)
    fd=os.open(dump,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);size=0;sha=hashlib.sha256()
    with os.fdopen(fd,'wb') as out,gzip.open(compressed,'rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):
            size+=len(block)
            if size>4*1024**3:raise RuntimeError('Public dump exceeds selected4GiB policy; positive qualification blocked')
            sha.update(block);out.write(block)
        out.flush();os.fsync(out.fileno())
    with dump.open('rb') as stream:header=stream.read(64)
    if header[:8]!=b'PAGEDU64':raise RuntimeError('Public fixture is not selected x64 Windows dump format')
    compressed.unlink()
    print(json.dumps({'status':'PUBLIC_WINDOWS_MEMORY_FIXTURE_READY','symbols':s,'compressed_dump':d,
        'expanded_dump_bytes':size,'expanded_dump_sha256':sha.hexdigest(),'elapsed_seconds':round(time.monotonic()-start,3),
        'raw_memory_or_provider_output_uploaded':False},sort_keys=True))


if __name__=='__main__':main()
