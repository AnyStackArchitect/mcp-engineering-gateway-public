"""Root-owned private source entry point for the experimental Rocky installer.

Run with python3 -I -B. The approved source-manifest checksum must come from the
separate package receipt. All source bytes, ownership and closure are verified
before neighboring modules are imported. Keep bundles/state outside this tree.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import runpy
import stat
import sys

ROUTES={'inventory':'site_inventory.py','policy-preflight':'policy_preflight.py',
        'prepare':'native_prepare.py','verify':'native_prepare.py',
        'rollback':'native_prepare.py','activate':'native_activate.py','audit':'native_activate.py'}


def require(value,label):
    if not value:raise ValueError(label)


def safe_file(path,maximum):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
                and not info.st_mode & 0o022,'unsafe_source_file')
        data=stream.read(maximum+1)
    require(len(data)<=maximum,'source_file_bound')
    return data


def verify_source(root,expected):
    require(re.fullmatch(r'[0-9a-f]{64}',expected) is not None,'approved_source_manifest_required')
    for path in (root,*root.parents):
        info=path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode & 0o022,
                'root_owned_source_tree_required')
    data=safe_file(root/'SHA256SUMS.txt',262144)
    require(hashlib.sha256(data).hexdigest()==expected,'approved_source_manifest_mismatch')
    entries={}
    for line in data.decode('utf8').splitlines():
        digest,sep,name=line.partition('  ');path=PurePosixPath(name)
        require(sep and re.fullmatch(r'[0-9a-f]{64}',digest) and name not in entries
                and not path.is_absolute() and str(path)==name and '..' not in path.parts
                and '\\' not in name and ':' not in name and name!='SHA256SUMS.txt','source_manifest_record')
        entries[name]=digest
    require(1<=len(entries)<=4096,'source_count')
    observed=set();total=0
    def denied(error):raise error
    for directory,dirs,files in os.walk(root,followlinks=False,onerror=denied):
        for name in dirs:
            info=(Path(directory)/name).lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode & 0o022,
                    'unsafe_source_directory')
        for name in files:
            path=Path(directory)/name;relative=path.relative_to(root).as_posix()
            require(relative in entries or relative=='SHA256SUMS.txt','unmanifested_source_file')
            if relative=='SHA256SUMS.txt':continue
            content=safe_file(path,16*1024*1024);total+=len(content)
            require(total<=128*1024*1024 and hashlib.sha256(content).hexdigest()==entries[relative],
                    'source_content_mismatch')
            observed.add(relative)
    require(observed==set(entries),'source_closure_mismatch')
    return {'status':'ROOT_OWNED_SOURCE_CLOSURE_PASS','source_manifest_sha256':expected,'files':len(entries)}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('verify-source',*ROUTES))
    parser.add_argument('--source-manifest-sha256',required=True)
    args,remaining=parser.parse_known_args(argv)
    try:
        require(sys.platform=='linux' and os.geteuid()==0,'root_linux_required')
        root=Path(__file__).absolute().parents[2]
        result=verify_source(root,args.source_manifest_sha256)
        if args.operation=='verify-source':
            require(not remaining,'unexpected_arguments');print(json.dumps(result));return 0
        directory=Path(__file__).absolute().parent
        sys.path.insert(0,str(directory))
        module=directory/ROUTES[args.operation]
        routed=([args.operation] if args.operation in {'prepare','verify','rollback'} else [])+remaining
        if args.operation=='audit':routed=['--audit-active',*routed]
        sys.argv=[str(module),*routed]
        runpy.run_path(str(module),run_name='__main__')
        return 0
    except (OSError,ValueError,UnicodeError) as error:
        print(json.dumps({'status':'SOURCE_OR_COMMAND_REFUSED','error':str(error),'deployment_ready':False}))
        return 2


if __name__=='__main__':raise SystemExit(main())
