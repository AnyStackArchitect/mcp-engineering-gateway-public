#!/usr/bin/env python3
"""Local operator review; never run on behalf of an MCP client or evidence file."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from casework import CaseStore,CaseError,_regular_open
from librarywork import MAX_NOTE,prepare,accept


def main():
    if len(sys.argv)!=2 or not sys.stdin.isatty() or not sys.stdout.isatty() or os.geteuid()==0:
        raise CaseError('Interactive nonroot operator terminal required')
    fd,info=_regular_open(Path(sys.argv[1]))
    with os.fdopen(fd,'rb') as source:
        if info.st_size>MAX_NOTE or info.st_nlink!=1:
            raise CaseError('Unsafe or oversized local review note')
        data=json.loads(source.read(MAX_NOTE+1))
    store=CaseStore(Path.home())
    reviewed=prepare(store,data)
    print(json.dumps(reviewed,ensure_ascii=True,sort_keys=True,indent=2))
    print('Confirm rights, accuracy, sanitization and disclosure of this note to MCP.')
    response=input('Type ACCEPT followed by the full review SHA256: ')
    if response!='ACCEPT '+reviewed['review_sha256']:
        print('No library entry accepted.')
        return 1
    print(json.dumps(accept(store,data,reviewed['review_sha256'],interactive=True)))
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (CaseError,ValueError,OSError):
        print('Library acceptance refused; no success implied.',file=sys.stderr)
        raise SystemExit(1)
