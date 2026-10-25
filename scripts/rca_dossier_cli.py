#!/usr/bin/env python3
"""Deliberately disclose bounded attributed reasoning to the read-only report."""
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from casework import CaseStore,CaseError,_regular_open
from dossierwork import prepare,accept,MAX_BYTES


def main():
    if len(sys.argv)!=2 or os.geteuid()==0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        raise CaseError('Interactive nonroot operator terminal required')
    fd,info=_regular_open(Path(sys.argv[1]))
    with os.fdopen(fd,'rb') as stream:
        if info.st_nlink!=1 or info.st_size>MAX_BYTES:raise CaseError('Unsafe or oversized dossier input')
        data=json.loads(stream.read(MAX_BYTES+1))
    store=CaseStore(Path.home());preview=prepare(store,data)
    print(json.dumps(preview,sort_keys=True,ensure_ascii=True,indent=2))
    if input('Review EVERY field for disclosure. Type ACCEPT followed by the full review SHA256: ')!='ACCEPT '+preview['review_sha256']:
        print('No dossier accepted.');return 1
    print(json.dumps(accept(store,data,preview['review_sha256'],interactive=True)))
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (CaseError,OSError,ValueError,TypeError,KeyError):
        print('Dossier refused; no success implied.',file=sys.stderr);raise SystemExit(1)
