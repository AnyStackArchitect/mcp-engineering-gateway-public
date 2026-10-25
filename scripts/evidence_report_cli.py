#!/usr/bin/env python3
"""Review exact metadata before making a private local evidence report package."""
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from casework import CaseStore,CaseError
from reportwork import build,package


def main():
    if (len(sys.argv)!=3 or os.geteuid()==0 or not sys.stdin.isatty() or not sys.stdout.isatty()):
        raise CaseError('Interactive nonroot operator terminal required')
    store=CaseStore(Path.home())
    report=build(store,sys.argv[1],sys.argv[2])
    print(json.dumps(report,sort_keys=True,ensure_ascii=True,indent=2))
    print('Review source identifiers, hashes and event times. Raw evidence is excluded.')
    print('This creates a PRIVATE LOCAL package. External disclosure still needs separate approval.')
    response=input('Type PACKAGE followed by the full review SHA256: ')
    if response!='PACKAGE '+report['review_sha256']:
        print('No report packaged.');return 1
    print(json.dumps(package(store,sys.argv[1],sys.argv[2],report['review_sha256'],interactive=True)))
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (CaseError,OSError,ValueError):
        print('Evidence report refused; no success implied.',file=sys.stderr)
        raise SystemExit(1)
