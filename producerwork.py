"""Record bounded producer source identities when derived evidence is built."""
import hashlib
from pathlib import Path
import platform
import re

MODULES=frozenset({'producerwork','timelinework','casework','protocolwork','packettruth','evtxwork','reportwork','dossierwork','streamwork'})


def record(*modules):
    names=sorted(set(modules)|{'producerwork'})
    if not set(names)<=MODULES:raise ValueError('Unknown producer source module')
    root=Path(__file__).resolve().parent
    return {'schema':1,'python_runtime':platform.python_version(),
        'modules':{name:hashlib.sha256((root/(name+'.py')).read_bytes()).hexdigest() for name in names}}


def checked(data):
    if data is None:return {'status':'UNRECORDED_LEGACY_INDEX'}
    if (type(data) is not dict or set(data)!={'schema','python_runtime','modules'} or
            type(data['schema']) is not int or data['schema']!=1 or type(data['python_runtime']) is not str or
            not re.fullmatch(r'[0-9][0-9.]{0,31}',data['python_runtime']) or
            type(data['modules']) is not dict or not 1<=len(data['modules'])<=len(MODULES)):
        raise ValueError('Invalid producer identity')
    for name,digest in data['modules'].items():
        if name not in MODULES or type(digest) is not str or not re.fullmatch('[a-f0-9]{64}',digest):
            raise ValueError('Invalid producer source identity')
    return data
