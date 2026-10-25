"""Source-bound declared identity gate, never vendor compatibility proof."""
import hashlib,json,os,re
from casework import CaseError,CASE_ID,_regular_open

PRODUCT=re.compile(r'[a-z0-9][a-z0-9._-]{0,47}\Z')
VERSION=re.compile(r'[A-Za-z0-9][A-Za-z0-9._+()-]{0,63}\Z')
MAX_DECLARATION=4096


def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise CaseError('Duplicate version declaration field')
        result[key]=value
    return result


def checked_declaration(store,folder,manifest,family,recipe_sha256,product,platform_version,version_artifact_id):
    controls=(product,platform_version,version_artifact_id)
    if all(v is None for v in controls):
        return {'status':'UNKNOWN','reason':'version_identity_evidence_not_supplied','vendor_compatibility_verified':False}
    if (any(v is None for v in controls) or type(product) is not str or not PRODUCT.fullmatch(product) or
        type(platform_version) is not str or not VERSION.fullmatch(platform_version) or
        type(version_artifact_id) is not str or not CASE_ID.fullmatch(version_artifact_id)):
        raise CaseError('Product, exact platform version and registered declaration must be supplied together')
    path,item=store._artifact(folder,manifest,version_artifact_id)
    fd,info=_regular_open(path)
    with os.fdopen(fd,'rb') as stream:
        if info.st_nlink!=1 or info.st_size>MAX_DECLARATION:raise CaseError('Version declaration source budget exceeded')
        raw=stream.read(MAX_DECLARATION+1);after=os.fstat(stream.fileno())
    current=path.lstat()
    if (len(raw)!=item['bytes'] or hashlib.sha256(raw).hexdigest()!=item['sha256'] or
        (info.st_ino,info.st_dev,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_ino,after.st_dev,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or
        (info.st_ino,info.st_dev,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(current.st_ino,current.st_dev,current.st_size,current.st_mtime_ns,current.st_ctime_ns)):
        raise CaseError('Version declaration original changed')
    try:data=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs)
    except (ValueError,UnicodeError,RecursionError) as exc:raise CaseError('Invalid version declaration JSON') from exc
    if (type(data) is not dict or set(data)!={'schema','family','product','version','recipe_sha256'} or
        type(data['schema']) is not int or data['schema']!=1 or type(data['family']) is not str or not PRODUCT.fullmatch(data['family']) or
        type(data['product']) is not str or not PRODUCT.fullmatch(data['product']) or
        type(data['version']) is not str or not VERSION.fullmatch(data['version']) or
        type(data['recipe_sha256']) is not str or not re.fullmatch('[a-f0-9]{64}',data['recipe_sha256'])):
        raise CaseError('Invalid exact version declaration fields')
    matches={'family':data['family']==family,'product':data['product']==product,
        'version':data['version']==platform_version,'recipe_sha256':data['recipe_sha256']==recipe_sha256}
    return {'status':'DECLARATION_MATCH_COMPATIBILITY_UNVERIFIED' if all(matches.values()) else 'DECLARATION_MISMATCH_DO_NOT_APPLY',
        'requested_product':product,'requested_version':platform_version,'identity_matches':matches,
        'artifact_id':version_artifact_id,'source_sha256':item['sha256'],'locator_type':'json_member',
        'locator_keys':['family','product','version','recipe_sha256'],
        'basis':'operator_supplied_declaration_not_live_inventory_or_vendor_validation',
        'vendor_compatibility_verified':False,'root_cause_established':False}
