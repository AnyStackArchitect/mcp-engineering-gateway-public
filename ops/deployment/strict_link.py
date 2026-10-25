"""Offline CIL link via installed libsepol. Never load a kernel policy."""
import ctypes as c
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
assert len(sys.argv) == 1
lib = c.CDLL('libsepol.so.2')
libc = c.CDLL(None)
ptr = c.c_void_p
lib.cil_db_init.argtypes = [c.POINTER(ptr)]
lib.cil_db_init.restype = None
lib.cil_db_destroy.argtypes = [c.POINTER(ptr)]
lib.cil_db_destroy.restype = None
lib.cil_add_file.argtypes = [ptr, c.c_char_p, c.c_char_p, c.c_size_t]
lib.cil_add_file.restype = c.c_int
lib.cil_compile.argtypes = [ptr]
lib.cil_compile.restype = c.c_int
lib.cil_build_policydb.argtypes = [ptr, c.POINTER(ptr)]
lib.cil_build_policydb.restype = c.c_int
lib.cil_set_mls.argtypes = [ptr, c.c_int]
lib.cil_set_policy_version.argtypes = [ptr, c.c_int]
lib.cil_set_mls.restype = lib.cil_set_policy_version.restype = None
lib.sepol_policydb_to_image.argtypes = [ptr, ptr, c.POINTER(ptr), c.POINTER(c.c_size_t)]
lib.sepol_policydb_to_image.restype = c.c_int
lib.sepol_policydb_free.argtypes = [ptr]
lib.sepol_policydb_free.restype = None
libc.free.argtypes = [ptr]
db = ptr()
policy = ptr()
data = ptr()
size = c.c_size_t()
lib.cil_db_init(c.byref(db))
try:
    lib.cil_set_multiple_decls.argtypes = [ptr, c.c_int]
    lib.cil_set_multiple_decls.restype = None
    lib.cil_set_multiple_decls(db, 1)
    lib.cil_set_mls(db, 1)
    lib.cil_set_policy_version(db, 35)
    # Binary-to-CIL export omits the module linker's unused require sinks.
    # Reintroduce only those declarations; do not strip requires or assertions.
    metadata = b'(typeattribute cil_gen_require)\n(roleattribute cil_gen_require)\n'
    # Native base source already declares its require attributes.
    for name in json.loads((root / 'link-inputs.json').read_text()):
        content = (root / name).read_bytes()
        assert lib.cil_add_file(db, name.encode(), content, len(content)) == 0, name
    assert lib.cil_compile(db) == 0, 'CIL compile/neverallow failed'
    assert lib.cil_build_policydb(db, c.byref(policy)) == 0, 'CIL policy build failed'
    assert lib.sepol_policydb_to_image(None, policy, c.byref(data), c.byref(size)) == 0
    output = c.string_at(data, size.value)
    (root / 'combined-policy.35').write_bytes(output)
    print(json.dumps({'offline_link': 'PASS', 'bytes': len(output),
                      'sha256': hashlib.sha256(output).hexdigest(),
                      'kernel_policy_loaded': False}))
finally:
    if data:
        libc.free(data)
    if policy:
        lib.sepol_policydb_free(policy)
    lib.cil_db_destroy(c.byref(db))
