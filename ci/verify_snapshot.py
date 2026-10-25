"""Bind apt-authenticated InRelease payloads to approved snapshot Release bytes."""
import hashlib
from pathlib import Path
import sys

EXPECTED = {
    'ed56aac47e7911e65ee63aae8d67e29f20e023f840e49f8ed037043a33de138a',
    '08a2ef0c2340e5a2b965146879ba5d89b48d484bac2c2d3ee76f32818516413d',
}

def payload(blob):
    if not blob.startswith(b'-----BEGIN PGP SIGNED MESSAGE-----\n'):
        raise ValueError('Not a clear-signed InRelease')
    body = blob.split(b'\n\n', 1)[1].split(b'-----BEGIN PGP SIGNATURE-----\n', 1)
    if len(body) != 2 or not body[1].endswith(b'-----END PGP SIGNATURE-----\n'):
        raise ValueError('Incomplete InRelease')
    return b'\n'.join(line[2:] if line.startswith(b'- ') else line for line in body[0].split(b'\n'))

def verify(directory):
    files = sorted(Path(directory).glob('*_InRelease'))
    observed = {hashlib.sha256(payload(p.read_bytes())).hexdigest() for p in files}
    if len(files) != 2 or observed != EXPECTED:
        raise ValueError('Authenticated snapshot payload mismatch')
    return sorted(observed)

if __name__ == '__main__':
    print('SNAPSHOT_PAYLOADS_VERIFIED', *verify(sys.argv[1]))
