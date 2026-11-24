#!/usr/bin/env python3
"""Build manifest.json (sha256 of every script) and manifest.sig (RSA-SHA256 signature of manifest.json).
Usage: python3 tools/sign.py /path/to/mon-prx-signing-private.pem
The private key never goes into this repository."""
import sys, json, hashlib, base64, glob, os, datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(root)
files = sorted(f.replace('\\', '/') for f in glob.glob('windows/*') + glob.glob('linux/*') if os.path.isfile(f))
entries = [{'path': f, 'sha256': hashlib.sha256(open(f, 'rb').read()).hexdigest()} for f in files]
manifest = {'generated': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'files': entries}
data = json.dumps(manifest, indent=2, sort_keys=True).encode('utf-8')
open('manifest.json', 'wb').write(data)
key = serialization.load_pem_private_key(open(sys.argv[1], 'rb').read(), None)
sig = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
open('manifest.sig', 'w').write(base64.b64encode(sig).decode())
print('signed', len(entries), 'files')
