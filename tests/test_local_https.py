"""Verify actual OpenSSL IP certificates without changing system trust or services."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

BASH = shutil.which('bash')
OPENSSL = shutil.which('openssl')
if os.name == 'nt':
    git = Path('C:/Program Files/Git')
    BASH = str(git/'bin/bash.exe') if (git/'bin/bash.exe').exists() else None
    OPENSSL = str(git/'usr/bin/openssl.exe') if (git/'usr/bin/openssl.exe').exists() else None


@unittest.skipUnless(BASH and OPENSSL, 'Requires Bash and OpenSSL')
class LocalHTTPSTests(unittest.TestCase):
    def test_ip_certificate_renewal_and_invalid_input(self):
        script = Path(__file__).resolve().parents[1]/'scripts/setup-local-https.sh'
        with tempfile.TemporaryDirectory(prefix='.https-test-', dir=script.parent.parent) as temp:
            env = {**os.environ, 'TLS_CERT_DIR':Path(temp).as_posix(), 'MSYS_NO_PATHCONV':'1'}
            # Git Bash needs its bundled OpenSSL in PATH when run from Python on Windows.
            if os.name == 'nt':
                env['PATH'] = str(Path(OPENSSL).parent) + os.pathsep + env.get('PATH','')
            def generate(ip):
                return subprocess.run([BASH, script.as_posix(), ip], env=env, capture_output=True, text=True)
            result = generate('192.168.99.82')
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            cert, ca = Path(temp)/'server.crt', Path(temp)/'portal-root-ca.crt'
            verified = subprocess.run([OPENSSL,'verify','-CAfile',str(ca),'-verify_ip','192.168.99.82',str(cert)],capture_output=True,text=True)
            self.assertEqual(verified.returncode,0,verified.stdout+verified.stderr)
            wrong_ip = subprocess.run([OPENSSL,'verify','-CAfile',str(ca),'-verify_ip','192.168.99.83',str(cert)],capture_output=True)
            self.assertNotEqual(wrong_ip.returncode,0)
            root_hash = hashlib.sha256(ca.read_bytes()).hexdigest()
            key_hash = hashlib.sha256((Path(temp)/'server.key').read_bytes()).hexdigest()
            result = generate('192.168.99.82')
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(hashlib.sha256(ca.read_bytes()).hexdigest(),root_hash)
            self.assertEqual(hashlib.sha256((Path(temp)/'server.key').read_bytes()).hexdigest(),key_hash)
            for ip in ['192.168.99.999','not-an-ip','192.168.99.82;echo']:
                self.assertNotEqual(generate(ip).returncode,0)
            self.assertEqual(hashlib.sha256(ca.read_bytes()).hexdigest(),root_hash)
            self.assertFalse(list(Path(temp).glob('.https.*')))
