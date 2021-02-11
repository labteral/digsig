# digsig

The private key detection is automatic. It currently works with RSA (`PKCS#12` file: `.p12`, or `.pfx`) and with ECDSA (Ethereum account exported in a `JSON` file).

## Install
```bash
pip install digsig
```

## Usage
```python
from digsig import PrivateKey

private_key = PrivateKey('fnmt.p12', 'p4ssw0rd')
# private_key = PrivateKey('ethereum.json', 'p4ssw0rd')

signature = private_key.sign("message to sign")
```
