<h1 align="center">
DigSig
</h1>

<p align="center">
    <a href="https://pepy.tech/project/digsig/"><img alt="Downloads" src="https://img.shields.io/badge/dynamic/json?style=flat-square&maxAge=3600&label=downloads&query=$.total_downloads&url=https://api.pepy.tech/api/projects/digsig"></a>
    <a href="https://pypi.python.org/pypi/digsig/"><img alt="PyPi" src="https://img.shields.io/pypi/v/digsig.svg?style=flat-square"></a>
    <a href="https://github.com/labteral/digsig/releases"><img alt="GitHub releases" src="https://img.shields.io/github/release/labteral/digsig.svg?style=flat-square"></a>
    <a href="https://github.com/labteral/digsig/blob/master/LICENSE"><img alt="License" src="https://img.shields.io/github/license/labteral/digsig.svg?style=flat-square&color=green"></a>
</p>

<h3 align="center">
<b>Digital signatures with Python</b>
</h3>

<p align="center">
    <a href="https://www.buymeacoffee.com/brunneis" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="35px"></a>
</p>

The private key detection is automatic with the class `PrivateKey`. It currently works with RSA (`X.509` with `PKCS#12` files: `.p12`, or `.pfx`) and with ECDSA (Ethereum account exported in a `JSON` file).

## Install
```bash
pip install digsig
```

# Load keys
## Automatic detection
RSA (X.509)
```python
from digsig import PrivateKey, PublicKey

private_key = PrivateKey.get_instance('fnmt.p12', 'p4ssw0rd')
signature = private_key.sign('message')

# public_key = private_key.public_key
public_key = PublicKey.get_instance('fnmt.pem')
```

ECDSA (Ethereum)
```python
from digsig import PrivateKey, PublicKey

private_key = PrivateKey.get_instance('ethereum.json', 'p4ssw0rd')

signature = private_key.sign('message')

public_key = private_key.public_key
```

## RSA
```python
from digsig import RsaPrivateKey, RsaModes, RsaFormats

private_key = RsaPrivateKey('fnmt.p12', 'p4ssw0rd', mode=RsaModes.PSS_MGF1_SHA3_256)
signature = private_key.sign('message')

# public_key = private_key.public_key
public_key = RsaPublicKey('fnmt.pem', mode=RsaModes.PSS_MGF1_SHA3_256)
```

## ECDSA
```python
from digsig import EcdsaPrivateKey, EcdsaModes

private_key = EcdsaPrivateKey('account.json', 'p4ssw0rd', mode=EcdsaModes.SECP256K1_SHA3_256)
signature = private_key.sign('message')

public_key = private_key.public_key
```

# Verify signature
```python
from digsig.errors import InvalidSignatureError

try:
    public_key.verify(signature)
except InvalidSignatureError:
    print('Invalid signature.')
```

# Generate keys
> To-Do

# Export keys
> To-Do

# Supported modes
## RSA
> To-Do

## ECDSA
> To-Do


# Supported formats
## RSA
> To-Do

## ECDSA
> To-Do
