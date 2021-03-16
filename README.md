# DigSig

The private key detection is automatic with the class `PrivateKeyAuto`. It currently works with RSA (`X.509` with `PKCS#12` files: `.p12`, or `.pfx`) and with ECDSA (Ethereum account exported in a `JSON` file).

## Install
```bash
pip install digsig
```

# Load keys
## Automatic detection
RSA (X.509)
```python
from digsig.auto import PrivateKeyAuto, PublicKeyAuto

private_key = PrivateKeyAuto.get_instance('fnmt.p12', 'p4ssw0rd')
signature = private_key.sign('message')

# public_key = private_key.public_key
public_key = PublicKeyAuto.get_instance('fnmt.pem')
```

ECDSA (Ethereum)
```python
from digsig.auto import PrivateKeyAuto, PublicKeyAuto

private_key = PrivateKeyAuto.get_instance('ethereum.json', 'p4ssw0rd')

signature = private_key.sign('message')

public_key = private_key.public_key
```

## RSA
```python
from digsig.rsa import RsaPrivateKey, RsaModes, RsaFormats

private_key = RsaPrivateKey('fnmt.p12', 'p4ssw0rd', mode=RsaModes.PSS_MGF1_SHA3_256)
signature = private_key.sign('message')

# public_key = private_key.public_key
public_key = RsaPublicKey('fnmt.pem', mode=RsaModes.PSS_MGF1_SHA3_256)
```

## ECDSA
```python
from digsig.ecdsa import EcdsaPrivateKey, EcdsaModes

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
