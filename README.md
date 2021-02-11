# digsig

## Install
```bash
pip install digsig
```

## Usage
```python
from digsig import PrivateKey

private_key = PrivateKey('file.p12', 'p4ssw0rd')
signature = private_key.sign("message to sign")
```
