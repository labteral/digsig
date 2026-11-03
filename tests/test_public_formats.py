"""Public factories preserve signer identity across disk and memory formats."""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from digsig import PublicKey, RsaPrivateKey, RsaModes, EcdsaPrivateKey, EcdsaPublicKey, EcdsaModes


def test_rsa_factory_keeps_positional_api_and_memory_pem_der(tmp_path):
    key = RsaPrivateKey(mode=RsaModes.PSS_MGF1_SHA256, key_size=2048)
    pem = key.public_key.public_pem
    signature = key.sign('fixture')
    path = tmp_path / 'public.pem'
    path.write_text(pem)
    PublicKey.get_instance(path, RsaModes.PSS_MGF1_SHA256, 'PEM').verify('fixture', signature)
    public = serialization.load_pem_public_key(pem.encode())
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    for value in (pem, pem.encode(), der):
        loaded = PublicKey.get_instance(key=value)
        loaded.verify('fixture', signature)
        with pytest.raises(Exception):
            loaded.verify('altered', signature)


@pytest.mark.parametrize('mode', EcdsaModes.options())
def test_ecdsa_file_raw_pem_der_and_coordinates(tmp_path, mode):
    key = EcdsaPrivateKey(key=1, mode=mode, key_format='RAW_VALUE')
    assert len(key.private_bytes) == 32
    signature = key.sign('fixture')
    pem = key.public_key.public_pem.encode()
    native = serialization.load_pem_public_key(pem)
    formats = [('PEM', pem), ('DER', native.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
               ('RAW_VALUE', key.public_key.public_bytes), ('RAW_VALUE', key.public_key.public_bytes.hex().encode()),
               ('RAW_VALUE', native.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint))]
    for fmt, data in formats:
        path = tmp_path / ('public.' + fmt)
        path.write_bytes(data)
        for public in (EcdsaPublicKey(filepath=path, mode=mode, key_format=fmt), PublicKey.get_instance(key=data, mode=mode)):
            assert public.public_bytes == key.public_key.public_bytes
            public.verify('fixture', signature)
            with pytest.raises(Exception):
                public.verify('altered', signature)
    PublicKey.get_instance(key=key.public_key.public_value, mode=mode).verify('fixture', signature)
    wrong = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(ValueError):
        PublicKey.get_instance(key=wrong)
    with pytest.raises(ValueError):
        PublicKey.get_instance(key=b'\0' * 64)
