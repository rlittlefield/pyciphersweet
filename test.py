import pytest
import ciphersweet
import secrets
import binascii


nacl_key = binascii.unhexlify('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc')


def test_encrypt():
    key = secrets.token_bytes(32)
    plaintext = b'plaintext example'
    encrypted = ciphersweet.encrypt(plaintext, key)
    decrypted = ciphersweet.decrypt(encrypted, key)
    assert plaintext == decrypted


@pytest.mark.parametrize("test_input,name,expected", [
    ['111-11-1111', 'contact_ssn_last_four', '7843'],
    ['111-11-2222', 'contact_ssn_last_four', 'd246'],
    ['123-45-6788', 'contact_ssn_last_four', '4882'],
    ['123-45-6789', 'contact_ssn_last_four', '92c8'],
    ['invalid guess 123', 'contact_ssn', 'b6fd11a1'],
    ['123-45-6789', 'contact_ssn', '30c7cc68'],
])
def test_encrypted_field_fast(test_input, name, expected):
    ssn = get_example_field(longer=False, fast=True)
    result1 = ssn.get_blind_index(test_input, name)
    assert expected == result1['value']


@pytest.mark.parametrize("test_input,name,expected", [
    ['111-11-1111', 'contact_ssn_last_four', '32ae'],
    ['111-11-2222', 'contact_ssn_last_four', 'e538'],
    ['123-45-6788', 'contact_ssn_last_four', '8d1a'],
    ['123-45-6789', 'contact_ssn_last_four', '2acb'],
    ['invalid guess 123', 'contact_ssn', '499db508'],
    ['123-45-6789', 'contact_ssn', '311314c1'],
])
def test_encrypted_field_slow(test_input, name, expected):
    ssn = get_example_field(longer=False, fast=False)
    result1 = ssn.get_blind_index(test_input, name)
    assert expected == result1['value']


@pytest.mark.parametrize("test_input,expected", [
    [[], b'\x00\x00\x00\x00'],
    [[b''], b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'],
    [[b'test'], b'\x01\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test'],
    [
        [b'test', b'again'],
        b'\x02\x00\x00\x00'
        b'\x04\x00\x00\x00\x00\x00\x00\x00test'
        b'\x05\x00\x00\x00\x00\x00\x00\x00again'
    ],
])
def test_util_pack(test_input, expected):
    r1 = ciphersweet.util_pack(*test_input)
    assert r1 == expected


def get_example_field(longer=False, fast=False) -> ciphersweet.EncryptedField:
    field = ciphersweet.EncryptedField(
        base_key=nacl_key,
        table='contacts',
        field='ssn',
    )
    t = ciphersweet.Transformation.last_four_digits
    field.add_blind_index('contact_ssn_last_four', t, 64 if longer else 16, fast=fast)
    field.add_blind_index('contact_ssn', None, 128 if longer else 32, fast=fast)
    return field


def test_blind_index_fast():
    key = secrets.token_bytes(32)

    plaintext = b'8017090830'
    blind_index = ciphersweet.blind_index_fast(
        plaintext=plaintext,
        key=key
    )
    assert blind_index


@pytest.mark.parametrize("mask_input,size,output,output_right", [
    ['ff', 4, b'f0', b'0f'],
    ['ff', 8, b'ff', b'ff'],
    ['ff', 9, b'ff00', b'ff00'],
    ['ffffffff', 16, b'ffff', b'ffff'],
    ['ffffffff', 17, b'ffff80', b'ffff01'],
    ['ffffffff', 18, b'ffffc0', b'ffff03'],
    ['ffffffff', 19, b'ffffe0', b'ffff07'],
    ['ffffffff', 20, b'fffff0', b'ffff0f'],
    ['ffffffff', 21, b'fffff8', b'ffff1f' ],
    ['ffffffff', 22, b'fffffc', b'ffff3f'],
    ['ffffffff', 23, b'fffffe', b'ffff7f'],
    ['ffffffff', 24, b'ffffff', b'ffffff'],
    ['ffffffff', 32, b'ffffffff', b'ffffffff'],
    ['ffffffff', 64, b'ffffffff00000000', b'ffffffff00000000'],
    ['ffffffff', 65, b'ffffffff00000000', b'ffffffff00000000'],
    ['55f6778c', 11, b'55e0', b'5506'],
    ['55f6778c', 12, b'55f0', b'5506'],
    ['55f6778c', 13, b'55f0', b'5516'],
    ['55f6778c', 14, b'55f4', b'5536'],
    ['55f6778c', 15, b'55f6', b'5576'],
    ['55f6778c', 16, b'55f6', b'55f6'],
    ['55f6778c', 17, b'55f600', b'55f601'],
    ['55f6778c', 32, b'55f6778c', b'55f6778c'],
])
def test_mask(mask_input, size, output, output_right):
    mask_input = binascii.unhexlify(mask_input)
    masked = ciphersweet.and_mask(mask_input, size)
    masked_hex = binascii.hexlify(masked)
    assert output == masked_hex
