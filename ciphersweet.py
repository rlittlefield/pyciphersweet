import base64
import secrets
import binascii
import hashlib
import hmac
import struct
import pysodium
from cryptography.hazmat.primitives.kdf import hkdf
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl.backend import Backend
import re


openssl_backend = Backend()


MAGIC_HEADER = b'nacl:'
NONCE_SIZE = 24
DS_BIDX = b"\x7E" * 32
DS_FENC = b"\xB4" * 32
CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE = 4
CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE = 33554432


class Transformation:
    @classmethod
    def last_four_digits(cls, item: str):
        item = re.sub(r'/[^0-9]/', '', item)
        item = item.rjust(4, '0')
        item = item[-4:]
        return item.encode()

    @classmethod
    def default(cls, item):
        if type(item) != bytes:
            new_item = f"{item}"
            encoded_item = new_item.encode()
            return encoded_item
        return item


def encrypt(plaintext, key):
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = pysodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        message=plaintext,
        ad=nonce,
        nonce=nonce,
        key=key
    )
    return MAGIC_HEADER + base64.urlsafe_b64encode(nonce + ciphertext)


def decrypt(ciphertext: bytes, key:bytes):
    if not secrets.compare_digest(ciphertext[:5], MAGIC_HEADER):
        raise Exception('Invalid ciphertext header')
    decoded = base64.urlsafe_b64decode(ciphertext[5:])
    if len(decoded) < NONCE_SIZE + 16:
        raise Exception('Message is too short')
    nonce = decoded[0:NONCE_SIZE]
    encrypted = decoded[NONCE_SIZE:]
    decrypted = pysodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext=encrypted,
        ad=nonce,
        nonce=nonce,
        key=key,
    )
    return decrypted


def blind_index_fast(plaintext: bytes, key: bytes, bit_length: int=256):
    if not bit_length or bit_length > 512:
        raise Exception('invalid bit length')
    if bit_length > 256:
        hash_length = bit_length >> 3
    else:
        hash_length = 32
    if type(plaintext) != bytes:
        plaintext = plaintext.encode()
    hashed = pysodium.crypto_generichash(
        m=plaintext,
        k=key,
        outlen=hash_length,
    )
    result = and_mask(hashed, bit_length)
    return result


def blind_index_slow(plaintext: bytes, key: bytes, bit_length: int=256, **options):
    ops_limit = max(
        options.get('opslimit', CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE),
        CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE
    )
    mem_limit = max(
        options.get('memlimit', CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE),
        CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
    )
    pw_hash_length = bit_length >> 3
    if pw_hash_length < 16:
        pw_hash_length = 16
    if pw_hash_length > 4294967295:
        raise Exception('Output length is far too big');

    hashed = pysodium.crypto_pwhash(
        outlen=pw_hash_length,
        passwd=plaintext,
        salt=pysodium.crypto_generichash(key, outlen=16),
        opslimit=ops_limit,
        memlimit=mem_limit,
        alg=pysodium.crypto_pwhash_ALG_ARGON2ID13,
    )
    result = and_mask(hashed, bit_length)
    return result


def util_pack(*items):
    buffer = []
    buffer.append(struct.pack('<L', len(items)))
    for item in items:
        buffer.append(struct.pack('<Q', len(item)))
        buffer.append(item)
    output = b''.join(buffer)
    return output


def and_mask(mask_input, bits):
    full_byte_count = bits // 8
    leftover_bits_count = bits % 8
    full_bytes = mask_input[:full_byte_count]
    if leftover_bits_count:
        b = mask_input[full_byte_count:full_byte_count+1]
        b = int.from_bytes(b, byteorder='little')
        distance = 8 - leftover_bits_count
        b = b >> distance
        b = b << distance
        full_bytes += b.to_bytes(1, byteorder='little')
    padded = full_bytes.ljust(full_byte_count, b'\x00')
    return padded


class EncryptedField:
    def __init__(self, base_key, table, field):
        self.table = table
        self.field = field
        self.blind_indexes = {}
        self.field_key = self.get_field_symmetric_key(base_key)
        self.blind_key = self.get_blind_index_root_key(base_key)

    def get_field_symmetric_key(self, base_key):
        return self._hkdf(base_key, DS_FENC)

    def get_blind_index_root_key(self, base_key):
        return self._hkdf(base_key, DS_BIDX)

    def _hkdf(self, base_key, info_prefix):
        local_hkdf = hkdf.HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=self.table.encode(),
            info=info_prefix + self.field.encode(),
            backend=openssl_backend,
        )
        output = local_hkdf.derive(base_key)
        return output

    def add_blind_index(self, name: str, transform, output_length: int, fast: bool=False):
        subkey = hmac.new(
            key=self.blind_key,
            msg=util_pack(self.table.encode(), self.field.encode(), name.encode()),
            digestmod=hashlib.sha256
        ).digest()

        if not transform:
            transform = Transformation.default
        self.blind_indexes[name] = {
            'name': name,
            'transform': transform,
            'output_length': output_length,
            'subkey': subkey,
            'speed': 'fast' if fast else 'slow',
        }

    def get_blind_index(self, plaintext, name):
        type_column = ''
        output = {
            'type': type_column,
            'value': binascii.hexlify(self.get_blind_index_raw(
                plaintext=plaintext,
                name=name,
            )).decode()
        }
        return output

    def get_blind_index_raw(self, plaintext, name):
        if name not in self.blind_indexes:
            raise Exception(f"Blind index {name} not found")
        index_info = self.blind_indexes[name]
        plaintext = index_info.get('transform')(plaintext)
        speed = index_info.get('speed')
        if speed == 'slow':
            blind_index_function = blind_index_slow
        elif speed == 'fast':
            blind_index_function = blind_index_fast
        else:
            raise Exception('invalid blind index speed')

        blind_idx = blind_index_function(
            plaintext,
            index_info['subkey'],
            index_info['output_length'],
        )
        return blind_idx

    def encrypt(self, plaintext):
        output = encrypt(plaintext, self.field_key)
        return output

    def decrypt(self, ciphertext):
        output = decrypt(ciphertext, self.field_key)
        return output

    def get_all_blind_indexes(self, plaintext):
        pass
