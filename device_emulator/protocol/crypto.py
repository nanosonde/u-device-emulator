from __future__ import annotations

import zlib

from Crypto.Cipher import AES

from ..constants import FLAG_AES_GCM, FLAG_COMPRESSED_SNAPPY, FLAG_COMPRESSED_ZLIB, FLAG_ENCRYPTED


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def unpad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid PKCS7 block")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS7 padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS7 padding bytes")
    return data[:-pad_len]


def decrypt_payload(flags: int, mac_bytes: bytes, iv: bytes, key_hex: str, payload: bytes, aad: bytes = b"") -> bytes:
    key = bytes.fromhex(key_hex)
    if flags & FLAG_ENCRYPTED:
        if flags & FLAG_AES_GCM:
            if len(payload) < 16:
                raise ValueError("GCM payload too short")
            ciphertext, tag = payload[:-16], payload[-16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            if aad:
                cipher.update(aad)
            plain = cipher.decrypt_and_verify(ciphertext, tag)
        else:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plain = unpad_pkcs7(cipher.decrypt(payload))
    else:
        plain = payload

    if flags & FLAG_COMPRESSED_ZLIB:
        plain = zlib.decompress(plain)
    if flags & FLAG_COMPRESSED_SNAPPY:
        raise ValueError("Snappy-compressed payload not supported by this simulator")
    return plain
