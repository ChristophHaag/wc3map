import struct
from io import BytesIO
import bz2
import zlib


# stolen from https://github.com/eagleflo/mpyq


def decompress(data):
    """Read the compression type and decompress file data."""
    compression_type = ord(data[0:1])
    if compression_type == 0:
        return data
    elif compression_type == 2:
        return zlib.decompress(data[1:], 15)
    elif compression_type == 16:
        return bz2.decompress(data[1:])
    else:
        raise RuntimeError("Unsupported compression type.")

def _hash(string, hash_type):
    """Hash a string using MPQ's hash function."""
    hash_types = {
        'TABLE_OFFSET': 0,
        'HASH_A': 1,
        'HASH_B': 2,
        'TABLE': 3
    }
    seed1 = 0x7FED7FED
    seed2 = 0xEEEEEEEE

    for ch in string.upper():
        if not isinstance(ch, int): ch = ord(ch)
        value = encryption_table[(hash_types[hash_type] << 8) + ch]
        seed1 = (value ^ (seed1 + seed2)) & 0xFFFFFFFF
        seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3 & 0xFFFFFFFF

    return seed1


def _decrypt(data, key):
    """Decrypt hash or block table or a sector."""
    seed1 = key
    seed2 = 0xEEEEEEEE
    result = BytesIO()

    for i in range(len(data) // 4):
        seed2 += encryption_table[0x400 + (seed1 & 0xFF)]
        seed2 &= 0xFFFFFFFF
        value = struct.unpack("<I", data[i * 4:i * 4 + 4])[0]
        value = (value ^ (seed1 + seed2)) & 0xFFFFFFFF

        seed1 = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B)
        seed1 &= 0xFFFFFFFF
        seed2 = value + seed2 + (seed2 << 5) + 3 & 0xFFFFFFFF

        result.write(struct.pack("<I", value))

    return result.getvalue()


def _prepare_encryption_table():
    """Prepare encryption table for MPQ hash function."""
    seed = 0x00100001
    crypt_table = {}

    for i in range(256):
        index = i
        for j in range(5):
            seed = (seed * 125 + 3) % 0x2AAAAB
            temp1 = (seed & 0xFFFF) << 0x10

            seed = (seed * 125 + 3) % 0x2AAAAB
            temp2 = (seed & 0xFFFF)

            crypt_table[index] = (temp1 | temp2)

            index += 0x100

    return crypt_table


encryption_table = _prepare_encryption_table()
