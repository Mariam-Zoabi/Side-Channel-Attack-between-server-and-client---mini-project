
# Note: https://stackoverflow.com/questions/9454463/are-openssl-byte-sequences-in-little-endian-or-big-endian-order
# OpenSSL works with big endian too.

def bytes_to_integer(bytes_obj):
    return int.from_bytes(bytes_obj, byteorder="big")

def integer_to_bytes(integer):
    k = integer.bit_length()

    # adjust number of bytes
    bytes_length = k // 8 + (k % 8 > 0)

    bytes_obj = integer.to_bytes(bytes_length, byteorder="big")

    return bytes_obj
