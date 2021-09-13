import random

import param
import utils

def PKCS1_encode(message, total_bytes):
    """
    Encodes the given message using PKCS1 v1.5 scheme:
    PKCS1(M) = 0x00 | 0x02 | [non-zero padding bytes] | 0x00 | [M]
    length(PKCS1(M)) = total_bytes
    """

    # 11 = 3 constant bytes and at aleast 8 bytes for padding
    if len(message) > total_bytes - 11:
        raise Exception("Message to big for encoding scheme!")

    pad_len = total_bytes - 3 - len(message)

    # non-zero padding bytes
    padding = bytes(random.sample(range(1, 256), pad_len))

    encoded = b"\x00\x02" + padding + b"\x00" + message

    return encoded

def encrypt_integer(m):
    if m > param.n:
        raise ValueError("Message is to big for current RSA scheme!")

    return pow(m, param.e, param.n)

def encrypt_string(message):
    integer = utils.bytes_to_integer(message)
    enc_integer = encrypt_integer(integer)
    enc_string = utils.integer_to_bytes(enc_integer)

    return enc_string

def PKCS1_decode(encoded):
    """
    Decodes a PKCS1 v1.5 string.
    Remove constant bytes and random pad until arriving at "\x00".
    The rest is the message.
    """

    encoded = encoded[2:]
    idx = encoded.index(b"\x00")

    message = encoded[idx + 1 :]

    return message

def get_public_key():
    # Setting up the request from the server
    # according to the server's protocol
    send_data = b'pubinfo'

    # Sending the data
    param.sock.sendall(send_data)

    # Receiving the data
    recv_data = param.sock.recv(param.max_message_size) # the data that we receive is byte array

    # Checking if we got error from server
    if recv_data[0:6] == b'ERROR':
        param.sock.close()
        raise Exception('Error: got ERROR from server in get_public_key')
    
    # Getting the size of the exponent (number of bytes)
    exp_size_end = next(i for i in range(param.max_message_size) if recv_data[i] == 0) # 0 = '\0'
    byte_exp_size = recv_data[0:exp_size_end]
    str_exp_size = byte_exp_size.decode('ascii')
    exp_size = int(str_exp_size)

    # Getting the exponent
    byte_exp = recv_data[exp_size_end + 1 : exp_size_end + 1 + exp_size]
    str_exp = byte_exp.decode('ascii')
    exp = int(str_exp)

    # Getting the size of the modulus (number of bytes)
    mod_size_end = next(i for i in range(exp_size_end + 2 + exp_size, param.max_message_size) if recv_data[i] == 0) # 0 = '\0'
    byte_mod_size = recv_data[exp_size_end + 2 + exp_size : mod_size_end]
    str_mod_size = byte_mod_size.decode('ascii')
    mod_size = int(str_mod_size)
    
    # Getting the modulus
    byte_mod = recv_data[mod_size_end + 1 : mod_size_end + 1 + mod_size]
    str_mod = byte_mod.decode('ascii')
    mod = int(str_mod, 16)

    return mod, exp