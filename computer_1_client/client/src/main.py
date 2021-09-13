import socket
import re
import os

import rsa
import attack
import param
import my_math

def compare_bytes(password, decrypted_with_pad):
    dec = decrypted_with_pad.split('|0x')
    dec = dec[1:]
    dec = list(map(my_math.str_hex_to_int, dec))

    gap = len(dec) - len(password)

    dec = dec[gap:] # removing the paddded part
    # now the bytes in dec are only the bytes of the password its self.

    for index in range(len(dec)):
        if dec[index] == password[index]:
            print("Password's {} byte is the same in decrypt and in the original password ({})".format(index, chr(password[index])))


def connect_server():
    param.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    param.sock.connect((param.host, param.port)) # Will throw exception if can't connect after few seconds.

def disconnect_server():
    if param.sock != 0:
        param.sock.sendall(b'shutdown')
        param.sock.close()

def prepare(message):
    # Credit: https://stackoverflow.com/questions/1665511/python-equivalent-to-atoi-atof
    # Credit: https://stackoverflow.com/questions/9868653/find-first-sequence-item-that-matches-a-criterion
    # Setting up the request from the server
    # according to the server's protocol
    send_data = b'enc ' + message

    # Sending the data
    param.sock.sendall(send_data)

    # Receiving the data
    recv_data = param.sock.recv(param.max_message_size) # the data that we receive is byte array

    # Checking if we got error from server
    if recv_data[0:6] == b'ERROR':
        str_error_code = recv_data[6].decode('ascii')
        if str_error_code != '3': # ERROR_3 will shutdown the server on its on
            param.sock.sendall(b'shutdown')
        param.sock.close()
        raise Exception('Error: got ERROR_' + str_error_code + ' from server in prepare')

    # Getting the size of the ciphertext (number of bytes)
    data_size_end = next(i for i in range(param.max_message_size) if recv_data[i] == 0) # 0 = '\0'
    byte_data_size = recv_data[0:data_size_end]
    str_recv_data = byte_data_size.decode('ascii')
    regex = re.compile(r'[^\d-]*(-?[\d]+(\.[\d]*)?([eE][+-]?[\d]+)?)')
    str_data_size = regex.match(str_recv_data).groups()[0] # Gets the first result in the string
    len_str_data_size = len(str_data_size)
    data_size = int(str_data_size)

    cip_begin = len_str_data_size + 1 # skipping the null terminator
    cip_end = cip_begin + data_size

    return recv_data[cip_begin:cip_end]

def main():
    # Credit: https://stackoverflow.com/questions/4934806/how-can-i-find-scripts-directory
    
    # The password of the "user" that going to be encrypted and the attacker trying to decrypt it
    password = b'MY_pa$$w0rd_is_v3ry_c0mpl3Xtdkfstawwxvfxjhayqpjjfclmyvfvreyuuxsufgmnoyeaxmyigkbbtadbkktdisnsrqbuponddfwhhsfdpfhcnqvkpgtvmodabdnsiawfowkyjckonsgfkikpnndzcttflumruwmthfiktovxcowrsiwqpnvvsemwxuqgdqugojfayxanddfplrypasiofhwzjxamlfmtjnsqjmcwmdkvsblia'
    param.cwd = os.path.dirname(os.path.realpath(__file__))

    connect_server()
    (param.n, param.e) = rsa.get_public_key()
    if param.encrypt_openssl:
        ciphertext = prepare(password)
    else:
        padded_password = rsa.PKCS1_encode(password, param.k)
        ciphertext = rsa.encrypt_string(padded_password)
    decrypted_with_pad = attack.bleichenbacher(ciphertext)
    try:
        decrypted = rsa.PKCS1_decode(decrypted_with_pad)
    except:
        decrypted = decrypted_with_pad
    disconnect_server()

    print("----------")
    print("Original password:")
    print(password)
    print("Ciphertext of the password that we try to decrypt:")
    print(''.join('|0x{:02X}'.format(x) for x in ciphertext))
    print("Our decryption of the password's ciphertext with padding:")
    print("|0x00" + ''.join('|0x{:02X}'.format(x) for x in decrypted_with_pad))
    print("Our decryption of the password's ciphertext:")
    print("|0x00" + ''.join('|0x{:02X}'.format(x) for x in decrypted))
    print("Compare the bytes of the password and the decrpyted password:")
    compare_bytes(password, decrypted_with_pad)

if __name__ == "__main__":
    main()
