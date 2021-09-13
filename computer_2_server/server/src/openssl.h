#ifndef OPENSSL_H
#define OPENSSL_H

// Create new RSA private/public keys in resource folder
bool generate_new_key_pair();

// Create msg file and encrypt it, resulting in a new ciphertext file in messages folder.
bool encrypt_message(char* msg);

// Create cip file and decrypt it, resulting in a new msg file in messages folder.
bool decrypt_ciphertext(char* cip, size_t size_cip);

// Create modulus and exponent files in resource folder
bool save_public_key_info();

#endif