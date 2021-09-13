#ifndef PARAMETERS_H
#define PARAMETERS_H

// For more readable code
#define true 1
#define false 0
#define PIPE_READ		0
#define PIPE_WRITE	1
typedef char bool;

// Parameters
#define DEBUG false
#define DEBUG2 false

#define DEFAULT_PORT 4430
#define PATH_TO_OPENSSL "/usr/local/ssl/bin/openssl"
#define MAX_MESSAGE_SIZE 2048
#define RSA_MOD_BIT_SIZE "2048"

#define FILE_NAME_PRIVATE_KEY "private_PEM_rsa_aes-256-cbc.key"
#define FILE_NAME_PRIVATE_KEY_WITHOUT_PASSWORD "private_PEM_rsa.key"
#define FILE_NAME_PUBLIC_KEY "public_PEM_rsa.key"
#define FILE_NAME_MESSAGE "msg.txt"
#define FILE_NAME_CIPHERTEXT "ciphertext.txt"
#define FILE_NAME_MODULUS "modulus.txt"
#define FILE_NAME_EXPONENT "exponent.txt"

#endif