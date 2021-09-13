
# RSA key
modulus_size = 2048
(n, e) = (0, 0) # Not being initialize here

# modulus size in bytes
k = modulus_size // 8

# keep track of the oracle calls
queries = 0
print_queries_every = 1
number_of_time_to_confirm_conforming = 10

# Choose to use OpenSSL encrypt function or our own implementations
encrypt_openssl = True

# start timer
t_start = 0 # Not being initialize here

# Current Working Directory of the project
cwd = ""

# Server info
host = '10.0.0.1'
port = 4430
sock = 0 # Not being initialize here
max_message_size = 2048
