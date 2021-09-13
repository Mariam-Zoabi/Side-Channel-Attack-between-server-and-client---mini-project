#ifndef INIT_SERVER_H
#define INIT_SERVER_H

#include <stdint.h>

// Will search for available port, by default will start at DEFAULT_PORT.
uint16_t find_port();

// Create a working socket and start listen.
int start_server(uint16_t port);

// Waiting for client and returning his socket.
int accept_client(int sockfd);

#endif