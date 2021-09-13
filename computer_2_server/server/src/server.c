#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include "exit_codes.h"
#include "parameters.h"
#include "openssl.h"
#include "init_server.h"
#include "handler.h"

int main(int argc, char **argv) {
	if(!generate_new_key_pair())
		exit(EXIT_FAILURE);

	uint16_t port = find_port();
	#if DEBUG
		printf("Debug :: main :: The choosen port: %hu\n", port);
	#endif

	int sockfd = start_server(port);
	printf("Server: Started listening on port %hu\n", port);

	int connfd;
	while(true) { // The server runs until exit(...)
		connfd = accept_client(sockfd);

		if (connfd >= 0)
			handle_client(sockfd, connfd);
	}
}