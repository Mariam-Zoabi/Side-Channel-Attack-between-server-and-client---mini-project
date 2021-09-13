#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "exit_codes.h"
#include "parameters.h"

// Will search for available port, by default will start at DEFAULT_PORT.
uint16_t find_port() {
	uint16_t port = DEFAULT_PORT;
	char port_str[6]; // max unsigned short 65535
	
	// Finding the ABSOLUTE path to the script is_port_free.sh
	char binary[PATH_MAX] = { 0 };
	if(readlink("/proc/self/exe", binary, PATH_MAX) < 0) {
		fprintf(stderr, "Error: Couldn't readlink in generate_new_key_pair (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	char* binary_pointer = strrchr(binary, (int) '/');
	*binary_pointer = '\0';
	binary_pointer = strrchr(binary, (int) '/');
	*binary_pointer = '\0';
	strcat(binary, "/script/is_port_free.sh");
	#if DEBUG
		printf("Debug :: find_port :: binary: %s\n", binary);
	#endif

	char* argv[] = {"is_port_free.sh", "", NULL};
	int exit_code;
	pid_t pid;
	int my_pipe[2];
	char output[1];
	int nbytes;

	while(true) {
		if(pipe(my_pipe) == -1) {
			fprintf(stderr, "Error: Couldn't pipe in find_port\n");
			exit(EXIT_FAILURE);
		}

		pid = fork();
		if(pid < 0) {
			fprintf(stderr, "Error: Couldn't fork in find_port\n");
			exit(EXIT_FAILURE);
		} else if(pid == 0) { /* child */
			close(my_pipe[PIPE_READ]);
			dup2 (my_pipe[PIPE_WRITE], STDOUT_FILENO);
			close(my_pipe[PIPE_WRITE]);

			sprintf(port_str, "%hu", port); // converting int(port) to string(port_str)
			argv[1] = port_str;
			execv(binary, argv); // ./../is_port_free.sh port
			exit(EXIT_CANT_RUN_SCRIPT);
		} else { /* parent */
			close(my_pipe[PIPE_WRITE]);

			nbytes = read(my_pipe[PIPE_READ], output, sizeof(output));
			#if DEBUG
    		printf("Debug :: find_port :: read from pipe: %.*s\n", nbytes, output);
			#endif

			waitpid(pid, &exit_code, 0);
			close(my_pipe[PIPE_READ]);

			if(exit_code == EXIT_SUCCESS) {
				if(output[0] == '0')
					return port;
				else if(output[0] == '1')
					port++; // checking the next port number
				else {
					fprintf(stderr, "Error: is_port_free.sh script return invalid output(%c)\n", output[0]);
					exit(EXIT_FAILURE);
				}
			} else if(exit_code == EXIT_CANT_RUN_SCRIPT) {
				fprintf(stderr, "Error: Couldn't run is_port_free.sh script\n");
				exit(EXIT_FAILURE);
			} else {
				fprintf(stderr, "Error: Unknown error(%d) at find_port\n", exit_code);
				exit(EXIT_FAILURE);
			}
		}
	}
}

// Create a working socket and start listen.
int start_server(uint16_t port) {
	// Credit: https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/
	int sockfd;
	struct sockaddr_in servaddr;

	// socket create and verification
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		fprintf(stderr, "Error: socket creation failed\n");
		exit(EXIT_FAILURE);
	}
	#if DEBUG
	else
		printf("Debug :: main :: Socket was created\n");
	#endif
	bzero(&servaddr, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	// Binding newly created socket to given IP and verification
	if ((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) {
		fprintf(stderr, "Error: socket bind failed\n");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	#if DEBUG
	else
		printf("Debug :: main :: Socket successfully binded\n");
	#endif

	// Now server is ready to listen and verification
	if ((listen(sockfd, 5)) != 0) {
		fprintf(stderr, "Error: Listen failed\n");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	#if DEBUG
	else
		printf("Debug :: main :: Server listening\n");
	#endif

	return sockfd;
}

// Waiting for client and returning his socket.
int accept_client(int sockfd) {
	// Credit: https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/
	struct sockaddr_in cli;
	int connfd, len = sizeof(cli);

	// Accept the data packet from client and verification
	connfd = accept(sockfd, (struct sockaddr*)&cli, &len);
	if (connfd < 0)
		printf("Server: failed accepting connection from a client\n");
	else
		printf("Server: acccepted a client\n");
	
	return connfd;
}