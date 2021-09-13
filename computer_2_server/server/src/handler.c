#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#include "exit_codes.h"
#include "parameters.h"
#include "openssl.h"

// Global
static char message_buffer[MAX_MESSAGE_SIZE];

#if DEBUG
	void print_buffer() {
		unsigned char current_char;
		for(int i = 0; i < MAX_MESSAGE_SIZE; ++i) {
			current_char = message_buffer[i];
			printf("0x%02X ", current_char);
			if(i%21 == 20)
				printf("\n");
		}
		printf("\n");
	}
#endif

bool send_all(int socket, void *buffer, size_t length) {
	// Credit: https://stackoverflow.com/questions/13479760/c-socket-recv-and-send-all-data
	char *ptr = (char*) buffer;
	while (length > 0) {
		int i = write(socket, ptr, length);
		if (i < 1)
			return false;
		ptr += i;
		length -= i;
	}
	return true;
}

void send_message_to_client(int sockfd, int connfd, const char* msg, int len_msg) {
	// Cleaning buffer
	bzero(message_buffer, MAX_MESSAGE_SIZE);

	strncpy(message_buffer, msg, len_msg);

	#if DEBUG2
		printf("Debug2 :: send_message_to_client :: 1\n");
	#endif
	// send message back to client
	if(!send_all(connfd, message_buffer, MAX_MESSAGE_SIZE)) {
		fprintf(stderr, "Error: couldn't write in send_message_to_client (%s)", strerror(errno));
		close(connfd);
		close(sockfd);
		exit(EXIT_FAILURE);
	};
}

void handle_help(int sockfd, int connfd) {
	static const char* help_message =
		"Usage:\n"
			"\tenc <message>\t\t\t\tWill tell the server to encrypt the message (using his public key)\n"
									"\t\t\t\t\t\tand send back the corresponding ciphertext.\n"
									"\t\t\t\t\t\tThe result format will be: <number of bytes>\\0<ciphertext bytes>\n"
									"\t\t\t\t\t\tIn case of an error:\n"
									"\t\t\t\t\t\t\tERROR_1\tSpace must separate between \"enc\" and the message.\n"
									"\t\t\t\t\t\t\tERROR_2\tMessage can't be of length 0.\n"
									"\t\t\t\t\t\t\tERROR_3\tServer side error, will shutdown the server.\n"
			"\n"
			"\tdec <number of bytes>\\0<ciphertext>\tWill tell the server to decrypt the ciphertext (using his private key)\n"
									"\t\t\t\t\t\tand send back \"DONE\" once he is finished.\n"
									"\t\t\t\t\t\tNote: he will not send back the decrypted message or info about it failing.\n"
									"\t\t\t\t\t\tIn case of an error:\n"
									"\t\t\t\t\t\t\tERROR_1\tSpace must separate between \"dec\" and the ciphertext.\n"
									"\t\t\t\t\t\t\tERROR_2\tCiphertext size must be positive integer.\n"
									"\t\t\t\t\t\t\tERROR_3\tServer side error, will shutdown the server.\n"
			"\n"
			"\tgenkey\t\t\t\t\tWill tell the server to delete his current private/public key pair and create new set.\n"
									"\t\t\t\t\t\tWill send back \"DONE\" once he is finished.\n"
									"\t\t\t\t\t\tIn case of an error, will return \"ERROR\" and shutdown.\n"
			"\n"
			"\tpubinfo\t\t\t\t\tWill ask the server to return the modulus and exponent of the public key.\n"
									"\t\t\t\t\t\tThe result format will be:\n"
									"\t\t\t\t\t\t\t<exponent number of bytes>\\0<exponent in hex without 0x prefix>\\0<modulus number of bytes>\\0<modulus in dec>\n"
									"\t\t\t\t\t\tIn case of an error, will return \"ERROR\" and shutdown.\n"
			"\n"
			"\texit\t\t\t\t\tDisconnect the client.\n"
			"\n"
			"\tshutdown\t\t\t\tDisconnect the client and shutdown the server.\n";
	int len_help_message = strlen(help_message) + 1; // Compiler optimization should set this to const number (+1 for null-termination).

	send_message_to_client(sockfd, connfd, help_message, len_help_message);
}

void handle_genkey(int sockfd, int connfd) {
	if(generate_new_key_pair()) {
		static const char* done_message = "DONE\n";
		int len_done_message = strlen(done_message) + 1;

		send_message_to_client(sockfd, connfd, done_message, len_done_message);
	} else {
		static const char* error_message = "ERROR\n";
		int len_error_message = strlen(error_message) + 1;

		send_message_to_client(sockfd, connfd, error_message, len_error_message);
		
		close(connfd);
		close(sockfd);
		exit(EXIT_SUCCESS);
	}
}

bool send_ciphertext(int sockfd, int connfd) {
	// Credit: https://stackoverflow.com/questions/11952898/c-send-and-receive-file

	// Finding the ABSOLUTE path to the ciphertext
	char ciphertext_path[PATH_MAX] = { 0 };
	if(readlink("/proc/self/exe", ciphertext_path, PATH_MAX) < 0) {
		fprintf(stderr, "Error: Couldn't readlink in send_ciphertext (%s)\n", strerror(errno));
		return false;
	}
	char* binary_pointer = strrchr(ciphertext_path, (int) '/');
	*binary_pointer = '\0';
	binary_pointer = strrchr(ciphertext_path, (int) '/');
	*binary_pointer = '\0';
	sprintf(ciphertext_path, "%s/messages/%s", ciphertext_path, FILE_NAME_CIPHERTEXT);
	#if DEBUG
		printf("Debug :: send_ciphertext :: ciphertext_path: %s\n", ciphertext_path);
	#endif

	// Getting the data from the file
	int fd = open(ciphertext_path, O_RDONLY);
	if(fd < 0) {
		fprintf(stderr, "Error: couldn't open ciphertext_path in send_ciphertext (%s)", strerror(errno));
		return false;
	}
	struct stat file_stat;
	if (fstat(fd, &file_stat) < 0) {
		fprintf(stderr, "Error: couldn't run fstat in send_ciphertext (%s)", strerror(errno));
		close(fd);
		return false;
	}
	#if DEBUG
		printf("Debug :: send_ciphertext :: File Size: %ld bytes\n", file_stat.st_size);
	#endif

	// Cleaning buffer
	bzero(message_buffer, MAX_MESSAGE_SIZE);
	int bytes_of_string_st_size = sprintf(message_buffer, "%ld", file_stat.st_size);
	#if DEBUG
		printf("Debug :: send_ciphertext :: bytes_of_string_st_size: %d\n", bytes_of_string_st_size);
		printf("Debug :: send_ciphertext :: message_buffer after adding file_stat.st_size:\n");
		print_buffer();
	#endif

	char* message_buffer_pointer = &message_buffer[bytes_of_string_st_size + 1]; // +1 to skip null terminator

	if(read(fd, message_buffer_pointer, file_stat.st_size) < 0) {
		fprintf(stderr, "Error: couldn't read ciphertext_path in send_ciphertext (%s)", strerror(errno));
		close(fd);
		return false;
	}
	#if DEBUG
		printf("Debug :: send_ciphertext :: message_buffer after adding ciphertext:\n");
		print_buffer();
	#endif

	// send message back to client
	if(!send_all(connfd, message_buffer, MAX_MESSAGE_SIZE)) {
		fprintf(stderr, "Error: couldn't write in send_ciphertext (%s)", strerror(errno));
		close(connfd);
		close(sockfd);
		exit(EXIT_FAILURE);
	};

	return true;
}

void handle_enc(int sockfd, int connfd) {
	if(message_buffer[3] != ' ') {
		// Space must separate between "enc" and the message.
		static const char* error_message = "ERROR_1\n";
		int len_error_message = strlen(error_message) + 1;

		send_message_to_client(sockfd, connfd, error_message, len_error_message);

	} else if(message_buffer[4] == '\n' || message_buffer[4] == '\0') {
		// Message can't be of length 0.
		static const char* error_message = "ERROR_2\n";
		int len_error_message = strlen(error_message) + 1;

		send_message_to_client(sockfd, connfd, error_message, len_error_message);

	} else if(!encrypt_message(&message_buffer[4]) || !send_ciphertext(sockfd, connfd)) {
		// Some server side error
		static const char* error_message = "ERROR_3\n";
		int len_error_message = strlen(error_message) + 1;

		send_message_to_client(sockfd, connfd, error_message, len_error_message);

		close(connfd);
		close(sockfd);
		exit(EXIT_SUCCESS);
	}
}

void handle_dec(int sockfd, int connfd) {
	if(message_buffer[3] != ' ') {
		#if DEBUG2
			printf("Debug2 :: handle_dec :: 1\n");
		#endif
		// Space must separate between "dec" and the ciphertext.
		static const char* error_message = "ERROR_1\n";
		int len_error_message = strlen(error_message) + 1;

		send_message_to_client(sockfd, connfd, error_message, len_error_message);

	} else {
		#if DEBUG2
			printf("Debug2 :: handle_dec :: 2\n");
		#endif
		char* ciphertext;
		long size_ciphertext = strtol(&message_buffer[4], &ciphertext, 10);
		ciphertext++; // Skipping the \0 between the size and ciphertext
		#if DEBUG
			// printf("Debug :: handle_dec :: ciphertext: %s\n", ciphertext);
		#endif
		if(size_ciphertext <= 0) {
			#if DEBUG2
				printf("Debug2 :: handle_dec :: 3\n");
			#endif
			// ciphertext size must be positive integer.
			static const char* error_message = "ERROR_2\n";
			int len_error_message = strlen(error_message) + 1;

			send_message_to_client(sockfd, connfd, error_message, len_error_message);
		} else if(decrypt_ciphertext(ciphertext, size_ciphertext)) {
			#if DEBUG2
				printf("Debug2 :: handle_dec :: 4\n");
			#endif
			static const char* done_message = "DONE\n";
			int len_done_message = strlen(done_message) + 1;

			#if DEBUG2
				printf("Debug2 :: handle_dec :: 6\n");
			#endif
			send_message_to_client(sockfd, connfd, done_message, len_done_message);
		} else {
			#if DEBUG2
				printf("Debug2 :: handle_dec :: 5\n");
			#endif
			// Some server side error
			static const char* error_message = "ERROR_3\n";
			int len_error_message = strlen(error_message) + 1;

			send_message_to_client(sockfd, connfd, error_message, len_error_message);

			close(connfd);
			close(sockfd);
			exit(EXIT_SUCCESS);
		}
	}
}

bool send_public_key_info(int sockfd, int connfd) {
	// <exponent number of bytes>\\0<exponent>\\0<modulus number of bytes>\\0<modulus>
	// Finding the ABSOLUTE path to the modulus and exponent files
	char resource_path[PATH_MAX] = { 0 };
	if(readlink("/proc/self/exe", resource_path, PATH_MAX) < 0) {
		fprintf(stderr, "Error: Couldn't readlink in send_public_key_info (%s)\n", strerror(errno));
		return false;
	}
	char* binary_pointer = strrchr(resource_path, (int) '/');
	*binary_pointer = '\0';
	binary_pointer = strrchr(resource_path, (int) '/');
	*binary_pointer = '\0';
	strcat(resource_path, "/resource");
	#if DEBUG
		printf("Debug :: send_public_key_info :: resource_path: %s\n", resource_path);
	#endif

	char modulus_path[PATH_MAX];
	sprintf(modulus_path, "%s/%s", resource_path, FILE_NAME_MODULUS);

	char exponent_path[PATH_MAX];
	sprintf(exponent_path, "%s/%s", resource_path, FILE_NAME_EXPONENT);

	#if DEBUG
		printf("Debug :: send_public_key_info :: modulus_path: %s\n", modulus_path);
		printf("Debug :: send_public_key_info :: exponent_path: %s\n", exponent_path);
	#endif

	// Getting info from modulus file
	int fd_mod = open(modulus_path, O_RDONLY);
	if(fd_mod < 0) {
		fprintf(stderr, "Error: couldn't open modulus_path in send_public_key_info (%s)", strerror(errno));
		return false;
	}
	struct stat file_stat_mod;
	if(fstat(fd_mod, &file_stat_mod) < 0) {
		fprintf(stderr, "Error: couldn't run fstat in send_public_key_info (%s)", strerror(errno));
		close(fd_mod);
		return false;
	}
	#if DEBUG
		printf("Debug :: send_public_key_info :: File Size: %ld bytes\n", file_stat_mod.st_size);
	#endif
	char buff_mod[file_stat_mod.st_size];
	bzero(buff_mod, file_stat_mod.st_size);
	if(read(fd_mod, buff_mod, file_stat_mod.st_size) < 0) {
		fprintf(stderr, "Error: couldn't read modulus_path in send_public_key_info (%s)", strerror(errno));
		close(fd_mod);
		return false;
	}
	#if DEBUG
		printf("Debug :: send_public_key_info :: buff_mod:\n%s\n", buff_mod);
	#endif
	close(fd_mod);

	// Getting info from modulus file
	int fd_exp = open(exponent_path, O_RDONLY);
	if(fd_exp < 0) {
		fprintf(stderr, "Error: couldn't open exponent_path in send_public_key_info (%s)", strerror(errno));
		return false;
	}
	struct stat file_stat_exp;
	if(fstat(fd_exp, &file_stat_exp) < 0) {
		fprintf(stderr, "Error: couldn't run fstat in send_public_key_info (%s)", strerror(errno));
		close(fd_exp);
		return false;
	}
	#if DEBUG
		printf("Debug :: send_public_key_info :: File Size: %ld bytes\n", file_stat_exp.st_size);
	#endif
	char buff_exp[file_stat_exp.st_size];
	bzero(buff_exp, file_stat_exp.st_size);
	if(read(fd_exp, buff_exp, file_stat_exp.st_size) < 0) {
		fprintf(stderr, "Error: couldn't read exponent_path in send_public_key_info (%s)", strerror(errno));
		close(fd_exp);
		return false;
	}
	#if DEBUG
		printf("Debug :: send_public_key_info :: buff_exp:\n%s\n", buff_exp);
	#endif
	close(fd_exp);


	// Cleaning buffer
	bzero(message_buffer, MAX_MESSAGE_SIZE);
	int offset = sprintf(message_buffer, "%ld", file_stat_exp.st_size) + 1;
	binary_pointer = &message_buffer[offset];
	#if DEBUG
		printf("Debug :: send_public_key_info :: file_stat_exp.st_size: %ld\n", file_stat_exp.st_size);
		printf("Debug :: send_public_key_info :: message_buffer:\n");
		print_buffer();
	#endif
	offset += sprintf(binary_pointer, "%.*s", (int) file_stat_exp.st_size, buff_exp) + 1;
	binary_pointer = &message_buffer[offset];
	#if DEBUG
		printf("Debug :: send_public_key_info :: message_buffer:\n");
		print_buffer();
	#endif
	offset += sprintf(binary_pointer, "%ld", file_stat_mod.st_size) + 1;
	binary_pointer = &message_buffer[offset];
	#if DEBUG
		printf("Debug :: send_public_key_info :: file_stat_mod.st_size: %ld\n", file_stat_mod.st_size);
		printf("Debug :: send_public_key_info :: message_buffer:\n");
		print_buffer();
	#endif
	sprintf(binary_pointer, "%.*s", (int) file_stat_mod.st_size, buff_mod);
	#if DEBUG
		printf("Debug :: send_public_key_info :: message_buffer:\n");
		print_buffer();
	#endif

	// send message back to client
	if(!send_all(connfd, message_buffer, MAX_MESSAGE_SIZE)) {
		fprintf(stderr, "Error: couldn't write in send_public_key_info (%s)", strerror(errno));
		close(connfd);
		close(sockfd);
		exit(EXIT_FAILURE);
	};

	return true;
}

void handle_pubinfo(int sockfd, int connfd) {
	if(!save_public_key_info() || !send_public_key_info(sockfd, connfd)) {
		static const char* error_message = "ERROR\n";
		int len_error_message = strlen(error_message) + 1;

		send_message_to_client(sockfd, connfd, error_message, len_error_message);
		
		close(connfd);
		close(sockfd);
		exit(EXIT_SUCCESS);
	}
}

void handle_client(int sockfd, int connfd) {
	while(true) { // infinite loop for chat until return
		// Cleaning buffer
		bzero(message_buffer, MAX_MESSAGE_SIZE);

		#if DEBUG2
			printf("Debug2 :: handle_client :: 1\n");
		#endif

		// read the message from client and copy it in buffer
		if(read(connfd, message_buffer, sizeof(message_buffer)) < 0) {
			fprintf(stderr, "Error: couldn't read in handle_client (%s)", strerror(errno));
			close(connfd);
			close(sockfd);
			exit(EXIT_FAILURE);
		}
		#if DEBUG2
			printf("Debug2 :: handle_client :: 2\n");
		#endif
		#if DEBUG
			printf("Debug :: handle_client :: Message from client: %s\n", message_buffer);
		#endif

		if(			  strncmp("help", message_buffer, 4) == 0) {
			handle_help(sockfd, connfd);

		} else if(strncmp("enc", message_buffer, 3) == 0) {
			handle_enc(sockfd, connfd);

		} else if(strncmp("dec", message_buffer, 3) == 0) {
			#if DEBUG2
				printf("Debug2 :: handle_client :: 3\n");
			#endif
			handle_dec(sockfd, connfd);

		} else if(strncmp("genkey", message_buffer, 6) == 0) {
			handle_genkey(sockfd, connfd);

		} else if(strncmp("pubinfo", message_buffer, 7) == 0) {
			handle_pubinfo(sockfd, connfd);

		} else if(strncmp("exit", message_buffer, 4) == 0) {
			static const char* goodbye_message = "GOODBYE\n";
			int len_goodbye_message = strlen(goodbye_message) + 1;

			send_message_to_client(sockfd, connfd, goodbye_message, len_goodbye_message);

			close(connfd);
			return;

		} else if(strncmp("shutdown", message_buffer, 8) == 0) {
			static const char* goodbye_message = "GOODBYE\n";
			int len_goodbye_message = strlen(goodbye_message) + 1;

			send_message_to_client(sockfd, connfd, goodbye_message, len_goodbye_message);

			close(connfd);
			close(sockfd);
			exit(EXIT_SUCCESS);

		} else {
			handle_help(sockfd, connfd);
		}
	}
}