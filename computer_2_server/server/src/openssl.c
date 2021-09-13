#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "exit_codes.h"
#include "parameters.h"

/**
 * Optimization:
 * We can make the path finding more global, so we don't have to find out the
 * paths to files each time.
 */

void remove_all_files_in_folder(char* folder_path) {
	// Credit: https://stackoverflow.com/questions/11007494/how-to-delete-all-files-in-a-folder-but-not-delete-the-folder-using-nix-standar
	DIR *folder = opendir(folder_path);
	struct dirent *next_file;
	char filepath[PATH_MAX];

	while ( (next_file = readdir(folder)) != NULL ) {
		sprintf(filepath, "%s/%s", folder_path, next_file->d_name);
		remove(filepath);
	}
	closedir(folder);
}

bool run_openssl_command(char* openssl_path, char* argv[], int argc, bool to_ignore_cmd_fail) {
	#if DEBUG
		printf("Debug :: run_openssl_command :: Command:\n\t");
		for(int index = 0; index < argc; ++index) {
			printf("%s ", argv[index]);
		}
		printf("\n");
	#endif

	pid_t pid = fork();

	if(pid < 0) {
		fprintf(stderr, "Error: Couldn't fork in run_openssl_command\n");
		return false;

	} else if(pid == 0) { // child
		execv(openssl_path, argv);
		exit(EXIT_CANT_RUN_OPENSSL);

	} else { // parent
		int exit_code;
		waitpid(pid, &exit_code, 0);

		#if DEBUG
			printf("Debug :: run_openssl_command :: exit_code: %d\n", exit_code);
			printf("Debug :: run_openssl_command :: to_ignore_cmd_fail: %s\n", to_ignore_cmd_fail ? "true" : "false");
		#endif

		if(exit_code == EXIT_CANT_RUN_OPENSSL) {
			fprintf(stderr, "Error: Couldn't run openssl in run_openssl_command\n");
			return false;
		} else if(to_ignore_cmd_fail) {
			return true;
		} else if(exit_code == EXIT_SUCCESS) {
			return true;
		} else {
			fprintf(stderr, "Error: Unknown error(%d) at run_openssl_command\n", exit_code);
			return false;
		}
	}
}

bool generate_new_key_pair() {
	// Finding the ABSOLUTE path to the resource folder
	char resource_path[PATH_MAX] = { 0 };
	if(readlink("/proc/self/exe", resource_path, PATH_MAX) < 0) {
		fprintf(stderr, "Error: Couldn't readlink in generate_new_key_pair (%s)\n", strerror(errno));
		return false;
	}
	char* binary_pointer = strrchr(resource_path, (int) '/');
	*binary_pointer = '\0';
	binary_pointer = strrchr(resource_path, (int) '/');
	*binary_pointer = '\0';
	strcat(resource_path, "/resource");
	#if DEBUG
		printf("Debug :: generate_new_key_pair :: resource_path: %s\n", resource_path);
	#endif

	printf("Server: Cleaning resource folder\n");
	remove_all_files_in_folder(resource_path);

	static char* openssl_path = PATH_TO_OPENSSL;

	char private_key_path[PATH_MAX];
	sprintf(private_key_path, "%s/%s", resource_path, FILE_NAME_PRIVATE_KEY);

	char private_key_without_password_path[PATH_MAX];
	sprintf(private_key_without_password_path, "%s/%s", resource_path, FILE_NAME_PRIVATE_KEY_WITHOUT_PASSWORD);

	char public_key_path[PATH_MAX];
	sprintf(public_key_path, "%s/%s", resource_path, FILE_NAME_PUBLIC_KEY);

	#if DEBUG
		printf("Debug :: generate_new_key_pair :: private_key_path: %s\n", private_key_path);
		printf("Debug :: generate_new_key_pair :: private_key_without_password_path: %s\n", private_key_without_password_path);
		printf("Debug :: generate_new_key_pair :: public_key_path: %s\n", public_key_path);
	#endif

	char* argv_command_1[] = {
		openssl_path, "genpkey",
		"-out", private_key_path,
		"-outform", "PEM",
		"-aes-256-cbc",
		"-algorithm", "RSA",
		"-pkeyopt", "rsa_keygen_bits:" RSA_MOD_BIT_SIZE,
		"-pass", "pass:qwerty",
		NULL
	};

	printf("Server: Creating private key\n");
	// openssl genpkey -out FILE_NAME_PRIVATE_KEY -outform PEM -aes-256-cbc -algorithm RSA -pkeyopt rsa_keygen_bits:RSA_MOD_BIT_SIZE -pass pass:qwerty
	if(!run_openssl_command(openssl_path, argv_command_1, 13, false))
		return false;

	char* argv_command_2[] = {
		openssl_path, "rsa",
		"-outform", "PEM",
		"-in", private_key_path,
		"-passin", "pass:qwerty",
		"-out", private_key_without_password_path,
		NULL
	};

	printf("Server: Creating private key without password\n");
	// openssl rsa -outform PEM -in FILE_NAME_PRIVATE_KEY -passin pass:qwerty -out FILE_NAME_PRIVATE_KEY_WITHOUT_PASSWORD
	if(!run_openssl_command(openssl_path, argv_command_2, 10, false))
		return false;

	char* argv_command_3[] = {
		openssl_path, "rsa",
		"-inform", "PEM",
		"-outform", "PEM",
		"-in", private_key_without_password_path,
		"-out", public_key_path,
		"-pubout",
		NULL
	};

	printf("Server: Creating public key\n");
	// openssl rsa -inform PEM -outform PEM -in FILE_NAME_PRIVATE_KEY_WITHOUT_PASSWORD -out FILE_NAME_PUBLIC_KEY -pubout
	if(!run_openssl_command(openssl_path, argv_command_3, 11, false))
		return false;

	return true;
}

bool encrypt_message(char* msg) {
	// Finding the ABSOLUTE path to the messages/resource folders
	char messages_path[PATH_MAX] = { 0 };
	char resource_path[PATH_MAX] = { 0 };
	if(readlink("/proc/self/exe", messages_path, PATH_MAX) < 0) {
		fprintf(stderr, "Error: Couldn't readlink in encrypt_message (%s)\n", strerror(errno));
		return false;
	}
	char* binary_pointer = strrchr(messages_path, (int) '/');
	*binary_pointer = '\0';
	binary_pointer = strrchr(messages_path, (int) '/');
	*binary_pointer = '\0';
	sprintf(resource_path, "%s/resource", messages_path);
	strcat(messages_path, "/messages");
	#if DEBUG
		printf("Debug :: encrypt_message :: messages_path: %s\n", messages_path);
		printf("Debug :: encrypt_message :: resource_path: %s\n", resource_path);
	#endif

	printf("Server: Cleaning messages folder\n");
	remove_all_files_in_folder(messages_path);

	static char* openssl_path = PATH_TO_OPENSSL;

	char msg_path[PATH_MAX];
	sprintf(msg_path, "%s/%s", messages_path, FILE_NAME_MESSAGE);

	char ciphertext_path[PATH_MAX];
	sprintf(ciphertext_path, "%s/%s", messages_path, FILE_NAME_CIPHERTEXT);

	char public_key_path[PATH_MAX];
	sprintf(public_key_path, "%s/%s", resource_path, FILE_NAME_PUBLIC_KEY);

	#if DEBUG
		printf("Debug :: encrypt_message :: msg_path: %s\n", msg_path);
		printf("Debug :: encrypt_message :: ciphertext_path: %s\n", ciphertext_path);
		printf("Debug :: encrypt_message :: public_key_path: %s\n", public_key_path);
	#endif

	printf("Server: Creating and write the msg into a file\n");
	FILE* fp = fopen(msg_path, "w");
	if(fp == NULL) {
		fprintf(stderr, "Error: couldn't open msg_path in encrypt_message (%s)", strerror(errno));
		return false;
	}
	if(fputs(msg, fp) == EOF) {
		fprintf(stderr, "Error: couldn't write to msg_path in encrypt_message");
		fclose(fp);
		return false;
	}
	fclose(fp);

	char* argv_command[] = {
		openssl_path, "rsautl",
		"-in", msg_path,
		"-out", ciphertext_path,
		"-inkey", public_key_path,
		"-pubin",
		"-encrypt",
		NULL
	};

	printf("Server: Encrypting the message\n");
	// openssl rsautl -in FILE_NAME_MESSAGE -out FILE_NAME_CIPHERTEXT -inkey FILE_NAME_PUBLIC_KEY -pubin -encrypt
	// os rsault -in messages/msg.txt
	if(!run_openssl_command(openssl_path, argv_command, 10, false))
		return false;

	return true;
}

bool decrypt_ciphertext(char* cip, size_t size_cip) {
	#if DEBUG2
		printf("Debug2 :: decrypt_ciphertext :: 1\n");
	#endif
	// Finding the ABSOLUTE path to the messages/resource folders
	char messages_path[PATH_MAX] = { 0 };
	char resource_path[PATH_MAX] = { 0 };
	if(readlink("/proc/self/exe", messages_path, PATH_MAX) < 0) {
		fprintf(stderr, "Error: Couldn't readlink in decrypt_ciphertext (%s)\n", strerror(errno));
		return false;
	}
	char* binary_pointer = strrchr(messages_path, (int) '/');
	*binary_pointer = '\0';
	binary_pointer = strrchr(messages_path, (int) '/');
	*binary_pointer = '\0';
	sprintf(resource_path, "%s/resource", messages_path);
	strcat(messages_path, "/messages");
	#if DEBUG
		printf("Debug :: decrypt_ciphertext :: messages_path: %s\n", messages_path);
		printf("Debug :: decrypt_ciphertext :: resource_path: %s\n", resource_path);
	#endif

	#if DEBUG2
		printf("Debug2 :: decrypt_ciphertext :: 2\n");
	#endif

	printf("Server: Cleaning messages folder\n");
	remove_all_files_in_folder(messages_path);

	#if DEBUG2
		printf("Debug2 :: decrypt_ciphertext :: 3\n");
	#endif

	static char* openssl_path = PATH_TO_OPENSSL;

	char msg_path[PATH_MAX];
	sprintf(msg_path, "%s/%s", messages_path, FILE_NAME_MESSAGE);

	char ciphertext_path[PATH_MAX];
	sprintf(ciphertext_path, "%s/%s", messages_path, FILE_NAME_CIPHERTEXT);

	char private_key_without_password_path[PATH_MAX];
	sprintf(private_key_without_password_path, "%s/%s", resource_path, FILE_NAME_PRIVATE_KEY_WITHOUT_PASSWORD);

	#if DEBUG
		printf("Debug :: decrypt_ciphertext :: msg_path: %s\n", msg_path);
		printf("Debug :: decrypt_ciphertext :: ciphertext_path: %s\n", ciphertext_path);
		printf("Debug :: decrypt_ciphertext :: private_key_without_password_path: %s\n", private_key_without_password_path);
	#endif

	#if DEBUG2
		printf("Debug2 :: decrypt_ciphertext :: 4\n");
	#endif

	printf("Server: Creating and write the cip into a file\n");
	int fd = open(ciphertext_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if(fd < 0) {
		fprintf(stderr, "Error: couldn't open ciphertext_path in decrypt_ciphertext (%s)", strerror(errno));
		return false;
	}
	#if DEBUG2
		printf("Debug2 :: decrypt_ciphertext :: 5\n");
	#endif
	if(write(fd, cip, size_cip) < 0) {
		fprintf(stderr, "Error: couldn't write to ciphertext_path in decrypt_ciphertext (%s)", strerror(errno));
		close(fd);
		return false;
	}
	#if DEBUG2
		printf("Debug2 :: decrypt_ciphertext :: 6\n");
	#endif
	close(fd);

	char* argv_command[] = {
		openssl_path, "rsautl",
		"-in", ciphertext_path,
		"-out", msg_path,
		"-inkey", private_key_without_password_path,
		"-decrypt",
		NULL
	};

	printf("Server: Decrypting the ciphertext\n");
	// openssl rsautl -in FILE_NAME_CIPHERTEXT -out FILE_NAME_MESSAGE -inkey FILE_NAME_PRIVATE_KEY_WITHOUT_PASSWORD -decrypt
	run_openssl_command(openssl_path, argv_command, 9, true);
	// Doesn't check return value, because it doesn't matter, we aren't informing the attacker.

	#if DEBUG2
		printf("Debug2 :: decrypt_ciphertext :: 7\n");
	#endif

	return true;
}

bool save_public_key_info() {
	// Finding the ABSOLUTE path to the resource folder
	char resource_path[PATH_MAX] = { 0 };
	if(readlink("/proc/self/exe", resource_path, PATH_MAX) < 0) {
		fprintf(stderr, "Error: Couldn't readlink in save_public_key_info (%s)\n", strerror(errno));
		return false;
	}
	char* binary_pointer = strrchr(resource_path, (int) '/');
	*binary_pointer = '\0';
	binary_pointer = strrchr(resource_path, (int) '/');
	*binary_pointer = '\0';
	strcat(resource_path, "/resource");
	#if DEBUG
		printf("Debug :: save_public_key_info :: resource_path: %s\n", resource_path);
	#endif

	static char* openssl_path = PATH_TO_OPENSSL;

	char public_key_path[PATH_MAX];
	sprintf(public_key_path, "%s/%s", resource_path, FILE_NAME_PUBLIC_KEY);

	char modulus_path[PATH_MAX];
	sprintf(modulus_path, "%s/%s", resource_path, FILE_NAME_MODULUS);

	char exponent_path[PATH_MAX];
	sprintf(exponent_path, "%s/%s", resource_path, FILE_NAME_EXPONENT);

	#if DEBUG
		printf("Debug :: save_public_key_info :: public_key_path: %s\n", public_key_path);
		printf("Debug :: save_public_key_info :: modulus_path: %s\n", modulus_path);
		printf("Debug :: save_public_key_info :: exponent_path: %s\n", exponent_path);
	#endif

	char* argv_command_1[] = {
		openssl_path, "rsa",
		"-inform", "PEM",
		"-in", public_key_path,
		"-noout",
		"-modulus",
		"-pubin",
		"-out", modulus_path,
		NULL
	};

	printf("Server: Getting modulus info\n");
	// openssl rsa -inform PEM -in FILE_NAME_PUBLIC_KEY -noout -modulus -pubin -out FILE_NAME_MODULUS
	if(!run_openssl_command(openssl_path, argv_command_1, 11, false))
		return false;

	char* argv_command_2[] = {
		openssl_path, "rsa",
		"-inform", "PEM",
		"-in", public_key_path,
		"-text",
		"-noout",
		"-pubin",
		"-out", exponent_path,
		NULL
	};

	printf("Server: Getting exponent info\n");
  // openssl rsa -inform PEM -in FILE_NAME_PUBLIC_KEY -text -noout -pubin -out FILE_NAME_EXPONENT
	if(!run_openssl_command(openssl_path, argv_command_2, 11, false))
		return false;
	
	// Parsing the modulus file and rewrite it to only have the modulus in it
	int fd = open(modulus_path, O_RDWR);
	if(fd < 0) {
		fprintf(stderr, "Error: couldn't open modulus_path in save_public_key_info (%s)", strerror(errno));
		return false;
	}
	struct stat file_stat;
	if(fstat(fd, &file_stat) < 0) {
		fprintf(stderr, "Error: couldn't run fstat in save_public_key_info (%s)", strerror(errno));
		close(fd);
		return false;
	}
	#if DEBUG
		printf("Debug :: save_public_key_info :: File Size: %ld bytes\n", file_stat.st_size);
	#endif
	int read_size = file_stat.st_size - 8 - 1; // "Modulus=" is 8 bytes, the last byte is '\n', no need for those parts.

	if(lseek(fd, 8, SEEK_SET) < 0) { // Skipping "Modulus="
		fprintf(stderr, "Error: couldn't run lseek in save_public_key_info (%s)", strerror(errno));
		close(fd);
		return false;
	}
	
	char buff_mod[file_stat.st_size];
	bzero(buff_mod, file_stat.st_size);
	if(read(fd, buff_mod, read_size) < 0) {
		fprintf(stderr, "Error: couldn't read modulus_path in save_public_key_info (%s)", strerror(errno));
		close(fd);
		return false;
	}
	#if DEBUG
		printf("Debug :: save_public_key_info :: buff_mod:\n%.*s\n", read_size, buff_mod);
	#endif

	printf("Server: Rewriting modulus info\n");
	if(lseek(fd, 0, SEEK_SET) < 0) { // Returning to the begining of the file before writing
		fprintf(stderr, "Error: couldn't run lseek in save_public_key_info (%s)", strerror(errno));
		close(fd);
		return false;
	}

	if(write(fd, buff_mod, file_stat.st_size) < 0) { // Writing the whole file size instead of read size only, to overwrite the end
		fprintf(stderr, "Error: couldn't write to modulus_path in save_public_key_info (%s)", strerror(errno));
		close(fd);
		return false;
	}

	if(ftruncate(fd, (off_t) read_size) < 0) {
		fprintf(stderr, "Error: couldn't ftruncate to modulus_path in save_public_key_info (%s)", strerror(errno));
		close(fd);
		return false;
	}
	close(fd);


	// Parsing the exponent file and rewrite it to only have the exponent in it
	fd = open(exponent_path, O_RDWR);
	if(fd < 0) {
		fprintf(stderr, "Error: couldn't open exponent_path in save_public_key_info (%s)", strerror(errno));
		return false;
	}
	if(fstat(fd, &file_stat) < 0) {
		fprintf(stderr, "Error: couldn't run fstat in save_public_key_info (%s)", strerror(errno));
		close(fd);
		return false;
	}
	#if DEBUG
		printf("Debug :: save_public_key_info :: File Size: %ld bytes\n", file_stat.st_size);
	#endif
	
	char buff_exp[file_stat.st_size];
	if(read(fd, buff_exp, file_stat.st_size) < 0) {
		fprintf(stderr, "Error: couldn't read exponent_path in save_public_key_info (%s)", strerror(errno));
		close(fd);
		return false;
	}
	#if DEBUG
		printf("Debug :: save_public_key_info :: buff_exp:\n%s\n", buff_exp);
	#endif

	char* buff_pointer_begin = strstr(buff_exp, "Exponent: ");
	if(buff_pointer_begin == NULL) {
		fprintf(stderr, "Error: couldn't find \"Exponent: \" in exponent_path in save_public_key_info");
		close(fd);
		return false;
	}
	buff_pointer_begin += 10; // +10 to skip "Exponent: " and +1 to get to the beginning of the exponent.
	#if DEBUG
		printf("Debug :: save_public_key_info :: buff_pointer_begin:\n%s\n", buff_pointer_begin);
	#endif

	char* buff_pointer_end = strchr(buff_pointer_begin, ' ');
	#if DEBUG
		printf("Debug :: save_public_key_info :: buff_pointer_end:\n%s\n", buff_pointer_end);
	#endif

	int exp_size = buff_pointer_end - buff_pointer_begin;
	#if DEBUG
		printf("Debug :: save_public_key_info :: exp_size: %d\n", exp_size);
	#endif
	
	char* buff_pointer = strncpy(buff_exp, buff_pointer_begin, exp_size);
	#if DEBUG
		printf("Debug :: save_public_key_info :: buff_exp:\n%s\n", buff_exp);
	#endif
	buff_pointer += exp_size;
	bzero(buff_pointer, file_stat.st_size - exp_size);
	#if DEBUG
		printf("Debug :: save_public_key_info :: buff_exp:\n%s\n", buff_exp);
	#endif

	printf("Server: Rewriting exponent info\n");
	if(lseek(fd, 0, SEEK_SET) < 0) { // Returning to the begining of the file before writing
		fprintf(stderr, "Error: couldn't run lseek in save_public_key_info (%s)", strerror(errno));
		close(fd);
		return false;
	}

	if(write(fd, buff_exp, file_stat.st_size) < 0) { // Writing the whole file size instead of read size only, to overwrite the end
		fprintf(stderr, "Error: couldn't write to exponent_path in save_public_key_info (%s)", strerror(errno));
		close(fd);
		return false;
	}

	if(ftruncate(fd, (off_t) exp_size) < 0) {
		fprintf(stderr, "Error: couldn't ftruncate to exponent_path in save_public_key_info (%s)", strerror(errno));
		close(fd);
		return false;
	}
	close(fd);

	return true;
}