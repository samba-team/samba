#include <memory.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <crack.h>

void usage(char *command) {
	char *c, *comm;

	comm = command;
	while ((c = strrchr(comm, '/')) != NULL) {
		comm = c + 1;
	}

	fprintf(stderr, "Usage: %s -d dictionary\n\n", comm);
	fprintf(stderr, "     -d dictionary file for cracklib\n\n");
	fprintf(stderr, "	The password is expected to be given via stdin.\n\n");
	exit(-1);
}

int main(int argc, char **argv) {
	extern char *optarg;
	int c;

	char f[256];
	char *dictionary = NULL;
	char *password;
	char *reply;

	while ( (c = getopt(argc, argv, "d:")) != EOF){
		switch(c) {
		case 'd':
			dictionary = strdup(optarg);
			break;
		default:
			usage(argv[0]);
		}
	}

	if (dictionary == NULL) {
		fprintf(stderr, "ERR - Wrong Command Line\n\n");
		usage(argv[0]);
	} 

	password = fgets(f, sizeof(f), stdin);

	if (password == NULL) {
		fprintf(stderr, "ERR - Failed to read password\n\n");
		exit(-2);
	}

	reply = FascistCheck(password, dictionary);
	if (reply != NULL) {
		fprintf(stderr, "ERR - %s\n\n", reply);
		exit(-3);
	}

	exit(0);

}

