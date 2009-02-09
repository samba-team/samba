/*
 * Simple Named Pipe Client
 * (C) 2005 Jelmer Vernooij <jelmer@samba.org>
 * (C) 2009 Stefan Metzmacher <metze@samba.org>
 * Published to the public domain
 */

#include <windows.h>
#include <stdio.h>

#define ECHODATA "Black Dog"

int main(int argc, char *argv[])
{
	HANDLE h;
	DWORD numread = 0;
	char *outbuffer = malloc(sizeof(ECHODATA));

	if (argc == 1) {
		printf("Usage: %s pipename\n", argv[0]);
		printf("  Where pipename is something like \\\\servername\\NPECHO\n");
		return -1;
	}

	h = CreateNamedPipe(argv[1],
			    PIPE_ACCESS_DUPLEX,
			    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			    PIPE_UNLIMITED_INSTANCES,
			    1024,
			    1024,
			    0,
			    NULL);
	if (h == INVALID_HANDLE_VALUE) {
		printf("Error opening: %d\n", GetLastError());
		return -1;
	}

	ConnectNamedPipe(h, NULL);

	if (!WriteFile(h, ECHODATA, sizeof(ECHODATA), &numread, NULL)) {
		printf("Error writing: %d\n", GetLastError());
		return -1;
	}

	if (!WriteFile(h, ECHODATA, sizeof(ECHODATA), &numread, NULL)) {
		printf("Error writing: %d\n", GetLastError());
		return -1;
	}

	FlushFileBuffers(h);
	DisconnectNamedPipe(h);
	CloseHandle(h);

	return 0;
}
