/*
   This structure is used by lib/interfaces.c to return the list of network
   interfaces on the machine
*/

#define MAX_INTERFACES 128

struct iface_struct {
	char name[16];
	int flags;
	struct sockaddr_storage ip;
	struct sockaddr_storage netmask;
	struct sockaddr_storage bcast;
};
