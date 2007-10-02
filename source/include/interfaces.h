/* 
   This structure is used by lib/interfaces.c to return the list of network
   interfaces on the machine
*/

#define MAX_INTERFACES 128

struct iface_struct {
	char name[16];
	sa_family_t sa_family;
	union {
		struct in_addr ip;
#ifdef AF_INET6
		struct in6_addr ip6;
#endif
	} iface_addr;
	union {
		struct in_addr netmask;
#ifdef AF_INET6
		struct in6_addr netmask6;
#endif
	} iface_netmask;
};
