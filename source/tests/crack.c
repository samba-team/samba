#include <crack.h>

#ifndef HAVE_CRACKLIB_DICTPATH
#ifndef CRACKLIB_DICTPATH
#define CRACKLIB_DICTPATH SAMBA_CRACKLIB_DICTPATH
#endif
#endif

int main(int argc, char **argv) {
	FascistCheck("Foo", CRACKLIB_DICTPATH);
	return 0;
}
