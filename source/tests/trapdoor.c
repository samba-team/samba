/* test for a trapdoor uid system */

#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>

main()
{
        if (getuid() != 0) {
                fprintf(stderr,"ERROR: This test must be run as root - assuming \
non-trapdoor system\n");
                exit(0);
        }

#if defined(HAVE_SETRESUID)
        if (setresuid(1,1,-1) != 0) exit(1);
        if (getuid() != 1) exit(1);
        if (geteuid() != 1) exit(1);
        if (setresuid(0,0,0) != 0) exit(1);
        if (getuid() != 0) exit(1);
        if (geteuid() != 0) exit(1);
#elif defined(HAVE_SETREUID)
	/* Set real uid to 1. */
	if (setreuid(1,-1) != 0) exit(1); 
	if (getuid() != 1) exit(1); 
	/* Go back to root. */
	if (setreuid(0,-1) != 0) exit(1);
	if (getuid() != 0) exit(1);
	/* Now set euid to 1. */
	if (setreuid(-1,1) != 0) exit(1);
	if (geteuid() != 1) exit(1);
	/* Go back to root. */
	if (setreuid(0,0) != 0) exit(1);
	if (getuid() != 0) exit(1);
	if (geteuid() != 0) exit(1);
#else
        if (seteuid(1) != 0) exit(1);
        if (geteuid() != 1) exit(1);
        if (seteuid(0) != 0) exit(1);
        if (geteuid() != 0) exit(1);
#endif

#if defined(HAVE_SETRESGID)
        if (setresgid(1,1,1) != 0) exit(1);
        if (getgid() != 1) exit(1);
        if (getegid() != 1) exit(1);
        if (setresgid(0,0,0) != 0) exit(1);
        if (getgid() != 0) exit(1);
        if (getegid() != 0) exit(1);
#elif defined(HAVE_SETREGID)
	if (setregid(1,1) != 0) exit(1);
	if (getgid() != 1) exit(1);
	if (getegid() != 1) exit(1);
	if (setregid(0,0) != 0) exit(1);
	if (getgid() != 0) exit(1);
	if (getegid() != 0) exit(1);
#else
        if (setegid(1) != 0) exit(1);
        if (getegid() != 1) exit(1);
        if (setegid(0) != 0) exit(1);
        if (getegid() != 0) exit(1);
#endif

        exit(0);
}
