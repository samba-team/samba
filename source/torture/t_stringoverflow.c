#include "includes.h"

 int main(void)
{
	fstring dest;

	printf("running on valgrind? %d\n", RUNNING_ON_VALGRIND);

	/* Try copying a string into an fstring buffer.  The string
	 * will actually fit, but this is still wrong because you
	 * can't pstrcpy into an fstring.  This should trap in a
	 * developer build. */
	pstrcpy(dest, "hello");

	return 0;
}
