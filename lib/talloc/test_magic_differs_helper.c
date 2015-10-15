#include <stdio.h>
#include "talloc.h"

/*
 * This program is called by a testing shell script in order to ensure that
 * if the library is loaded into different processes it uses different magic
 * values in order to thwart security attacks.
 */
int main(int argc, char *argv[]) {
	printf("%i\n", talloc_test_get_magic());
	return 0;
}
