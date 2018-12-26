/* test whether readlink returns a short buffer incorrectly.
   We need to return 0 in case readlink is *broken* here - this is because our waf
   CHECK_CODE function does only allow generating defines in case the test succeeds
*/

#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DATA "readlink.test"
#define FNAME "rdlnk.file"

int main(void)
{
	char buf[7];
	int ret;
	ssize_t rl_ret;

	unlink(FNAME);
	ret = symlink(DATA, FNAME);
	if (ret == -1) {
		exit(0);
	}

	rl_ret = readlink(FNAME, buf, sizeof(buf));
	if (rl_ret == -1) {
		unlink(FNAME);
		exit(0);
	}
	unlink(FNAME);
	exit(1);
}
