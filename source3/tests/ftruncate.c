/* test whether ftruncte() can extend a file */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DATA "conftest.trunc"
#define LEN 7663

main()
{
	int *buf;
	int fd = open(DATA,O_RDWR|O_CREAT|O_TRUNC,0666);

	ftruncate(fd, LEN);

	unlink(DATA);

	if (lseek(fd, 0, SEEK_END) == LEN) {
		exit(0);
	}
	exit(1);
}
