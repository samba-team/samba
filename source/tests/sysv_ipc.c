/* this tests whether we can use a sysv shared memory segment
   as needed for the sysv varient of FAST_SHARE_MODES */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define KEY 0x963796
#define SIZE (32*1024)

main()
{
	int id;
	int *buf;
	int count=7;

#ifdef LINUX
	if (sizeof(struct shmid_ds) == 52) {
		printf("WARNING: You probably have a broken set of glibc2 include files - disabling sysv shared memory\n");
		exit(1);
	}
#endif

	id = shmget(KEY, 0, 0);
	if (id != -1) {
		if (shmctl(id, IPC_RMID, 0) != 0) exit(1);
	}

	if (fork() == 0) {
		/* uggh - need locking */
		sleep(2);

		/* get an existing area */
		id = shmget(KEY, 0, 0);
		if (id == -1) exit(1);

		buf = (int *)shmat(id, 0, 0);
		if (buf == (int *)-1) exit(1);


		while (count-- && buf[6124] != 55732) sleep(1);

		if (count <= 0) exit(1);

		buf[1763] = 7268;
		exit(0);
	}
	
	id = shmget(KEY, SIZE, IPC_CREAT | IPC_EXCL | 0600);
	if (id == -1) exit(1);

	buf = (int *)shmat(id, 0, 0);

	if (buf == (int *)-1) exit(1);

	buf[6124] = 55732;

	while (count-- && buf[1763] != 7268) sleep(1);

	shmctl(id, IPC_RMID, 0);

	if (count <= 0) exit(1);
	exit(0);
}
