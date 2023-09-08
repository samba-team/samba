#include "replace.h"
#include "system/wait.h"
#include "system/threads.h"
#include <assert.h>

int main(int argc, const char *argv[])
{
	pid_t pid;
	int wstatus;
	pthread_key_t k1;
	pthread_key_t k2;
	pthread_key_t k3;
	char *val = NULL;
	const char *nss_winbind = (argc >= 2 ? argv[1] : "bin/plugins/libnss_winbind.so.2");
	void *nss_winbind_handle = NULL;
	union {
		int (*fn)(void);
		void *symbol;
	} nss_winbind_endpwent = { .symbol = NULL, };

	/*
	 * load and invoke something simple like
	 * _nss_winbind_endpwent in order to
	 * get the libnss_winbind internal going
	 */
	nss_winbind_handle = dlopen(nss_winbind, RTLD_NOW);
	printf("%d: nss_winbind[%s] nss_winbind_handle[%p]\n",
	       getpid(), nss_winbind, nss_winbind_handle);
	assert(nss_winbind_handle != NULL);

	nss_winbind_endpwent.symbol = dlsym(nss_winbind_handle,
					    "_nss_winbind_endpwent");
	printf("%d: nss_winbind_handle[%p] _nss_winbind_endpwent[%p]\n",
	       getpid(), nss_winbind_handle, nss_winbind_endpwent.symbol);
	assert(nss_winbind_endpwent.symbol != NULL);
	(void)nss_winbind_endpwent.fn();

	val = malloc(1);
	assert(val != NULL);

	pthread_key_create(&k1, NULL);
	pthread_setspecific(k1, val);
	printf("%d: k1=%d\n", getpid(), k1);

	pid = fork();
	if (pid) {
		free(val);
		wait(&wstatus);
		return WEXITSTATUS(wstatus);
	}

	pthread_key_create(&k2, NULL);
	pthread_setspecific(k2, val);

	printf("%d: Hello after fork, k1=%d, k2=%d\n", getpid(), k1, k2);

	pid = fork();

	if (pid) {
		free(val);
		wait(&wstatus);
		return WEXITSTATUS(wstatus);
	}

	pthread_key_create(&k3, NULL);
	pthread_setspecific(k3, val);

	printf("%d: Hello after fork2, k1=%d, k2=%d, k3=%d\n", getpid(), k1, k2, k3);

	if (k1 == k2 || k2 == k3) {
		printf("%d: FAIL inconsistent keys\n", getpid());
		return 1;
	}

	printf("%d: OK consistent keys\n", getpid());
	return 0;
}
