#define CCAN_LIST_DEBUG 1
#include <ccan/list/list.h>
#include <ccan/tap/tap.h>
#include <ccan/list/list.c>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

int main(int argc, char *argv[])
{
	struct ccan_list_head list1, list2;
	struct ccan_list_node n1, n2, n3;
	pid_t child;
	int status;

	plan_tests(1);
	ccan_list_head_init(&list1);
	ccan_list_head_init(&list2);
	ccan_list_add(&list1, &n1);
	ccan_list_add(&list2, &n2);
	ccan_list_add_tail(&list2, &n3);

	child = fork();
	if (child) {
		wait(&status);
	} else {
		/* This should abort. */
		ccan_list_del_from(&list1, &n3);
		exit(0);
	}

	ok1(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
	ccan_list_del_from(&list2, &n3);
	return exit_status();
}
