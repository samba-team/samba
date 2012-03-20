#include <ccan/list/list.h>
#include <ccan/tap/tap.h>
#include <ccan/list/list.c>
#include "helper.h"

struct parent {
	const char *name;
	struct ccan_list_head children;
	unsigned int num_children;
};

struct child {
	const char *name;
	struct ccan_list_node list;
};

static CCAN_LIST_HEAD(static_list);

int main(int argc, char *argv[])
{
	struct parent parent;
	struct child c1, c2, c3, *c, *n;
	unsigned int i;
	struct ccan_list_head list = CCAN_LIST_HEAD_INIT(list);
	opaque_t *q, *nq;
	struct ccan_list_head opaque_list = CCAN_LIST_HEAD_INIT(opaque_list);

	plan_tests(65);
	/* Test CCAN_LIST_HEAD, CCAN_LIST_HEAD_INIT, ccan_list_empty and check_list */
	ok1(ccan_list_empty(&static_list));
	ok1(ccan_list_check(&static_list, NULL));
	ok1(ccan_list_empty(&list));
	ok1(ccan_list_check(&list, NULL));

	parent.num_children = 0;
	ccan_list_head_init(&parent.children);
	/* Test ccan_list_head_init */
	ok1(ccan_list_empty(&parent.children));
	ok1(ccan_list_check(&parent.children, NULL));

	c2.name = "c2";
	ccan_list_add(&parent.children, &c2.list);
	/* Test ccan_list_add and !ccan_list_empty. */
	ok1(!ccan_list_empty(&parent.children));
	ok1(c2.list.next == &parent.children.n);
	ok1(c2.list.prev == &parent.children.n);
	ok1(parent.children.n.next == &c2.list);
	ok1(parent.children.n.prev == &c2.list);
	/* Test ccan_list_check */
	ok1(ccan_list_check(&parent.children, NULL));

	c1.name = "c1";
	ccan_list_add(&parent.children, &c1.list);
	/* Test ccan_list_add and !ccan_list_empty. */
	ok1(!ccan_list_empty(&parent.children));
	ok1(c2.list.next == &parent.children.n);
	ok1(c2.list.prev == &c1.list);
	ok1(parent.children.n.next == &c1.list);
	ok1(parent.children.n.prev == &c2.list);
	ok1(c1.list.next == &c2.list);
	ok1(c1.list.prev == &parent.children.n);
	/* Test ccan_list_check */
	ok1(ccan_list_check(&parent.children, NULL));

	c3.name = "c3";
	ccan_list_add_tail(&parent.children, &c3.list);
	/* Test ccan_list_add_tail and !ccan_list_empty. */
	ok1(!ccan_list_empty(&parent.children));
	ok1(parent.children.n.next == &c1.list);
	ok1(parent.children.n.prev == &c3.list);
	ok1(c1.list.next == &c2.list);
	ok1(c1.list.prev == &parent.children.n);
	ok1(c2.list.next == &c3.list);
	ok1(c2.list.prev == &c1.list);
	ok1(c3.list.next == &parent.children.n);
	ok1(c3.list.prev == &c2.list);
	/* Test ccan_list_check */
	ok1(ccan_list_check(&parent.children, NULL));

	/* Test ccan_list_check_node */
	ok1(ccan_list_check_node(&c1.list, NULL));
	ok1(ccan_list_check_node(&c2.list, NULL));
	ok1(ccan_list_check_node(&c3.list, NULL));

	/* Test ccan_list_top */
	ok1(ccan_list_top(&parent.children, struct child, list) == &c1);

	/* Test ccan_list_tail */
	ok1(ccan_list_tail(&parent.children, struct child, list) == &c3);

	/* Test ccan_list_for_each. */
	i = 0;
	ccan_list_for_each(&parent.children, c, list) {
		switch (i++) {
		case 0:
			ok1(c == &c1);
			break;
		case 1:
			ok1(c == &c2);
			break;
		case 2:
			ok1(c == &c3);
			break;
		}
		if (i > 2)
			break;
	}
	ok1(i == 3);

	/* Test ccan_list_for_each_rev. */
	i = 0;
	ccan_list_for_each_rev(&parent.children, c, list) {
		switch (i++) {
		case 0:
			ok1(c == &c3);
			break;
		case 1:
			ok1(c == &c2);
			break;
		case 2:
			ok1(c == &c1);
			break;
		}
		if (i > 2)
			break;
	}
	ok1(i == 3);

	/* Test ccan_list_for_each_safe, ccan_list_del and ccan_list_del_from. */
	i = 0;
	ccan_list_for_each_safe(&parent.children, c, n, list) {
		switch (i++) {
		case 0:
			ok1(c == &c1);
			ccan_list_del(&c->list);
			break;
		case 1:
			ok1(c == &c2);
			ccan_list_del_from(&parent.children, &c->list);
			break;
		case 2:
			ok1(c == &c3);
			ccan_list_del_from(&parent.children, &c->list);
			break;
		}
		ok1(ccan_list_check(&parent.children, NULL));
		if (i > 2)
			break;
	}
	ok1(i == 3);
	ok1(ccan_list_empty(&parent.children));

	/* Test ccan_list_for_each_off. */
	ccan_list_add_tail(&opaque_list,
		      (struct ccan_list_node *)create_opaque_blob());
	ccan_list_add_tail(&opaque_list,
		      (struct ccan_list_node *)create_opaque_blob());
	ccan_list_add_tail(&opaque_list,
		      (struct ccan_list_node *)create_opaque_blob());

	i = 0;

	ccan_list_for_each_off(&opaque_list, q, 0) {
	  i++;
	  ok1(if_blobs_know_the_secret(q));
	}
	ok1(i == 3);

	/* Test ccan_list_for_each_safe_off, ccan_list_del_off and ccan_list_del_from_off. */
	i = 0;
	ccan_list_for_each_safe_off(&opaque_list, q, nq, 0) {
		switch (i++) {
		case 0:
			ok1(if_blobs_know_the_secret(q));
			ccan_list_del_off(q, 0);
			destroy_opaque_blob(q);
			break;
		case 1:
			ok1(if_blobs_know_the_secret(q));
			ccan_list_del_from_off(&opaque_list, q, 0);
			destroy_opaque_blob(q);
			break;
		case 2:
			ok1(c == &c3);
			ccan_list_del_from_off(&opaque_list, q, 0);
			destroy_opaque_blob(q);
			break;
		}
		ok1(ccan_list_check(&opaque_list, NULL));
		if (i > 2)
			break;
	}
	ok1(i == 3);
	ok1(ccan_list_empty(&opaque_list));

	/* Test ccan_list_top/ccan_list_tail on empty list. */
	ok1(ccan_list_top(&parent.children, struct child, list) == NULL);
	ok1(ccan_list_tail(&parent.children, struct child, list) == NULL);
	return exit_status();
}
