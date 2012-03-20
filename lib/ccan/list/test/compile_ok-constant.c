#include <ccan/list/list.h>
#include <ccan/tap/tap.h>
#include <ccan/list/list.c>
#include <stdbool.h>
#include <stdio.h>

struct child {
	const char *name;
	struct ccan_list_node list;
};

static bool children(const struct ccan_list_head *list)
{
	return !ccan_list_empty(list);
}

static const struct child *first_child(const struct ccan_list_head *list)
{
	return ccan_list_top(list, struct child, list);
}

static const struct child *last_child(const struct ccan_list_head *list)
{
	return ccan_list_tail(list, struct child, list);
}

static void check_children(const struct ccan_list_head *list)
{
	ccan_list_check(list, "bad child list");
}

static void print_children(const struct ccan_list_head *list)
{
	const struct child *c;
	ccan_list_for_each(list, c, list)
		printf("%s\n", c->name);
}

int main(void)
{
	CCAN_LIST_HEAD(h);

	children(&h);
	first_child(&h);
	last_child(&h);
	check_children(&h);
	print_children(&h);
	return 0;
}
