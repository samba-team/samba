/* Licensed under LGPLv2.1+ - see LICENSE file for details */
#ifndef CCAN_LIST_H
#define CCAN_LIST_H
#include <stdbool.h>
#include <assert.h>
#include <ccan/container_of/container_of.h>
#include <ccan/check_type/check_type.h>

/**
 * struct ccan_list_node - an entry in a doubly-linked list
 * @next: next entry (self if empty)
 * @prev: previous entry (self if empty)
 *
 * This is used as an entry in a linked list.
 * Example:
 *	struct child {
 *		const char *name;
 *		// Linked list of all us children.
 *		struct ccan_list_node list;
 *	};
 */
struct ccan_list_node
{
	struct ccan_list_node *next, *prev;
};

/**
 * struct ccan_list_head - the head of a doubly-linked list
 * @h: the ccan_list_head (containing next and prev pointers)
 *
 * This is used as the head of a linked list.
 * Example:
 *	struct parent {
 *		const char *name;
 *		struct ccan_list_head children;
 *		unsigned int num_children;
 *	};
 */
struct ccan_list_head
{
	struct ccan_list_node n;
};

/**
 * ccan_list_check - check head of a list for consistency
 * @h: the ccan_list_head
 * @abortstr: the location to print on aborting, or NULL.
 *
 * Because list_nodes have redundant information, consistency checking between
 * the back and forward links can be done.  This is useful as a debugging check.
 * If @abortstr is non-NULL, that will be printed in a diagnostic if the list
 * is inconsistent, and the function will abort.
 *
 * Returns the list head if the list is consistent, NULL if not (it
 * can never return NULL if @abortstr is set).
 *
 * See also: ccan_list_check_node()
 *
 * Example:
 *	static void dump_parent(struct parent *p)
 *	{
 *		struct child *c;
 *
 *		printf("%s (%u children):\n", p->name, p->num_children);
 *		ccan_list_check(&p->children, "bad child list");
 *		ccan_list_for_each(&p->children, c, list)
 *			printf(" -> %s\n", c->name);
 *	}
 */
struct ccan_list_head *ccan_list_check(const struct ccan_list_head *h, const char *abortstr);

/**
 * ccan_list_check_node - check node of a list for consistency
 * @n: the ccan_list_node
 * @abortstr: the location to print on aborting, or NULL.
 *
 * Check consistency of the list node is in (it must be in one).
 *
 * See also: ccan_list_check()
 *
 * Example:
 *	static void dump_child(const struct child *c)
 *	{
 *		ccan_list_check_node(&c->list, "bad child list");
 *		printf("%s\n", c->name);
 *	}
 */
struct ccan_list_node *ccan_list_check_node(const struct ccan_list_node *n,
				  const char *abortstr);

#ifdef CCAN_LIST_DEBUG
#define ccan_list_debug(h) ccan_list_check((h), __func__)
#define ccan_list_debug_node(n) ccan_list_check_node((n), __func__)
#else
#define ccan_list_debug(h) (h)
#define ccan_list_debug_node(n) (n)
#endif

/**
 * CCAN_LIST_HEAD_INIT - initializer for an empty ccan_list_head
 * @name: the name of the list.
 *
 * Explicit initializer for an empty list.
 *
 * See also:
 *	CCAN_LIST_HEAD, ccan_list_head_init()
 *
 * Example:
 *	static struct ccan_list_head my_list = CCAN_LIST_HEAD_INIT(my_list);
 */
#define CCAN_LIST_HEAD_INIT(name) { { &name.n, &name.n } }

/**
 * CCAN_LIST_HEAD - define and initialize an empty ccan_list_head
 * @name: the name of the list.
 *
 * The CCAN_LIST_HEAD macro defines a ccan_list_head and initializes it to an empty
 * list.  It can be prepended by "static" to define a static ccan_list_head.
 *
 * See also:
 *	CCAN_LIST_HEAD_INIT, ccan_list_head_init()
 *
 * Example:
 *	static CCAN_LIST_HEAD(my_global_list);
 */
#define CCAN_LIST_HEAD(name) \
	struct ccan_list_head name = CCAN_LIST_HEAD_INIT(name)

/**
 * ccan_list_head_init - initialize a ccan_list_head
 * @h: the ccan_list_head to set to the empty list
 *
 * Example:
 *	...
 *	struct parent *parent = malloc(sizeof(*parent));
 *
 *	ccan_list_head_init(&parent->children);
 *	parent->num_children = 0;
 */
static inline void ccan_list_head_init(struct ccan_list_head *h)
{
	h->n.next = h->n.prev = &h->n;
}

/**
 * ccan_list_add - add an entry at the start of a linked list.
 * @h: the ccan_list_head to add the node to
 * @n: the ccan_list_node to add to the list.
 *
 * The ccan_list_node does not need to be initialized; it will be overwritten.
 * Example:
 *	struct child *child = malloc(sizeof(*child));
 *
 *	child->name = "marvin";
 *	ccan_list_add(&parent->children, &child->list);
 *	parent->num_children++;
 */
static inline void ccan_list_add(struct ccan_list_head *h, struct ccan_list_node *n)
{
	n->next = h->n.next;
	n->prev = &h->n;
	h->n.next->prev = n;
	h->n.next = n;
	(void)ccan_list_debug(h);
}

/**
 * ccan_list_add_tail - add an entry at the end of a linked list.
 * @h: the ccan_list_head to add the node to
 * @n: the ccan_list_node to add to the list.
 *
 * The ccan_list_node does not need to be initialized; it will be overwritten.
 * Example:
 *	ccan_list_add_tail(&parent->children, &child->list);
 *	parent->num_children++;
 */
static inline void ccan_list_add_tail(struct ccan_list_head *h, struct ccan_list_node *n)
{
	n->next = &h->n;
	n->prev = h->n.prev;
	h->n.prev->next = n;
	h->n.prev = n;
	(void)ccan_list_debug(h);
}

/**
 * ccan_list_empty - is a list empty?
 * @h: the ccan_list_head
 *
 * If the list is empty, returns true.
 *
 * Example:
 *	assert(ccan_list_empty(&parent->children) == (parent->num_children == 0));
 */
static inline bool ccan_list_empty(const struct ccan_list_head *h)
{
	(void)ccan_list_debug(h);
	return h->n.next == &h->n;
}

/**
 * ccan_list_del - delete an entry from an (unknown) linked list.
 * @n: the ccan_list_node to delete from the list.
 *
 * Note that this leaves @n in an undefined state; it can be added to
 * another list, but not deleted again.
 *
 * See also:
 *	ccan_list_del_from()
 *
 * Example:
 *	ccan_list_del(&child->list);
 *	parent->num_children--;
 */
static inline void ccan_list_del(struct ccan_list_node *n)
{
	(void)ccan_list_debug_node(n);
	n->next->prev = n->prev;
	n->prev->next = n->next;
#ifdef CCAN_LIST_DEBUG
	/* Catch use-after-del. */
	n->next = n->prev = NULL;
#endif
}

/**
 * ccan_list_del_from - delete an entry from a known linked list.
 * @h: the ccan_list_head the node is in.
 * @n: the ccan_list_node to delete from the list.
 *
 * This explicitly indicates which list a node is expected to be in,
 * which is better documentation and can catch more bugs.
 *
 * See also: ccan_list_del()
 *
 * Example:
 *	ccan_list_del_from(&parent->children, &child->list);
 *	parent->num_children--;
 */
static inline void ccan_list_del_from(struct ccan_list_head *h, struct ccan_list_node *n)
{
#ifdef CCAN_LIST_DEBUG
	{
		/* Thorough check: make sure it was in list! */
		struct ccan_list_node *i;
		for (i = h->n.next; i != n; i = i->next)
			assert(i != &h->n);
	}
#endif /* CCAN_LIST_DEBUG */

	/* Quick test that catches a surprising number of bugs. */
	assert(!ccan_list_empty(h));
	ccan_list_del(n);
}

/**
 * ccan_list_entry - convert a ccan_list_node back into the structure containing it.
 * @n: the ccan_list_node
 * @type: the type of the entry
 * @member: the ccan_list_node member of the type
 *
 * Example:
 *	// First list entry is children.next; convert back to child.
 *	child = ccan_list_entry(parent->children.n.next, struct child, list);
 *
 * See Also:
 *	ccan_list_top(), ccan_list_for_each()
 */
#define ccan_list_entry(n, type, member) container_of(n, type, member)

/**
 * ccan_list_top - get the first entry in a list
 * @h: the ccan_list_head
 * @type: the type of the entry
 * @member: the ccan_list_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *	struct child *first;
 *	first = ccan_list_top(&parent->children, struct child, list);
 */
#define ccan_list_top(h, type, member)					\
	((type *)ccan_list_top_((h), ccan_list_off_(type, member)))

static inline const void *ccan_list_top_(const struct ccan_list_head *h, size_t off)
{
	if (ccan_list_empty(h))
		return NULL;
	return (const char *)h->n.next - off;
}

/**
 * ccan_list_tail - get the last entry in a list
 * @h: the ccan_list_head
 * @type: the type of the entry
 * @member: the ccan_list_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *	struct child *last;
 *	last = ccan_list_tail(&parent->children, struct child, list);
 */
#define ccan_list_tail(h, type, member) \
	((type *)ccan_list_tail_((h), ccan_list_off_(type, member)))

static inline const void *ccan_list_tail_(const struct ccan_list_head *h, size_t off)
{
	if (ccan_list_empty(h))
		return NULL;
	return (const char *)h->n.prev - off;
}

/**
 * ccan_list_for_each - iterate through a list.
 * @h: the ccan_list_head (warning: evaluated multiple times!)
 * @i: the structure containing the ccan_list_node
 * @member: the ccan_list_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.
 *
 * Example:
 *	ccan_list_for_each(&parent->children, child, list)
 *		printf("Name: %s\n", child->name);
 */
#define ccan_list_for_each(h, i, member)					\
	ccan_list_for_each_off(h, i, ccan_list_off_var_(i, member))

/**
 * ccan_list_for_each_rev - iterate through a list backwards.
 * @h: the ccan_list_head
 * @i: the structure containing the ccan_list_node
 * @member: the ccan_list_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.
 *
 * Example:
 *	ccan_list_for_each_rev(&parent->children, child, list)
 *		printf("Name: %s\n", child->name);
 */
#define ccan_list_for_each_rev(h, i, member)					\
	for (i = container_of_var(ccan_list_debug(h)->n.prev, i, member);	\
	     &i->member != &(h)->n;					\
	     i = container_of_var(i->member.prev, i, member))

/**
 * ccan_list_for_each_safe - iterate through a list, maybe during deletion
 * @h: the ccan_list_head
 * @i: the structure containing the ccan_list_node
 * @nxt: the structure containing the ccan_list_node
 * @member: the ccan_list_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.  The extra variable
 * @nxt is used to hold the next element, so you can delete @i from the list.
 *
 * Example:
 *	struct child *next;
 *	ccan_list_for_each_safe(&parent->children, child, next, list) {
 *		ccan_list_del(&child->list);
 *		parent->num_children--;
 *	}
 */
#define ccan_list_for_each_safe(h, i, nxt, member)				\
	ccan_list_for_each_safe_off(h, i, nxt, ccan_list_off_var_(i, member))

/**
 * ccan_list_for_each_off - iterate through a list of memory regions.
 * @h: the ccan_list_head
 * @i: the pointer to a memory region wich contains list node data.
 * @off: offset(relative to @i) at which list node data resides.
 *
 * This is a low-level wrapper to iterate @i over the entire list, used to
 * implement all oher, more high-level, for-each constructs. It's a for loop,
 * so you can break and continue as normal.
 *
 * WARNING! Being the low-level macro that it is, this wrapper doesn't know
 * nor care about the type of @i. The only assumtion made is that @i points
 * to a chunk of memory that at some @offset, relative to @i, contains a
 * properly filled `struct node_list' which in turn contains pointers to
 * memory chunks and it's turtles all the way down. Whith all that in mind
 * remember that given the wrong pointer/offset couple this macro will
 * happilly churn all you memory untill SEGFAULT stops it, in other words
 * caveat emptor.
 *
 * It is worth mentioning that one of legitimate use-cases for that wrapper
 * is operation on opaque types with known offset for `struct ccan_list_node'
 * member(preferably 0), because it allows you not to disclose the type of
 * @i.
 *
 * Example:
 *	ccan_list_for_each_off(&parent->children, child,
 *				offsetof(struct child, list))
 *		printf("Name: %s\n", child->name);
 */
#define ccan_list_for_each_off(h, i, off)                                    \
  for (i = ccan_list_node_to_off_(ccan_list_debug(h)->n.next, (off));             \
       ccan_list_node_from_off_((void *)i, (off)) != &(h)->n;                \
       i = ccan_list_node_to_off_(ccan_list_node_from_off_((void *)i, (off))->next, \
                             (off)))

/**
 * ccan_list_for_each_safe_off - iterate through a list of memory regions, maybe
 * during deletion
 * @h: the ccan_list_head
 * @i: the pointer to a memory region wich contains list node data.
 * @nxt: the structure containing the ccan_list_node
 * @off: offset(relative to @i) at which list node data resides.
 *
 * For details see `ccan_list_for_each_off' and `ccan_list_for_each_safe'
 * descriptions.
 *
 * Example:
 *	ccan_list_for_each_safe_off(&parent->children, child,
 *		next, offsetof(struct child, list))
 *		printf("Name: %s\n", child->name);
 */
#define ccan_list_for_each_safe_off(h, i, nxt, off)                          \
  for (i = ccan_list_node_to_off_(ccan_list_debug(h)->n.next, (off)),             \
         nxt = ccan_list_node_to_off_(ccan_list_node_from_off_(i, (off))->next,   \
                                 (off));                                \
       ccan_list_node_from_off_(i, (off)) != &(h)->n;                        \
       i = nxt,                                                         \
         nxt = ccan_list_node_to_off_(ccan_list_node_from_off_(i, (off))->next,   \
                                 (off)))


/* Other -off variants. */
#define ccan_list_entry_off(n, type, off)		\
	((type *)ccan_list_node_from_off_((n), (off)))

#define ccan_list_head_off(h, type, off)		\
	((type *)ccan_list_head_off((h), (off)))

#define ccan_list_tail_off(h, type, off)		\
	((type *)ccan_list_tail_((h), (off)))

#define ccan_list_add_off(h, n, off)                 \
	ccan_list_add((h), ccan_list_node_from_off_((n), (off)))

#define ccan_list_del_off(n, off)                    \
	ccan_list_del(ccan_list_node_from_off_((n), (off)))

#define ccan_list_del_from_off(h, n, off)			\
	ccan_list_del_from(h, ccan_list_node_from_off_((n), (off)))

/* Offset helper functions so we only single-evaluate. */
static inline void *ccan_list_node_to_off_(struct ccan_list_node *node, size_t off)
{
	return (void *)((char *)node - off);
}
static inline struct ccan_list_node *ccan_list_node_from_off_(void *ptr, size_t off)
{
	return (struct ccan_list_node *)((char *)ptr + off);
}

/* Get the offset of the member, but make sure it's a ccan_list_node. */
#define ccan_list_off_(type, member)					\
	(container_off(type, member) +				\
	 check_type(((type *)0)->member, struct ccan_list_node))

#define ccan_list_off_var_(var, member)			\
	(container_off_var(var, member) +		\
	 check_type(var->member, struct ccan_list_node))

#endif /* CCAN_LIST_H */
