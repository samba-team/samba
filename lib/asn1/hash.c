/*
 * Hash table functions
 */

#include "asn1_locl.h"

RCSID("$Id$");

static Hashentry *_search(Hashtab * htab,	/* The hash table */
			  void *ptr);	/* And key */

Hashtab *
hashtabnew(int sz,
	   int (*cmp) (void *, void *),
	   unsigned (*hash) (void *))
{
    Hashtab *htab;
    int i;

    assert(sz > 0);

    htab = (Hashtab *) malloc(sizeof(Hashtab) + (sz - 1) * sizeof(Hashentry *));
    for (i = 0; i < sz; ++i)
	htab->tab[i] = NULL;

    if (htab == NULL) {
	return NULL;
    } else {
	htab->cmp = cmp;
	htab->hash = hash;
	htab->sz = sz;
	return htab;
    }
}

/* Intern search function */

static Hashentry *
_search(Hashtab * htab, void *ptr)
{
    Hashentry *hptr;

    assert(htab && ptr);

    for (hptr = htab->tab[(*htab->hash) (ptr) % htab->sz];
	 hptr;
	 hptr = hptr->next)
	if ((*htab->cmp) (ptr, hptr->ptr) == 0)
	    break;
    return hptr;
}

/* Search for element in hash table */

void *
hashtabsearch(Hashtab * htab, void *ptr)
{
    Hashentry *tmp;

    tmp = _search(htab, ptr);
    return tmp ? tmp->ptr : tmp;
}

/* add element to hash table */
/* if already there, set new value */
/* !NULL if succesful */

void *
hashtabadd(Hashtab * htab, void *ptr)
{
    Hashentry *h = _search(htab, ptr);
    Hashentry **tabptr;

    assert(htab && ptr);

    if (h)
	free((void *) h->ptr);
    else {
	h = (Hashentry *) malloc(sizeof(Hashentry));
	if (h == NULL) {
	    return NULL;
	}
	tabptr = &htab->tab[(*htab->hash) (ptr) % htab->sz];
	h->next = *tabptr;
	*tabptr = h;
	h->prev = tabptr;
	if (h->next)
	    h->next->prev = &h->next;
    }
    h->ptr = ptr;
    return h;
}

/* delete element with key key. Iff freep, free Hashentry->ptr */

int
_hashtabdel(Hashtab * htab, void *ptr, int freep)
{
    Hashentry *h;

    assert(htab && ptr);

    h = _search(htab, ptr);
    if (h) {
	if (freep)
	    free(h->ptr);
	if ((*(h->prev) = h->next))
	    h->next->prev = h->prev;
	free(h);
	return 0;
    } else
	return -1;
}

/* Do something for each element */

void
hashtabforeach(Hashtab * htab, int (*func) (void *ptr, void *arg),
	       void *arg)
{
    Hashentry **h, *g;

    assert(htab);

    for (h = htab->tab; h < &htab->tab[htab->sz]; ++h)
	for (g = *h; g; g = g->next)
	    if ((*func) (g->ptr, arg))
		return;
}

/* standard hash-functions for strings */

unsigned
hashadd(const char *s)
{				/* Standard hash function */
    unsigned i;

    assert(s);

    for (i = 0; *s; ++s)
	i += *s;
    return i;
}

unsigned
hashcaseadd(const char *s)
{				/* Standard hash function */
    unsigned i;

    assert(s);

    for (i = 0; *s; ++s)
	i += toupper(*s);
    return i;
}

#define TWELVE (sizeof(unsigned))
#define SEVENTYFIVE (6*sizeof(unsigned))
#define HIGH_BITS (~((unsigned)(~0) >> TWELVE))

unsigned
hashjpw(const char *ss)
{				/* another hash function */
    unsigned h = 0;
    unsigned g;
    unsigned const char *s = ss;

    for (; *s; ++s) {
	h = (h << TWELVE) + *s;
	if ((g = h & HIGH_BITS))
	    h = (h ^ (g >> SEVENTYFIVE)) & ~HIGH_BITS;
    }
    return h;
}
