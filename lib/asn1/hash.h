/*
 * hash.h. Header file for hash table functions
 */

/* $Id$ */

struct hashentry {		/* Entry in bucket */
     struct hashentry **prev;
     struct hashentry *next;
     void *ptr;
};

typedef struct hashentry Hashentry;

struct hashtab {		/* Hash table */
     int (*cmp)(void *, void *); /* Compare function */
     unsigned (*hash)(void *);	/* hash function */
     int sz;			/* Size */
     Hashentry *tab[1];		/* The table */
};

typedef struct hashtab Hashtab;

/* prototypes */

Hashtab *hashtabnew(int sz, 
		    int (*cmp)(void *, void *),
		    unsigned (*hash)(void *));	/* Make new hash table */

void *hashtabsearch(Hashtab *htab, /* The hash table */
		    void *ptr);	/*  The key */


void *hashtabadd(Hashtab *htab,	/* The hash table */
	       void *ptr);	/* The element */

int _hashtabdel(Hashtab *htab,	/* The table */
		void *ptr,	/* Key */
		int freep);	/* Free data part? */

void hashtabforeach(Hashtab *htab,
		    int (*func)(void *ptr, void *arg),
		    void *arg);

unsigned hashadd(const char *s);		/* Standard hash function */
unsigned hashcaseadd(const char *s);		/* Standard hash function */
unsigned hashjpw(const char *s);		/* another hash function */

/* macros */

 /* Don't free space */
#define hashtabdel(htab,key)  _hashtabdel(htab,key,FALSE)

#define hashtabfree(htab,key) _hashtabdel(htab,key,TRUE) /* Do! */
