#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif
#include <stdio.h>
#include <string.h>
#include <error.h>

const char *
com_right(struct error_table *list, long code)
{
    struct error_table *p;
    for(p = list; p; p = p->next){
	if(code >= p->base && code < p->base + p->n_msgs)
	    return p->msgs[code - p->base];
    }
    return NULL;
}

void
free_error_table(struct error_table *et)
{
    while(et){
	struct error_table *p = et;
	et = et->next;
	free(p);
    }
}
