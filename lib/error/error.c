#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif
#include <stdio.h>
#include <string.h>
#include <krb5.h>


const char *
krb5_get_err_text(krb5_context context, long code)
{
    struct error_table *p;
    for(p = context->et_list; p; p = p->next){
	if(code >= p->base && code < p->base + p->n_msgs)
	    return p->msgs[code - p->base];
    }
    return strerror(code);
}

void
krb5_init_ets(krb5_context context)
{
    if(context->et_list == NULL){
	initialize_krb5_error_table(&context->et_list);
#if 0
	initialize_kv5m_error_table(&context->et_list);
	initialize_kdb5_error_table(&context->et_list);
#endif
	initialize_asn1_error_table(&context->et_list);
    }
}
