#include <krb5_locl.h>

RCSID("$Id$");

const char *
krb5_get_err_text(krb5_context context, long code)
{
    struct error_list *p;
    for(p = context->et_list; p; p = p->next){
	if(code >= p->table->base && code < p->table->base + p->table->n_msgs)
	    return p->table->msgs[code - p->table->base];
    }
    return "Error message not found";
}

void
krb5_init_ets(krb5_context context)
{
    if(context->et_list == NULL){
	initialize_krb5_error_table(&context->et_list);
#if 0
	initialize_kv5m_error_table(&context->et_list);
	initialize_kdb5_error_table(&context->et_list);
	initialize_asn1_error_table(&context->et_list);
#endif
    }
}
