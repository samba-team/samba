/*
 * Copyright (c) 2004 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "krb5_locl.h"
#include <krb5_ccapi.h>
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

RCSID("$Id$");


/* XXX should we fetch these for each open ? */

static void *cc_handle;
static cc_initialize_func init_func;

typedef struct krb5_acc {
    char *name;
    cc_context_t context;
    cc_ccache_t ccache;
} krb5_acc;

#define ACACHE(X) ((krb5_acc *)(X)->data.data)

const char *default_acc_name = "Initial default cache";

static const struct {
    cc_int32 error;
    krb5_error_code ret;
} cc_errors[] = {
    { ccErrBadName,		KRB5_CC_BADNAME },
    { ccErrCredentialsNotFound,	KRB5_CC_NOTFOUND },
    { ccErrCCacheNotFound,	KRB5_FCC_NOFILE },
    { ccErrContextNotFound,	KRB5_CC_NOTFOUND },
    { ccIteratorEnd,		KRB5_CC_END },
    { ccErrNoMem,		KRB5_CC_NOMEM },
    { ccNoError,		0 }
};

static krb5_error_code
translate_cc_error(krb5_context context, cc_int32 error)
{
    int i;
    krb5_clear_error_string(context);
    for(i = 0; i < sizeof(cc_errors)/sizeof(cc_errors[0]); i++)
	if (cc_errors[i].error == error)
	    return cc_errors[i].ret;
    return KRB5_FCC_INTERNAL;
}

static krb5_error_code
init_ccapi(krb5_context context)
{
    const char *lib;

    if (init_func) {
	krb5_clear_error_string(context);
	return 0;
    }

    lib = krb5_config_get_string(context, NULL,
				 "libdefaults", "ccapi_library", 
				 NULL);
    if (lib == NULL) {
#ifdef __APPLE__
	lib = "/System/Library/Frameworks/Kerberos.framework/Kerberos";
#else
	lib = "/usr/lib/libkrb5_cc.so";
#endif
    }

#ifdef HAVE_DLOPEN
    cc_handle = dlopen(lib, 0);
    if (cc_handle == NULL) {
	krb5_set_error_string(context, "Failed to load %s", lib);
	return ENOENT;
    }

    init_func = dlsym(cc_handle, "cc_initialize");
    if (init_func == NULL) {
	krb5_set_error_string(context, "Failed to find cc_initialize"
			      "in %s: %s", lib, dlerror());
	dlclose(cc_handle);
	return ENOENT;
    }
#else
    krb5_set_error_string(context, "no support for shared object");
    return ENOENT;
#endif

    return 0;
}    

static krb5_error_code
make_cred_from_ccred(krb5_context context,
		     const cc_credentials_v5_t *incred,
		     krb5_creds *cred)
{
    krb5_error_code ret;
    int i;

    memset(cred, 0, sizeof(*cred));

    ret = krb5_parse_name(context, incred->client, &cred->client);
    if (ret)
	goto fail;

    ret = krb5_parse_name(context, incred->server, &cred->server);
    if (ret)
	goto fail;

    cred->session.keytype = incred->keyblock.type;
    cred->session.keyvalue.length = incred->keyblock.length;
    cred->session.keyvalue.data = malloc(incred->keyblock.length);
    if (cred->session.keyvalue.data == NULL)
	goto nomem;
    memcpy(cred->session.keyvalue.data, incred->keyblock.data,
	   incred->keyblock.length);

    cred->times.authtime = incred->authtime;
    cred->times.starttime = incred->starttime;
    cred->times.endtime = incred->endtime;
    cred->times.renew_till = incred->renew_till;

    ret = krb5_data_copy(&cred->ticket,
			 incred->ticket.data,
			 incred->ticket.length);
    if (ret)
	goto nomem;

    ret = krb5_data_copy(&cred->second_ticket,
			 incred->second_ticket.data,
			 incred->second_ticket.length);
    if (ret)
	goto nomem;

    cred->authdata.val = NULL;
    cred->authdata.len = 0;
    
    cred->addresses.val = NULL;
    cred->addresses.len = 0;
    
    for (i = 0; incred->authdata && incred->authdata[i]; i++)
	;
    
    if (i) {
	cred->authdata.val = malloc(sizeof(cred->authdata.val[0]) * i);
	if (cred->authdata.val == NULL)
	    goto nomem;
	cred->authdata.len = i;
	memset(cred->authdata.val, 0, sizeof(cred->authdata.val[0]) * i);
	for (i = 0; i < cred->authdata.len; i++) {
	    cred->authdata.val[i].ad_type = incred->authdata[i]->type;
	    ret = krb5_data_copy(&cred->authdata.val[i].ad_data,
				 incred->authdata[i]->data,
				 incred->authdata[i]->length);
	    if (ret)
		goto nomem;
	}
    }
    
    for (i = 0; incred->addresses && incred->addresses[i]; i++)
	;
    
    if (i) {
	cred->addresses.val = malloc(sizeof(cred->addresses.val[0]) * i);
	if (cred->addresses.val == NULL)
	    goto nomem;
	cred->addresses.len = i;
	memset(cred->addresses.val, 0, sizeof(cred->addresses.val[0]) * i);
	
	for (i = 0; i < cred->addresses.len; i++) {
	    ret = krb5_h_addr2addr(context,
				   incred->addresses[i]->type,
				   incred->addresses[i]->data,
				   &cred->addresses.val[i]);
	    if (ret)
		goto fail;
	}
    }
    
    cred->flags.b = int2TicketFlags(incred->ticket_flags); /* XXX */
    return 0;
    
nomem:
    ret = ENOMEM;
    krb5_set_error_string(context, "malloc - out of memory");
    
fail:
    krb5_free_creds_contents(context, cred);
    return ret;
}

static krb5_error_code
make_ccred_from_cred(krb5_context context,
		     const krb5_creds *incred,
		     cc_credentials_v5_t *cred)
{
    krb5_error_code ret;

    memset(cred, 0, sizeof(*cred));

    ret = krb5_unparse_name(context, incred->client, &cred->client);
    if (ret)
	goto fail;

    ret = krb5_unparse_name(context, incred->server, &cred->server);
    if (ret) {
	free(cred->client);
	goto fail;
    }

    cred->keyblock.type = incred->session.keytype;
    cred->keyblock.length = incred->session.keyvalue.length;
    cred->keyblock.data = incred->session.keyvalue.data;

    cred->authtime = incred->times.authtime;
    cred->starttime = incred->times.starttime;
    cred->endtime = incred->times.endtime;
    cred->renew_till = incred->times.renew_till;

    cred->ticket.length = incred->ticket.length;
    cred->ticket.data = incred->ticket.data;

    cred->second_ticket.length = incred->second_ticket.length;
    cred->second_ticket.data = incred->second_ticket.data;

    /* XXX these too should also be filled in */
    cred->authdata = NULL;
    cred->addresses = NULL;
    
    cred->ticket_flags = TicketFlags2int(incred->flags.b); /* XXX */
    return 0;

fail:    
    krb5_clear_error_string(context);
    return ret;
}

static const char*
acc_get_name(krb5_context context,
	     krb5_ccache id)
{
    krb5_acc *a = ACACHE(id);
    static char n[255];
    int32_t error;
    cc_string_t name;

    if (a->ccache == NULL)
	return default_acc_name;

    error = (*a->ccache->func->get_name)(a->ccache, &name);
    if (error)
	return "unknown name";

    strlcpy(n, name->data, sizeof(n));
    (*name->func->release)(name);
    return n;
}

static cc_int32
acc_alloc(krb5_context context, krb5_ccache *id)
{
    krb5_acc *a;
    cc_int32 error;

    error = init_ccapi(context);
    if (error)
	return error;

    error = krb5_data_alloc(&(*id)->data, sizeof(*a));
    if (error)
	return error;
    
    a = ACACHE(*id);

    error = (*init_func)(&a->context, ccapi_version_3, NULL, NULL);
    if (error) {
	krb5_data_free(&(*id)->data);
	return error;
    }

    a->name = NULL;

    return 0;
}

static krb5_error_code
acc_resolve(krb5_context context, krb5_ccache *id, const char *res)
{
    krb5_acc *a;
    cc_int32 error;

    error = acc_alloc(context, id);
    if (error)
	return translate_cc_error(context, error);

    a = ACACHE(*id);

    if (res == NULL || res[0] == '\0') {    
	error = (*a->context->func->open_default_ccache)(a->context,
							 &a->ccache);
    } else {
	error = (*a->context->func->open_ccache)(a->context, res, &a->ccache);
	if (error == 0)
	    a->name = strdup(res);
    }
    if (error != 0)
	a->ccache = NULL;

    return 0;
}

static krb5_error_code
acc_gen_new(krb5_context context, krb5_ccache *id)
{
    krb5_acc *a;
    cc_int32 error;

    error = acc_alloc(context, id);
    if (error)
	return translate_cc_error(context, error);

    a = ACACHE(*id);

    if (a->name)
	error = (*a->context->func->create_new_ccache)(a->context,
						       cc_credentials_v5,
						       a->name, &a->ccache);
    else{
	error = (*a->context->func->create_default_ccache)(a->context,
							   cc_credentials_v5,
							   default_acc_name,
							   &a->ccache);
	a->name = strdup(default_acc_name);
    }
    return translate_cc_error(context, error);
}

static krb5_error_code
acc_initialize(krb5_context context,
	       krb5_ccache id,
	       krb5_principal primary_principal)
{
    cc_credentials_iterator_t iter;
    krb5_acc *a = ACACHE(id);
    cc_credentials_t ccred;
    krb5_error_code ret;
    int32_t error;
    char *name;

    if (a->ccache == NULL) {

	if (a->name)
	    error = (*a->context->func->create_new_ccache)(a->context,
		cc_credentials_v5,
		a->name,
		&a->ccache);
	else{
	    error = (*a->context->func->create_default_ccache)(a->context,
		cc_credentials_v5,
		default_acc_name,
		&a->ccache);
	    a->name = strdup(default_acc_name);
	}
	if (error)
	    return translate_cc_error(context, error);

    } else {    

	error = (*a->ccache->func->new_credentials_iterator)(a->ccache, &iter);
	if (error)
	    return translate_cc_error(context, error);

	while (1) {
	    error = (*iter->func->next)(iter, &ccred);
	    if (error)
		break;
	    (*a->ccache->func->remove_credentials)(a->ccache, ccred);
	    (*ccred->func->release)(ccred);
	}
	(*iter->func->release)(iter);
    }

    ret = krb5_unparse_name(context, primary_principal, &name);
    if (ret)
	return ret;

    error = (*a->ccache->func->set_principal)(a->ccache,
					      cc_credentials_v5,
					      name);
    free(name);

    return translate_cc_error(context, error);
}

static krb5_error_code
acc_close(krb5_context context,
	  krb5_ccache id)
{
    krb5_acc *a = ACACHE(id);

    if (a->ccache)
	(*a->ccache->func->release)(a->ccache);
    (*a->context->func->release)(a->context);
	
    krb5_data_free(&id->data);
    return 0;
}

static krb5_error_code
acc_destroy(krb5_context context,
	    krb5_ccache id)
{
    krb5_acc *a = ACACHE(id);
    cc_int32 error = 0;

    if (a->ccache) {
	error = (*a->ccache->func->destroy)(a->ccache);
	a->ccache = NULL;
    }
    return translate_cc_error(context, error);
}

static krb5_error_code
acc_store_cred(krb5_context context,
	       krb5_ccache id,
	       krb5_creds *creds)
{
    krb5_acc *a = ACACHE(id);
    cc_credentials_union cred;
    cc_credentials_v5_t v5cred;
    krb5_error_code ret;
    cc_int32 error;
    
    cred.version = cc_credentials_v5;
    cred.credentials.credentials_v5 = &v5cred;

    ret = make_ccred_from_cred(context, 
			       creds,
			       &v5cred);
    if (ret)
	return ret;

    error = (*a->ccache->func->store_credentials)(a->ccache, &cred);

    free(v5cred.server);
    free(v5cred.client);

    return ret;
}

static krb5_error_code
acc_get_principal(krb5_context context,
		  krb5_ccache id,
		  krb5_principal *principal)
{
    krb5_acc *a = ACACHE(id);
    krb5_error_code ret;
    int32_t error;
    cc_string_t name;

    if (a->ccache == NULL)
	return ENOENT;

    error = (*a->ccache->func->get_principal)(a->ccache,
					      cc_credentials_v5,
					      &name);
    if (error)
	return translate_cc_error(context, error);
    
    ret = krb5_parse_name(context, name->data, principal);
    
    (*name->func->release)(name);
    return ret;
}

static krb5_error_code
acc_get_first (krb5_context context,
	       krb5_ccache id,
	       krb5_cc_cursor *cursor)
{
    cc_credentials_iterator_t iter;
    krb5_acc *a = ACACHE(id);
    int32_t error;
    
    error = (*a->ccache->func->new_credentials_iterator)(a->ccache, &iter);
    if (error)
	return ENOENT;
    *cursor = iter;
    return 0;
}


static krb5_error_code
acc_get_next (krb5_context context,
	      krb5_ccache id,
	      krb5_cc_cursor *cursor,
	      krb5_creds *creds)
{
    cc_credentials_iterator_t iter = *cursor;
    cc_credentials_t cred;
    krb5_error_code ret;
    int32_t error;

    while (1) {
	error = (*iter->func->next)(iter, &cred);
	if (error)
	    return translate_cc_error(context, error);
	if (cred->data->version == cc_credentials_v5)
	    break;
	(*cred->func->release)(cred);
    }

    ret = make_cred_from_ccred(context, 
			       cred->data->credentials.credentials_v5,
			       creds);
    (*cred->func->release)(cred);
    return ret;
}

static krb5_error_code
acc_end_get (krb5_context context,
	     krb5_ccache id,
	     krb5_cc_cursor *cursor)
{
    cc_credentials_iterator_t iter = *cursor;
    (*iter->func->release)(iter);
    return 0;
}

static krb5_error_code
acc_remove_cred(krb5_context context,
		krb5_ccache id,
		krb5_flags which,
		krb5_creds *cred)
{
    cc_credentials_iterator_t iter;
    krb5_acc *a = ACACHE(id);
    cc_credentials_t ccred;
    krb5_error_code ret;
    cc_int32 error;
    char *client, *server;
    
    if (cred->client) {
	ret = krb5_unparse_name(context, cred->client, &client);
	if (ret)
	    return ret;
    } else
	client = NULL;

    ret = krb5_unparse_name(context, cred->server, &server);
    if (ret) {
	free(client);
	return ret;
    }

    error = (*a->ccache->func->new_credentials_iterator)(a->ccache, &iter);
    if (error) {
	free(server);
	free(client);
	return translate_cc_error(context, error);
    }

    ret = KRB5_CC_NOTFOUND;
    while (1) {
	cc_credentials_v5_t *v5cred;

	error = (*iter->func->next)(iter, &ccred);
	if (error)
	    break;

	if (ccred->data->version != cc_credentials_v5)
	    goto next;

	v5cred = ccred->data->credentials.credentials_v5;

	if (client && strcmp(v5cred->client, client) != 0)
	    goto next;

	if (strcmp(v5cred->server, server) != 0)
	    goto next;

	(*a->ccache->func->remove_credentials)(a->ccache, ccred);
	ret = 0;
    next:
	(*ccred->func->release)(ccred);
    }

    (*iter->func->release)(iter);

    if (ret)
	krb5_set_error_string(context, "Can't find credential %s in cache", 
			      server);
    free(server);
    free(client);

    return ret;
}

static krb5_error_code
acc_set_flags(krb5_context context,
	      krb5_ccache id,
	      krb5_flags flags)
{
    return 0;
}

static krb5_error_code
acc_get_version(krb5_context context,
		krb5_ccache id)
{
    return 0;
}
		    
const krb5_cc_ops krb5_acc_ops = {
    "API",
    acc_get_name,
    acc_resolve,
    acc_gen_new,
    acc_initialize,
    acc_destroy,
    acc_close,
    acc_store_cred,
    NULL, /* acc_retrieve */
    acc_get_principal,
    acc_get_first,
    acc_get_next,
    acc_end_get,
    acc_remove_cred,
    acc_set_flags,
    acc_get_version
};
