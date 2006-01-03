/*
 * Copyright (c) 2004 - 2006 Kungliga Tekniska Högskolan
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

#include "hx_locl.h"
RCSID("$Id$");
#include <dlfcn.h>

#include <openssl/ui.h>

#include "pkcs11u.h"
#include "pkcs11.h"

struct p11_module {
    void *dl_handle;
    CK_FUNCTION_LIST_PTR funcs;
    CK_ULONG num_slots;
    CK_ULONG selected_slot;
    /* slot info */
    struct p11_slot {
	int flags;
#define P11_SESSION		1
#define P11_LOGIN_REQ		2
#define P11_LOGIN_DONE		4
	CK_SESSION_HANDLE session;
	CK_SLOT_ID id;
	CK_BBOOL token;
	char *name;
	char *pin;
	hx509_certs certs;
    } slot;
};

#define P11SESSION(module) ((module)->session)
#define P11FUNC(module,f,args) (*(module)->funcs->C_##f)args


static int
p11_init_slot(struct p11_module *p, CK_SLOT_ID id, struct p11_slot *slot)
{
    CK_SLOT_INFO slot_info;
    CK_TOKEN_INFO token_info;
    int ret, i;

    slot->id = id;

    ret = P11FUNC(p, GetSlotInfo, (slot->id, &slot_info));
    if (ret)
	return ret;

    for (i = sizeof(slot_info.slotDescription) - 1; i > 0; i--) {
	char c = slot_info.slotDescription[i];
	if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\0')
	    continue;
	i++;
	break;
    }

    asprintf(&slot->name, "%.*s",
	     i, slot_info.slotDescription);

    if ((slot_info.flags & CKF_TOKEN_PRESENT) == 0) {
	return 0;
    }

    ret = P11FUNC(p, GetTokenInfo, (slot->id, &token_info));
    if (ret)
	return ret;

    if (token_info.flags & CKF_LOGIN_REQUIRED)
	slot->flags |= P11_LOGIN_REQ;

    return 0;
}

static int
p11_get_session(struct p11_module *p, struct p11_slot *slot)
{
    CK_RV ret;

    if (slot->flags & P11_SESSION)
	_hx509_abort("slot already in session");

    ret = P11FUNC(p, OpenSession, (slot->id, 
				   CKF_SERIAL_SESSION,
				   NULL,
				   NULL,
				   &slot->session));
    if (ret != CKR_OK)
	return EINVAL;
    
    slot->flags |= P11_SESSION;
    
    if ((slot->flags & P11_LOGIN_REQ) && (slot->flags & P11_LOGIN_DONE) == 0) {
	char pin[20];
	char *prompt;

	slot->flags |= P11_LOGIN_DONE;

	asprintf(&prompt, "PIN code for %s: ", slot->name);

	if (UI_UTIL_read_pw_string(pin, sizeof(pin), prompt, 0)) {
	    printf("no pin");
	    return EINVAL;
	}
	free(prompt);

	ret = P11FUNC(p, Login, (P11SESSION(slot), CKU_USER,
				 (unsigned char*)pin, 4));
	if (ret != CKR_OK)
	    printf("login failed\n");
	else
	    slot->pin = strdup(pin);
    }

    return 0;
}

static int
p11_put_session(struct p11_module *p, struct p11_slot *slot)
{
    int ret;

    if ((slot->flags & P11_SESSION) == 0)
	_hx509_abort("slot not in session");
    slot->flags &= ~P11_SESSION;

    ret = P11FUNC(p, CloseSession, (P11SESSION(slot)));
    if (ret != CKR_OK)
	return EINVAL;

    return 0;
}


static int
iterate_entries(struct p11_module *p, struct p11_slot *slot,
		CK_ATTRIBUTE *search_data, int num_search_data,
		CK_ATTRIBUTE *query, int num_query,
		int (*func)(void *, CK_ATTRIBUTE *, int), void *ptr)
{
    CK_OBJECT_HANDLE object;
    CK_ULONG object_count;
    int ret, i;

    ret = P11FUNC(p, FindObjectsInit,
		  (P11SESSION(slot), search_data, num_search_data));
    if (ret != CKR_OK) {
	return -1;
    }
    while (1) {
	ret = P11FUNC(p, FindObjects, 
		      (P11SESSION(slot), &object, 1, &object_count));
	if (ret != CKR_OK) {
	    return -1;
	}
	if (object_count == 0)
	    break;
	
	for (i = 0; i < num_query; i++)
	    query[i].pValue = NULL;

	ret = P11FUNC(p, GetAttributeValue, 
		      (P11SESSION(slot), object, query, num_query));
	if (ret != CKR_OK) {
	    return -1;
	}
	for (i = 0; i < num_query; i++) {
	    query[i].pValue = malloc(query[i].ulValueLen);
	    if (query[i].pValue == NULL) {
		ret = ENOMEM;
		goto out;
	    }
	}
	ret = P11FUNC(p, GetAttributeValue,
		      (P11SESSION(slot), object, query, num_query));
	if (ret != CKR_OK) {
	    ret = -1;
	    goto out;
	}
	
	ret = (*func)(ptr, query, num_query);
	if (ret)
	    goto out;

	for (i = 0; i < num_query; i++) {
	    if (query[i].pValue)
		free(query[i].pValue);
	    query[i].pValue = NULL;
	}
    }
 out:

    for (i = 0; i < num_query; i++) {
	if (query[i].pValue)
	    free(query[i].pValue);
	query[i].pValue = NULL;
    }

    ret = P11FUNC(p, FindObjectsFinal, (P11SESSION(slot)));
    if (ret != CKR_OK) {
	return -2;
    }


    return 0;
}
		
static int
print_id(void *ptr, CK_ATTRIBUTE *query, int num_query)
{
#if 0
    printf("id: %.*s\n", (int)query[0].ulValueLen, (char *)query[0].pValue);
#endif
    return 0;
}

static int
collect_cert(void *ptr, CK_ATTRIBUTE *query, int num_query)
{
    struct hx509_collector *c = ptr;
    hx509_cert cert;
    Certificate t;
    int ret;

    ret = decode_Certificate(query[1].pValue, query[1].ulValueLen,
			     &t, NULL);
    if (ret) {
	printf("decode_Certificate failed with %d\n", ret);
	return 0;
    }

    ret = hx509_cert_init(&t, &cert);
    free_Certificate(&t);
    if (ret)
	return ret;

    ret = _hx509_collector_certs_add(c, cert);
    if (ret) {
	hx509_cert_free(cert);
	return ret;
    }

    return 0;
}


static int
p11_list_keys(struct p11_module *p,
	      struct p11_slot *slot, 
	      hx509_lock lock,
	      hx509_certs *certs)
{
    CK_OBJECT_CLASS key_class;
    CK_ATTRIBUTE search_data[] = {
	{CKA_CLASS, &key_class, sizeof(key_class)},
    };
    CK_ATTRIBUTE query_data[2] = {
	{CKA_ID, NULL, 0},
	{CKA_VALUE, NULL, 0}
    };
    int ret;
    struct hx509_collector *c;

    if (lock == NULL)
	lock = _hx509_empty_lock;

    c = _hx509_collector_alloc(lock);
    if (c == NULL)
	return ENOMEM;


    key_class = CKO_PRIVATE_KEY;
    ret = iterate_entries(p, slot,
			  search_data, 1,
			  query_data, 1,
			  print_id, c);
    if (ret) {
	return ret;
    }

    key_class = CKO_PUBLIC_KEY;
    ret = iterate_entries(p, slot,
			  search_data, 1,
			  query_data, 1,
			  print_id, c);
    if (ret) {
	return ret;
    }

    key_class = CKO_CERTIFICATE;
    ret = iterate_entries(p, slot,
			  search_data, 1,
			  query_data, 2,
			  collect_cert, c);
    if (ret) {
	return ret;
    }

    ret = _hx509_collector_collect(c, &slot->certs);

    _hx509_collector_free(c);

    return ret;
}


static int
p11_init_module(const char *fn, hx509_lock lock, struct p11_module **module)
{
    CK_C_GetFunctionList getFuncs;
    struct p11_module *p;
    int ret;

    *module = NULL;

    p = calloc(1, sizeof(*p));
    if (p == NULL)
	return ENOMEM;

    p->selected_slot = 0;

    p->dl_handle = dlopen(fn, RTLD_NOW);
    if (p->dl_handle == NULL) {
	ret = EINVAL; /* XXX */
	goto out;
    }

    getFuncs = dlsym(p->dl_handle, "C_GetFunctionList");
    if (getFuncs == NULL) {
	ret = EINVAL;
	goto out;
    }

    ret = (*getFuncs)(&p->funcs);
    if (ret) {
	ret = EINVAL;
	goto out;
    }

    ret = P11FUNC(p, Initialize, (NULL_PTR));
    if (ret != CKR_OK) {
	ret = EINVAL;
	goto out;
    }

    ret = P11FUNC(p, GetSlotList, (FALSE, NULL, &p->num_slots));
    if (ret) {
	ret = EINVAL;
	goto out;
    }

    if (p->selected_slot > p->num_slots) {
	ret = EINVAL;
	goto out;
    }

    {
	CK_SLOT_ID_PTR slot_ids;

	slot_ids = malloc(p->num_slots * sizeof(*slot_ids));
	if (slot_ids == NULL) {
	    ret = ENOMEM;
	    goto out;
	}

	ret = P11FUNC(p, GetSlotList, (FALSE, slot_ids, &p->num_slots));
	if (ret) {
	    free(slot_ids);
	    ret = EINVAL;
	    goto out;
	}

	ret = p11_init_slot(p, slot_ids[p->selected_slot], &p->slot);

	free(slot_ids);

	p11_get_session(p, &p->slot);
	p11_list_keys(p, &p->slot, NULL, &p->slot.certs);
	p11_put_session(p, &p->slot);
    }

    *module = p;

    return 0;
 out:    
    if (p->dl_handle)
	dlclose(p->dl_handle);
    free(p);
    return ret;
}

static int
p11_init(hx509_certs certs, void **data, int flags, 
	 const char *residue, hx509_lock lock)
{
    struct p11_module *p;
    int ret;

    ret = p11_init_module(residue, lock, &p);
    if (ret)
	return ret;

    *data = p;
    return 0;
}

static int
p11_free(hx509_certs certs, void *data)
{
    struct p11_module *p = data;

    if (p->dl_handle)
	dlclose(p->dl_handle);
    free(p);
    return 0;
}

static int 
p11_iter_start(hx509_certs certs, void *data, void **cursor)
{
    struct p11_module *p = data;
    return hx509_certs_start_seq(p->slot.certs, cursor);
}

static int
p11_iter(hx509_certs certs, void *data, void *cursor, hx509_cert *cert)
{
    struct p11_module *p = data;
    return hx509_certs_next_cert(p->slot.certs, cursor, cert);
}

static int
p11_iter_end(hx509_certs certs, void *data, void *cursor)
{
    struct p11_module *p = data;
    return hx509_certs_end_seq(p->slot.certs, cursor);
}

static struct hx509_keyset_ops keyset_pkcs11 = {
    "PKCS11",
    0,
    p11_init,
    p11_free,
    NULL,
    NULL,
    p11_iter_start,
    p11_iter,
    p11_iter_end
};

void
_hx509_ks_pkcs11_register(void)
{
    _hx509_ks_register(&keyset_pkcs11);
}
