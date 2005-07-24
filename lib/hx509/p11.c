/*
 * Copyright (c) 2004 - 2005 Kungliga Tekniska Högskolan
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
RCSID("$ID$");

/* http://developer.netscape.com/support/faqs/pkcs_11.html */

#include <openssl/ui.h>

#include <dlfcn.h>

#include "pkcs11u.h"
#include "pkcs11.h"

typedef struct hx509_security_device_data *hx509_security_device;
typedef struct hx509_keyset_data *hx509_keyset;

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
};

struct hx509_security_device_data {
    int refcount;
    void *handle;
    CK_FUNCTION_LIST_PTR funcs;
    CK_ULONG num_slots;
    struct p11_slot *slots;
    int selected_slot; /* XXX */
};

#define P11SESSION(module) ((module)->slots[(module)->selected_slot].session)
#define P11FUNC(module,f,args) (*(module)->funcs->C_##f)args

struct hx509_keyset_data {
    hx509_security_device device;
    hx509_certs certs;
};


typedef struct hx509_key_data *hx509_key;

static int
hx509_p11_load_module(const char *fn, hx509_security_device *module)
{
    CK_C_GetFunctionList getFuncs;
    hx509_security_device p;
    int ret;

    *module = NULL;

    p = calloc(1, sizeof(*p));
    if (p == NULL)
	return ENOMEM;

    p->selected_slot = 0;

    p->handle = dlopen(fn, RTLD_NOW);
    if (p->handle == NULL) {
	ret = EINVAL; /* XXX */
	goto out;
    }

    getFuncs = dlsym(p->handle, "C_GetFunctionList");
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

    {
	CK_INFO info;

	ret = P11FUNC(p, GetInfo, (&info));
	if (ret != CKR_OK) {
	    ret = EINVAL;
	    goto out;
	}

	printf("module information:\n");
	printf("version: %04x.%04x\n",
	       (unsigned int)info.cryptokiVersion.major,
	       (unsigned int)info.cryptokiVersion.minor);
	printf("manufacturer: %.*s\n",
	       (int)sizeof(info.manufacturerID) - 1,
	       info.manufacturerID);
	printf("flags: 0x%04x\n", (unsigned int)info.flags);
	printf("library description: %.*s\n",
	       (int)sizeof(info.libraryDescription) - 1,
	       info.libraryDescription);
	printf("version: %04x.%04x\n",
	       (unsigned int)info.libraryVersion.major,
	       (unsigned int)info.libraryVersion.minor);

    }

    ret = P11FUNC(p, GetSlotList, (FALSE, NULL, &p->num_slots));
    if (ret) {
	ret = EINVAL;
	goto out;
    }

    printf("num slots: %ld\n", (long)p->num_slots);

    {
	CK_SLOT_ID_PTR slot_ids;
	int i, j;

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

	p->slots = calloc(p->num_slots, sizeof(p->slots[0]));
	if (p->slots == NULL) {
	    free(slot_ids);
	    ret = ENOMEM;
	    goto out;
	}

	for (i = 0; i < p->num_slots; i++) {
	    CK_SLOT_INFO slot_info;
	    CK_TOKEN_INFO token_info;

	    printf("slot %d = id %d\n", i, (int)slot_ids[i]);

	    p->slots[i].id = slot_ids[i];

	    ret = P11FUNC(p, GetSlotInfo, (slot_ids[i], &slot_info));
	    if (ret)
		continue;

	    for (j = sizeof(slot_info.slotDescription) - 1; j > 0; j--) {
		char c = slot_info.slotDescription[j];
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\0')
		    continue;
		j++;
		break;
	    }

	    asprintf(&p->slots[i].name, "%.*s (slot %d)",
		     j, slot_info.slotDescription, i);

	    printf("description: %s\n", p->slots[i].name);

	    printf("manufacturer: %.*s\n",
		   (int)sizeof(slot_info.manufacturerID),
		   slot_info.manufacturerID);

	    if ((slot_info.flags & CKF_TOKEN_PRESENT) == 0) {
		printf("no token present\n");
		continue;
	    }

	    ret = P11FUNC(p, GetTokenInfo, (slot_ids[i], &token_info));
	    if (ret)
		continue;

	    printf("token present\n");

	    printf("label: %.*s\n",
		   (int)sizeof(token_info.label),
		   token_info.label);
	    printf("manufacturer: %.*s\n",
		   (int)sizeof(token_info.manufacturerID),
		   token_info.manufacturerID);
	    printf("model: %.*s\n",
		   (int)sizeof(token_info.model),
		   token_info.model);
	    printf("serialNumber: %.*s\n",
		   (int)sizeof(token_info.serialNumber),
		   token_info.serialNumber);

	    printf("flags: 0x%04x\n", (unsigned int)token_info.flags);

	    printf("slotinfo.flags 0x%x & 0x%x = 0x%x\n",
		   (int)slot_info.flags, (int)CKF_LOGIN_REQUIRED,
		   (int)(slot_info.flags & CKF_LOGIN_REQUIRED));
	    if (token_info.flags & CKF_LOGIN_REQUIRED) {
		printf("login required\n");
		p->slots[i].flags |= P11_LOGIN_REQ;
	    }
	}	
    }

    *module = p;

    return 0;
 out:    
    if (p->slots)
	free(p->slots);
    if (p->handle)
	dlclose(p->handle);
    free(p);
    return ret;
    
}

static int
p11_get_session(hx509_security_device module, const char *conf, int slot)
{
    CK_RV ret;

    module->selected_slot = slot;

    if (slot >= module->num_slots)
	return EINVAL;

    if (module->slots[slot].flags & P11_SESSION)
	return EINVAL; /* XXX */

    ret = P11FUNC(module, OpenSession, (module->slots[slot].id, 
					CKF_SERIAL_SESSION,
					NULL,
					NULL,
					&module->slots[slot].session));
    if (ret != CKR_OK)
	return EINVAL;
    
    module->slots[slot].flags |= P11_SESSION;
    
    if ((module->slots[slot].flags & P11_LOGIN_REQ) &&
	(module->slots[slot].flags & P11_LOGIN_DONE) == 0) {
	char pin[20];
	char *prompt;

	module->slots[slot].flags |= P11_LOGIN_DONE;

	asprintf(&prompt, "PIN code for %s: ", module->slots[slot].name);

	if (UI_UTIL_read_pw_string(pin, sizeof(pin), prompt, 0)) {
	    printf("no pin");
	    goto out;
	}
	free(prompt);

	ret = P11FUNC(module, Login,
		      (P11SESSION(module), CKU_USER, "3962", 4));
	if (ret != CKR_OK)
	    printf("login failed\n");
	else
	    module->slots[slot].pin = strdup(pin);
    out:;
    }

    return 0;
}

static int
p11_put_session(hx509_security_device module, int slot)
{
    int ret;

    if (module->slots[slot].flags & P11_SESSION)
	return EINVAL;
    ret = P11FUNC(module, CloseSession, (module->slots[slot].session));
    if (ret != CKR_OK)
	return EINVAL;

    return 0;
}


static int
iterate_entries(hx509_security_device module, hx509_certs ks,
		CK_ATTRIBUTE *search_data, int num_search_data,
		CK_ATTRIBUTE *query, int num_query,
		int (*func)(void *, CK_ATTRIBUTE *, int), void *ptr)
{
    CK_OBJECT_HANDLE object;
    CK_ULONG object_count;
    int ret, i;

    printf("current slot: %d\n", module->selected_slot);
    
    ret = P11FUNC(module, FindObjectsInit,
		  (P11SESSION(module), search_data, num_search_data));
    if (ret != CKR_OK) {
	return -1;
    }
    while (1) {
	ret = P11FUNC(module, FindObjects, 
		      (P11SESSION(module), &object, 1, &object_count));
	if (ret != CKR_OK) {
	    return -1;
	}
	printf("object count = %d\n", (int)object_count);
	if (object_count == 0)
	    break;
	
	for (i = 0; i < num_query; i++)
	    query[i].pValue = NULL;

	ret = P11FUNC(module, GetAttributeValue, 
		      (P11SESSION(module), object, query, num_query));
	if (ret != CKR_OK) {
	    return -1;
	}
	for (i = 0; i < num_query; i++) {
	    printf("id %d len = %d\n", i, (int)query[i].ulValueLen);
	    query[i].pValue = malloc(query[i].ulValueLen);
	    if (query[i].pValue == NULL) {
		ret = ENOMEM;
		goto out;
	    }
	}
	ret = P11FUNC(module, GetAttributeValue,
		      (P11SESSION(module), object, query, num_query));
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

    ret = P11FUNC(module, FindObjectsFinal, (P11SESSION(module)));
    if (ret != CKR_OK) {
	return -2;
    }


    return 0;
}
		
static int
print_id(void *ptr, CK_ATTRIBUTE *query, int num_query)
{
    printf("id: %.*s\n", (int)query[0].ulValueLen, (char *)query[0].pValue);
    return 0;
}

static int
print_cert(void *ptr, CK_ATTRIBUTE *query, int num_query)
{
    hx509_validate_ctx ctx;
    hx509_cert cert;
    Certificate c;
    int ret;

    printf("id: %d\n", (int)query[0].ulValueLen);

    memset(&c, 0, sizeof(c));
    ret = decode_Certificate(query[1].pValue, query[1].ulValueLen,
			     &c, NULL);
    if (ret) {
	printf("decode_Certificate failed with %d\n", ret);
	return 0;
    }

    ret = hx509_cert_init(&c, &cert);
    if (ret)
	abort();
    free_Certificate(&c);

    hx509_validate_ctx_init(&ctx);
    hx509_validate_ctx_set_print(ctx, hx509_print_stdout, stdout);
    hx509_validate_ctx_add_flags(ctx, HX509_VALIDATE_F_VERBOSE);

    hx509_validate_cert(ctx, cert);

    hx509_validate_ctx_free(ctx);
    hx509_cert_free(cert);

    return 0;
}


static int
p11_list_keys(hx509_security_device module, hx509_certs ks)
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

    printf("---- private\n");
    key_class = CKO_PRIVATE_KEY;
    ret = iterate_entries(module, ks, search_data, 1,
			  query_data, 1,
			  print_id, NULL);
    if (ret) {
	return ret;
    }

    printf("---- public\n");
    key_class = CKO_PUBLIC_KEY;
    ret = iterate_entries(module, ks, search_data, 1,
			  query_data, 1,
			  print_id, NULL);
    if (ret) {
	return ret;
    }

    printf("---- cert\n");
    key_class = CKO_CERTIFICATE;
    ret = iterate_entries(module, ks, search_data, 1,
			  query_data, 2,
			  print_cert, NULL);
    if (ret) {
	return ret;
    }
    printf("----\n");


    return 0;
}

static int
security_device_add(hx509_security_device *device, const char *conf)
{
    hx509_security_device module;
    char *c, *fn;
    int ret;

    *device = NULL;

    c = strdup(conf);
    if (c == NULL)
	return ENOMEM;

    fn = strchr(c, ':');
    if (fn)
	*fn++ = '\0';
    else
	fn = "/usr/lib/default-pkcs11.so";

    if (strcasecmp(c, "PKCS11") != 0) {
	free(c);
	return EINVAL;
    }

    ret = hx509_p11_load_module(fn, &module);
    free(c);
    if (ret)
	return ret;

    *device = module;
    return 0;
}


int
hx509_keyset_init(const char *file, const char *conf)
{
    hx509_security_device module;
    hx509_keyset ks;
    int ret, slot;
		  
    ret = security_device_add(&module, file);
    if (ret) {
	printf("security_device_add: %d\n", ret);
	return 0;
    }

    module->refcount++;

    ks = calloc(1, sizeof(*ks));
    if (ks == NULL)
	return ENOMEM;

    ks->device = module;

    ret = hx509_certs_init("MEMORY:pkcs-11-store", 0, NULL, &ks->certs);
    if (ret)
	goto out;

    /* 
     * XXX just check if the device change changed, and if that case
     * refresh contents of cache
     */

    slot = 0;

    ret = p11_get_session(module, conf, slot);
    if (ret)
	goto out;

    /* fetch certificates and keys */
    ret = p11_list_keys(module, ks->certs);
    if (ret)
	goto out_session;

 out_session:

    ret = p11_put_session(module, slot);

 out:
    if (ret) {
	hx509_certs_free(&ks->certs);
	memset(ks, 0, sizeof(ks));
	free(ks);
	module->refcount--;
    } else {
	hx509_certs_iter(ks->certs, hx509_ci_print_names, stdout);
    }

    return 0;
}
