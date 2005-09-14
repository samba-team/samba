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
RCSID("$Id$");
#include <dlfcn.h>

#include "pkcs11u.h"
#include "pkcs11.h"

struct p11_module {
    hx509_certs certs;
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

    printf("slot = id %d\n", (int)id);

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

    printf("description: %s\n", slot->name);

    printf("manufacturer: %.*s\n",
	   (int)sizeof(slot_info.manufacturerID),
	   slot_info.manufacturerID);

    if ((slot_info.flags & CKF_TOKEN_PRESENT) == 0) {
	printf("no token present\n");
	return 0;
    }

    ret = P11FUNC(p, GetTokenInfo, (slot->id, &token_info));
    if (ret)
	return ret;

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

    if (token_info.flags & CKF_LOGIN_REQUIRED) {
	printf("login required\n");
	slot->flags |= P11_LOGIN_REQ;
    }

    return 0;
}


static int
p11_init_module(const char *fn, struct p11_module **module)
{
    CK_C_GetFunctionList getFuncs;
    struct p11_module *p;
    int ret;

    *module = NULL;

    printf("p11 init\n");

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

    ret = p11_init_module(residue, &p);
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
    *cursor = NULL;
    return 0;
}

static int
p11_iter(hx509_certs certs, void *data, void *cursor, hx509_cert *cert)
{
    *cert = NULL;
    return 0;
}

static int
p11_iter_end(hx509_certs certs, void *data, void *cursor)
{
    return 0;

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
