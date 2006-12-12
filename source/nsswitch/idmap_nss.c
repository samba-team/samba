/* 
   Unix SMB/CIFS implementation.

   idmap PASSDB backend

   Copyright (C) Simo Sorce 2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

/*****************************
 Initialise idmap database. 
*****************************/

static NTSTATUS idmap_nss_int_init(struct idmap_domain *dom, const char *compat_params)
{	
	return NT_STATUS_OK;
}

/**********************************
 lookup a set of unix ids. 
**********************************/

static NTSTATUS idmap_nss_unixids_to_sids(struct idmap_domain *dom, struct id_map **ids)
{
	TALLOC_CTX *ctx;
	struct winbindd_domain *wdom;
	BOOL winbind_env;
	int i;

	wdom = find_lookup_domain_from_name(dom->name);
	if (!wdom) {
		DEBUG(2, ("Can't lookup domain %s\n", dom->name));
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	ctx = talloc_new(dom);
	if ( ! ctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* avoid any possible recursion in winbindd,
	 * these calls are aimed at getting info
	 * out of alternative nss dbs anyway */
	winbind_env = winbind_env_set();
	winbind_off();

	for (i = 0; ids[i]; i++) {
		struct passwd *pw;
		struct group *gr;
		const char *name;
		enum lsa_SidType type;
		
		switch (ids[i]->xid.type) {
		case ID_TYPE_UID:
			pw = getpwuid((uid_t)ids[i]->xid.id);
			if (!pw) {
				ids[i]->mapped = False;
				continue;
			}
			name = pw->pw_name;
			break;
		case ID_TYPE_GID:
			gr = getgrgid((gid_t)ids[i]->xid.id);
			if (!gr) {
				ids[i]->mapped = False;
				continue;
			}
			name = gr->gr_name;
			break;
		default: /* ?? */
			ids[i]->mapped = False;
			continue;
		}

		/* Lookup name from PDC using lsa_lookup_names() */
		if (!winbindd_lookup_sid_by_name(ctx, wdom, dom->name, name, ids[i]->sid, &type)) {
			ids[i]->mapped = False;
			continue;
		}

		/* make sure it is marked as unmapped if types do not match */
		ids[i]->mapped = False;

		switch (type) {
		case SID_NAME_USER:
			if (ids[i]->xid.type == ID_TYPE_UID) {
				ids[i]->mapped = True;
			}
			break;

		case SID_NAME_DOM_GRP:
		case SID_NAME_ALIAS:
		case SID_NAME_WKN_GRP:
			if (ids[i]->xid.type == ID_TYPE_GID) {
				ids[i]->mapped = True;
			}
			break;

		default:
			break;
		}
	}

	/* allow winbindd calls again, if they were enabled */
	if (!winbind_env) {
		winbind_on();
	}

	talloc_free(ctx);
	return NT_STATUS_OK;
}

/**********************************
 lookup a set of sids. 
**********************************/

static NTSTATUS idmap_nss_sids_to_unixids(struct idmap_domain *dom, struct id_map **ids)
{
	TALLOC_CTX *ctx;
	BOOL winbind_env;
	int i;

	ctx = talloc_new(dom);
	if ( ! ctx) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* avoid any possible recursion in winbindd,
	 * these calls are aimed at getting info
	 * out of alternative nss dbs anyway */
	winbind_env = winbind_env_set();
	winbind_off();

	for (i = 0; ids[i]; i++) {
		struct passwd *pw;
		struct group *gr;
		enum lsa_SidType type;
		char *dom_name = NULL;
		char *name = NULL;

		if (!winbindd_lookup_name_by_sid(ctx, ids[i]->sid, &dom_name, &name, &type)) {
			ids[i]->mapped = False;
			continue;
		}

		/* make sure it is marked as unmapped if types do not match */
		ids[i]->mapped = False;

		switch (type) {
		case SID_NAME_USER:

			/* this will find also all lower case name and use username level */
			pw = Get_Pwnam(name);
			if (pw) {
				ids[i]->xid.id = pw->pw_uid;
				ids[i]->xid.type = ID_TYPE_UID;
				ids[i]->mapped = True;
			}
			break;

		case SID_NAME_DOM_GRP:
		case SID_NAME_ALIAS:
		case SID_NAME_WKN_GRP:

			gr = getgrnam(name);
			if (gr) {
				ids[i]->xid.id = gr->gr_gid;
				ids[i]->xid.type = ID_TYPE_GID;
				ids[i]->mapped = True;
			}
			break;

		default:
			break;
		}

		TALLOC_FREE(dom_name);
		TALLOC_FREE(name);
	}

	/* allow winbindd calls again, if they were enabled */
	if (!winbind_env) {
		winbind_on();
	}

	talloc_free(ctx);
	return NT_STATUS_OK;
}

/**********************************
 Close the idmap tdb instance
**********************************/

static NTSTATUS idmap_nss_close(struct idmap_domain *dom)
{
	return NT_STATUS_OK;
}

static struct idmap_methods nss_methods = {

	.init = idmap_nss_int_init,
	.unixids_to_sids = idmap_nss_unixids_to_sids,
	.sids_to_unixids = idmap_nss_sids_to_unixids,
	.close_fn = idmap_nss_close
};

NTSTATUS idmap_nss_init(void)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "nss", &nss_methods);
}
