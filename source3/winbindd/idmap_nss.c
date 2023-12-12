/*
   Unix SMB/CIFS implementation.

   idmap NSS backend

   Copyright (C) Simo Sorce 2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/passwd.h"
#include "winbindd.h"
#include "nsswitch/winbind_client.h"
#include "idmap.h"
#include "lib/winbind_util.h"
#include "libcli/security/dom_sid.h"
#include "lib/global_contexts.h"
#include "messages.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

struct idmap_nss_context {
	struct idmap_domain *dom;
	bool use_upn;
};

static int idmap_nss_context_destructor(struct idmap_nss_context *ctx)
{
	if ((ctx->dom != NULL) && (ctx->dom->private_data == ctx)) {
		ctx->dom->private_data = NULL;
	}
	return 0;
}

static NTSTATUS idmap_nss_context_create(TALLOC_CTX *mem_ctx,
					 struct idmap_domain *dom,
					 struct idmap_nss_context **pctx)
{
	struct idmap_nss_context *ctx = NULL;

	ctx = talloc_zero(mem_ctx, struct idmap_nss_context);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ctx->dom = dom;

	talloc_set_destructor(ctx, idmap_nss_context_destructor);

	ctx->use_upn = idmap_config_bool(dom->name, "use_upn", false);

	*pctx = ctx;
	return NT_STATUS_OK;
}

static NTSTATUS idmap_nss_get_context(struct idmap_domain *dom,
				      struct idmap_nss_context **pctx)
{
	struct idmap_nss_context *ctx = NULL;
	NTSTATUS status;

	if (dom->private_data != NULL) {
		*pctx = talloc_get_type_abort(dom->private_data,
					      struct idmap_nss_context);
		return NT_STATUS_OK;
	}

	status = idmap_nss_context_create(dom, dom, &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("idmap_nss_context_create failed: %s\n",
			    nt_errstr(status));
		return status;
	}

	dom->private_data = ctx;
	*pctx = ctx;
	return NT_STATUS_OK;
}

static bool idmap_nss_msg_filter(struct messaging_rec *rec, void *private_data)
{
	struct idmap_domain *dom = talloc_get_type_abort(private_data,
		       struct idmap_domain);
	struct idmap_nss_context *ctx = NULL;
	NTSTATUS status;
	bool ret;

	if (rec->msg_type == MSG_SMB_CONF_UPDATED) {
		ret = lp_load_global(get_dyn_CONFIGFILE());
		if (!ret) {
			DBG_WARNING("Failed to reload configuration\n");
			return false;
		}

		status = idmap_nss_get_context(dom, &ctx);
		if (NT_STATUS_IS_ERR(status)) {
			DBG_WARNING("Failed to get idmap nss context: %s\n",
					nt_errstr(status));
			return false;
		}

		ctx->use_upn = idmap_config_bool(dom->name, "use_upn", false);
	}

	return false;
}

/*****************************
 Initialise idmap database.
*****************************/

static NTSTATUS idmap_nss_int_init(struct idmap_domain *dom)
{
	struct idmap_nss_context *ctx = NULL;
	NTSTATUS status;
	struct messaging_context *msg_ctx = global_messaging_context();
	struct tevent_req *req = NULL;

	status = idmap_nss_context_create(dom, dom, &ctx);
	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	dom->private_data = ctx;

	req = messaging_filtered_read_send(
			dom,
			messaging_tevent_context(msg_ctx),
			msg_ctx,
			idmap_nss_msg_filter,
			dom);
	if (req == NULL) {
		DBG_WARNING("messaging_filtered_read_send failed\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	return status;
}

static NTSTATUS idmap_nss_lookup_name(const char *namespace,
				      const char *username,
				      struct dom_sid *sid,
				      enum lsa_SidType *type)
{
	bool ret;

	/*
	 * By default calls to winbindd are disabled
	 * the following call will not recurse so this is safe
	 */
	(void)winbind_on();
	ret = winbind_lookup_name(namespace, username, sid, type);
	(void)winbind_off();

	if (!ret) {
		DBG_NOTICE("Failed to lookup name [%s] in namespace [%s]\n",
			   username, namespace);
		return NT_STATUS_NOT_FOUND;
	}

	return NT_STATUS_OK;
}

/**********************************
 lookup a set of unix ids.
**********************************/

static NTSTATUS idmap_nss_unixids_to_sids(struct idmap_domain *dom, struct id_map **ids)
{
	struct idmap_nss_context *ctx = NULL;
	NTSTATUS status;
	int i;

	status = idmap_nss_get_context(dom, &ctx);
	if (NT_STATUS_IS_ERR(status)) {
		DBG_WARNING("Failed to get idmap nss context: %s\n",
			    nt_errstr(status));
		return status;
	}

	/* initialize the status to avoid surprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	for (i = 0; ids[i]; i++) {
		struct passwd *pw;
		struct group *gr;
		const char *name;
		struct dom_sid sid;
		enum lsa_SidType type;

		switch (ids[i]->xid.type) {
		case ID_TYPE_UID:
			errno = 0;
			pw = getpwuid((uid_t)ids[i]->xid.id);
			if (!pw) {
				DBG_DEBUG("getpwuid(%lu) failed: %s\n",
					  (unsigned long)ids[i]->xid.id,
					  errno != 0
					  ? strerror(errno)
					  : "not found");
				ids[i]->status = ID_UNMAPPED;
				continue;
			}
			name = pw->pw_name;
			break;
		case ID_TYPE_GID:
			errno = 0;
			gr = getgrgid((gid_t)ids[i]->xid.id);
			if (!gr) {
				DBG_DEBUG("getgrgid(%lu) failed: %s\n",
					  (unsigned long)ids[i]->xid.id,
					  errno != 0
					  ? strerror(errno)
					  : "not found");
				ids[i]->status = ID_UNMAPPED;
				continue;
			}
			name = gr->gr_name;
			break;
		default: /* ?? */
			DBG_WARNING("Unexpected xid type %d\n",
				    ids[i]->xid.type);
			ids[i]->status = ID_UNKNOWN;
			continue;
		}

		/* Lookup name from PDC using lsa_lookup_names() */
		if (ctx->use_upn) {
			char *p = NULL;
			const char *namespace = NULL;
			const char *domname = NULL;
			const char *domuser = NULL;

			p = strstr(name, lp_winbind_separator());
			if (p != NULL) {
				*p = '\0';
				domname = name;
				namespace = domname;
				domuser = p + 1;
			} else {
				p = strchr(name, '@');
				if (p != NULL) {
					*p = '\0';
					namespace = p + 1;
					domname = "";
					domuser = name;
				} else {
					namespace = dom->name;
					domuser = name;
				}
			}

			DBG_DEBUG("Using namespace [%s] from UPN instead "
				  "of [%s] to lookup the name [%s]\n",
				  namespace, dom->name, domuser);

			status = idmap_nss_lookup_name(namespace,
						       domuser,
						       &sid,
						       &type);
		} else {
			status = idmap_nss_lookup_name(dom->name,
						       name,
						       &sid,
						       &type);
                }

		if (NT_STATUS_IS_ERR(status)) {
			/*
			 * TODO: how do we know if the name is really
			 * not mapped, or something just failed ?
			 */
			ids[i]->status = ID_UNMAPPED;
			continue;
		}

		switch (type) {
		case SID_NAME_USER:
			if (ids[i]->xid.type == ID_TYPE_UID) {
				sid_copy(ids[i]->sid, &sid);
				ids[i]->status = ID_MAPPED;
			}
			break;

		case SID_NAME_DOM_GRP:
		case SID_NAME_ALIAS:
		case SID_NAME_WKN_GRP:
			if (ids[i]->xid.type == ID_TYPE_GID) {
				sid_copy(ids[i]->sid, &sid);
				ids[i]->status = ID_MAPPED;
			}
			break;

		default:
			ids[i]->status = ID_UNKNOWN;
			break;
		}
	}
	return NT_STATUS_OK;
}

/**********************************
 lookup a set of sids.
**********************************/

static NTSTATUS idmap_nss_sids_to_unixids(struct idmap_domain *dom, struct id_map **ids)
{
	struct idmap_nss_context *ctx = NULL;
	NTSTATUS status;
	int i;

	status = idmap_nss_get_context(dom, &ctx);
	if (NT_STATUS_IS_ERR(status)) {
		DBG_WARNING("Failed to get idmap nss context: %s\n",
			    nt_errstr(status));
		return status;
	}

	/* initialize the status to avoid surprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	for (i = 0; ids[i]; i++) {
		struct group *gr;
		enum lsa_SidType type;
		const char *_domain = NULL;
		const char *_name = NULL;
		char *domain = NULL;
		char *name = NULL;
		char *fqdn = NULL;
		char *sname = NULL;
		bool ret;

		/* by default calls to winbindd are disabled
		   the following call will not recurse so this is safe */
		(void)winbind_on();
		ret = winbind_lookup_sid(talloc_tos(),
					 ids[i]->sid,
					 &_domain,
					 &_name,
					 &type);
		(void)winbind_off();
		if (!ret) {
			/* TODO: how do we know if the name is really not mapped,
			 * or something just failed ? */
			ids[i]->status = ID_UNMAPPED;
			continue;
		}

		domain = discard_const_p(char, _domain);
		name = discard_const_p(char, _name);

		if (!strequal(domain, dom->name)) {
			struct dom_sid_buf buf;
			DBG_ERR("DOMAIN[%s] ignoring SID[%s] belongs to %s [%s\\%s]\n",
			        dom->name, dom_sid_str_buf(ids[i]->sid, &buf),
				sid_type_lookup(type), domain, name);
			ids[i]->status = ID_UNMAPPED;
			continue;
		}

		if (ctx->use_upn) {
			fqdn = talloc_asprintf(talloc_tos(),
					       "%s%s%s",
					       domain,
					       lp_winbind_separator(),
					       name);
			if (fqdn == NULL) {
				DBG_ERR("No memory\n");
				ids[i]->status = ID_UNMAPPED;
				continue;
			}
			DBG_DEBUG("Using UPN [%s] instead of plain name [%s]\n",
				  fqdn, name);
			sname = fqdn;
		} else {
			sname = name;
		}

		switch (type) {
		case SID_NAME_USER: {
			struct passwd *pw;

			/* this will find also all lower case name and use username level */
			pw = Get_Pwnam_alloc(talloc_tos(), sname);
			if (pw) {
				ids[i]->xid.id = pw->pw_uid;
				ids[i]->xid.type = ID_TYPE_UID;
				ids[i]->status = ID_MAPPED;
			}
			TALLOC_FREE(pw);
			break;
		}

		case SID_NAME_DOM_GRP:
		case SID_NAME_ALIAS:
		case SID_NAME_WKN_GRP:

			gr = getgrnam(sname);
			if (gr) {
				ids[i]->xid.id = gr->gr_gid;
				ids[i]->xid.type = ID_TYPE_GID;
				ids[i]->status = ID_MAPPED;
			}
			break;

		default:
			ids[i]->status = ID_UNKNOWN;
			break;
		}
		TALLOC_FREE(domain);
		TALLOC_FREE(name);
		TALLOC_FREE(fqdn);
	}
	return NT_STATUS_OK;
}

/**********************************
 Close the idmap tdb instance
**********************************/

static const struct idmap_methods nss_methods = {
	.init = idmap_nss_int_init,
	.unixids_to_sids = idmap_nss_unixids_to_sids,
	.sids_to_unixids = idmap_nss_sids_to_unixids,
};

NTSTATUS idmap_nss_init(TALLOC_CTX *mem_ctx)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "nss", &nss_methods);
}
