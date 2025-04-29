/*
   Unix SMB/CIFS implementation.
   ACL get/set utility

   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Tim Potter      2000
   Copyright (C) Jeremy Allison  2000
   Copyright (C) Jelmer Vernooij 2003
   Copyright (C) Noel Power <noel.power@suse.com> 2013

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
#include "lib/cmdline/cmdline.h"
#include "rpc_client/cli_pipe.h"
#include "../librpc/gen_ndr/ndr_lsa.h"
#include "rpc_client/cli_lsarpc.h"
#include "../libcli/security/security.h"
#include "libsmb/libsmb.h"
#include "libsmb/clirap.h"
#include "passdb/machine_sid.h"
#include "../librpc/gen_ndr/ndr_lsa_c.h"
#include "util_sd.h"
#include "lib/param/param.h"
#include "lib/util/util_file.h"

static char DIRSEP_CHAR = '\\';

static int inheritance = 0;
static const char *save_file = NULL;
static const char *restore_file = NULL;
static int recurse;
static int test_args;
static int sddl;
static int query_sec_info = -1;
static int set_sec_info = -1;
static bool want_mxac;

static const char *domain_sid = NULL;

enum acl_mode {SMB_ACL_SET, SMB_ACL_DELETE, SMB_ACL_MODIFY, SMB_ACL_ADD };
enum chown_mode {REQUEST_NONE, REQUEST_CHOWN, REQUEST_CHGRP, REQUEST_INHERIT};
enum exit_values {EXIT_OK, EXIT_FAILED, EXIT_PARSE_ERROR};

struct cacl_callback_state {
	struct cli_credentials *creds;
	struct cli_state *cli;
	struct security_descriptor *aclsd;
	struct security_acl *acl_to_add;
	enum acl_mode mode;
	char *the_acl;
	bool acl_no_propagate;
	bool numeric;
};

static NTSTATUS cli_lsa_lookup_domain_sid(struct cli_state *cli,
					  struct dom_sid *sid)
{
	union lsa_PolicyInformation *info = NULL;
	struct smbXcli_tcon *orig_tcon = NULL;
	char *orig_share = NULL;
	struct rpc_pipe_client *rpc_pipe = NULL;
	struct policy_handle handle;
	NTSTATUS status, result;
	TALLOC_CTX *frame = talloc_stackframe();

	if (cli_state_has_tcon(cli)) {
		cli_state_save_tcon_share(cli, &orig_tcon, &orig_share);
	}

	status = cli_tree_connect(cli, "IPC$", "?????", NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = cli_rpc_pipe_open_noauth(cli, &ndr_table_lsarpc, &rpc_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		goto tdis;
	}

	status = rpccli_lsa_open_policy(rpc_pipe, frame, True,
					GENERIC_EXECUTE_ACCESS, &handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto tdis;
	}

	status = dcerpc_lsa_QueryInfoPolicy2(rpc_pipe->binding_handle,
					     frame, &handle,
					     LSA_POLICY_INFO_DOMAIN,
					     &info, &result);

	if (any_nt_status_not_ok(status, result, &status)) {
		goto tdis;
	}

	*sid = *info->domain.sid;

tdis:
	TALLOC_FREE(rpc_pipe);
	cli_tdis(cli);
done:
	cli_state_restore_tcon_share(cli, orig_tcon, orig_share);
	TALLOC_FREE(frame);
	return status;
}

static struct dom_sid *get_domain_sid(struct cli_state *cli)
{
	NTSTATUS status;
	struct dom_sid_buf buf;

	struct dom_sid *sid = talloc(talloc_tos(), struct dom_sid);
	if (sid == NULL) {
		DEBUG(0, ("Out of memory\n"));
		return NULL;
	}

	if (domain_sid) {
		if (!dom_sid_parse(domain_sid, sid)) {
			DEBUG(0,("failed to parse domain sid\n"));
			TALLOC_FREE(sid);
		}
	} else {
		status = cli_lsa_lookup_domain_sid(cli, sid);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("failed to lookup domain sid: %s\n", nt_errstr(status)));
			TALLOC_FREE(sid);
		}

	}

	DEBUG(2,("Domain SID: %s\n", dom_sid_str_buf(sid, &buf)));
	return sid;
}

/* add an ACE to a list of ACEs in a struct security_acl */
static bool add_ace_with_ctx(TALLOC_CTX *ctx, struct security_acl **the_acl,
			     const struct security_ace *ace)

{
	struct security_acl *acl = *the_acl;

	if (acl == NULL) {
		acl = make_sec_acl(ctx, 3, 0, NULL);
		if (acl == NULL) {
			return false;
		}
	}

	if (acl->num_aces == UINT32_MAX) {
		return false;
	}
	ADD_TO_ARRAY(
		acl, struct security_ace, *ace, &acl->aces, &acl->num_aces);
	*the_acl = acl;
	return True;
}

static bool add_ace(struct security_acl **the_acl, struct security_ace *ace)
{
	return add_ace_with_ctx(talloc_tos(), the_acl, ace);
}

/* parse a ascii version of a security descriptor */
static struct security_descriptor *sec_desc_parse(TALLOC_CTX *ctx, struct cli_state *cli, char *str)
{
	const char *p = str;
	char *tok;
	struct security_descriptor *ret = NULL;
	size_t sd_size;
	struct dom_sid owner_sid = { .num_auths = 0 };
	bool have_owner = false;
	struct dom_sid group_sid = { .num_auths = 0 };
	bool have_group = false;
	struct security_acl *dacl=NULL;
	int revision=1;

	while (next_token_talloc(ctx, &p, &tok, "\t,\r\n")) {
		if (strncmp(tok,"REVISION:", 9) == 0) {
			revision = strtol(tok+9, NULL, 16);
			continue;
		}

		if (strncmp(tok,"OWNER:", 6) == 0) {
			if (have_owner) {
				printf("Only specify owner once\n");
				goto done;
			}
			if (!StringToSid(cli, &owner_sid, tok+6)) {
				printf("Failed to parse owner sid\n");
				goto done;
			}
			have_owner = true;
			continue;
		}

		if (strncmp(tok,"GROUP:", 6) == 0) {
			if (have_group) {
				printf("Only specify group once\n");
				goto done;
			}
			if (!StringToSid(cli, &group_sid, tok+6)) {
				printf("Failed to parse group sid\n");
				goto done;
			}
			have_group = true;
			continue;
		}

		if (strncmp(tok,"ACL:", 4) == 0) {
			struct security_ace ace;
			if (!parse_ace(cli, &ace, tok+4)) {
				goto done;
			}
			if(!add_ace(&dacl, &ace)) {
				printf("Failed to add ACL %s\n", tok);
				goto done;
			}
			continue;
		}

		printf("Failed to parse token '%s' in security descriptor,\n", tok);
		goto done;
	}

	ret = make_sec_desc(
		ctx,
		revision,
		SEC_DESC_SELF_RELATIVE,
		have_owner ? &owner_sid : NULL,
		have_group ? &group_sid : NULL,
		NULL,
		dacl,
		&sd_size);

done:
	return ret;
}

/*****************************************************
get fileinfo for filename
*******************************************************/
static uint16_t get_fileinfo(struct cli_state *cli, const char *filename)
{
	uint16_t fnum = (uint16_t)-1;
	NTSTATUS status;
	struct smb_create_returns cr = {0};

	/* The desired access below is the only one I could find that works
	   with NT4, W2KP and Samba */

	status = cli_ntcreate(
		cli,			/* cli */
		filename,		/* fname */
		0,			/* CreatFlags */
		READ_CONTROL_ACCESS,	/* DesiredAccess */
		0,			/* FileAttributes */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE,	/* ShareAccess */
		FILE_OPEN,		/* CreateDisposition */
		0x0,			/* CreateOptions */
		0x0,			/* SecurityFlags */
		&fnum,			/* pfid */
		&cr);			/* cr */
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to open %s: %s\n", filename, nt_errstr(status));
		return 0;
	}

	cli_close(cli, fnum);
	return cr.file_attributes;
}

/*****************************************************
get sec desc for filename
*******************************************************/
static struct security_descriptor *get_secdesc_with_ctx(TALLOC_CTX *ctx,
							struct cli_state *cli,
							const char *filename)
{
	uint16_t fnum = (uint16_t)-1;
	struct security_descriptor *sd;
	NTSTATUS status;
	uint32_t sec_info;
	uint32_t desired_access = 0;

	if (query_sec_info == -1) {
		sec_info = SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL;
	} else {
		sec_info = query_sec_info;
	}

	if (sec_info & (SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL)) {
		desired_access |= SEC_STD_READ_CONTROL;
	}
	if (sec_info & SECINFO_SACL) {
		desired_access |= SEC_FLAG_SYSTEM_SECURITY;
	}

	if (desired_access == 0) {
		desired_access |= SEC_STD_READ_CONTROL;
	}

	status = cli_ntcreate(cli, filename, 0, desired_access,
			      0, FILE_SHARE_READ|FILE_SHARE_WRITE,
			      FILE_OPEN, 0x0, 0x0, &fnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to open %s: %s\n", filename, nt_errstr(status));
		return NULL;
	}

	status = cli_query_security_descriptor(cli, fnum, sec_info,
					       ctx, &sd);

	cli_close(cli, fnum);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to get security descriptor: %s\n",
		       nt_errstr(status));
		return NULL;
	}
        return sd;
}

static struct security_descriptor *get_secdesc(struct cli_state *cli,
					       const char *filename)
{
	return get_secdesc_with_ctx(talloc_tos(), cli, filename);
}
/*****************************************************
set sec desc for filename
*******************************************************/
static bool set_secdesc(struct cli_state *cli, const char *filename,
                        struct security_descriptor *sd)
{
	uint16_t fnum = (uint16_t)-1;
        bool result=true;
	NTSTATUS status;
	uint32_t desired_access = 0;
	uint32_t sec_info;

	if (set_sec_info == -1) {
		sec_info = 0;

		if (sd->dacl || (sd->type & SEC_DESC_DACL_PRESENT)) {
			sec_info |= SECINFO_DACL;
		}
		if (sd->sacl || (sd->type & SEC_DESC_SACL_PRESENT)) {
			sec_info |= SECINFO_SACL;
		}
		if (sd->owner_sid) {
			sec_info |= SECINFO_OWNER;
		}
		if (sd->group_sid) {
			sec_info |= SECINFO_GROUP;
		}
	} else {
		sec_info = set_sec_info;
	}

	/* Make the desired_access more specific. */
	if (sec_info & SECINFO_DACL) {
		desired_access |= SEC_STD_WRITE_DAC;
	}
	if (sec_info & SECINFO_SACL) {
		desired_access |= SEC_FLAG_SYSTEM_SECURITY;
	}
	if (sec_info & (SECINFO_OWNER | SECINFO_GROUP)) {
		desired_access |= SEC_STD_WRITE_OWNER;
	}

	status = cli_ntcreate(cli, filename, 0,
			      desired_access,
			      0, FILE_SHARE_READ|FILE_SHARE_WRITE,
			      FILE_OPEN, 0x0, 0x0, &fnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to open %s: %s\n", filename, nt_errstr(status));
		return false;
	}

	status = cli_set_security_descriptor(cli, fnum, sec_info, sd);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ERROR: security descriptor set failed: %s\n",
                       nt_errstr(status));
		result=false;
	}

	cli_close(cli, fnum);
	return result;
}

/*****************************************************
get maximum access for a file
*******************************************************/
static int cacl_mxac(struct cli_state *cli, const char *filename)
{
	NTSTATUS status;
	uint32_t mxac;

	status = cli_query_mxac(cli, filename, &mxac);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to get mxac: %s\n", nt_errstr(status));
		return EXIT_FAILED;
	}

	printf("Maximum access: 0x%x\n", mxac);

	return EXIT_OK;
}


/*****************************************************
dump the acls for a file
*******************************************************/
static int cacl_dump(struct cli_state *cli, const char *filename, bool numeric)
{
	struct security_descriptor *sd;
	int ret;

	if (test_args) {
		return EXIT_OK;
	}

	sd = get_secdesc(cli, filename);
	if (sd == NULL) {
		return EXIT_FAILED;
	}

	if (sddl) {
		char *str = sddl_encode(talloc_tos(), sd, get_domain_sid(cli));
		if (str == NULL) {
			return EXIT_FAILED;
		}
		printf("%s\n", str);
		TALLOC_FREE(str);
	} else {
		sec_desc_print(cli, stdout, sd, numeric);
	}

	if (want_mxac) {
		ret = cacl_mxac(cli, filename);
		if (ret != EXIT_OK) {
			return ret;
		}
	}

	return EXIT_OK;
}

/*****************************************************
Change the ownership or group ownership of a file. Just
because the NT docs say this can't be done :-). JRA.
*******************************************************/

static int owner_set(struct cli_state *cli, enum chown_mode change_mode,
			const char *filename, const char *new_username)
{
	struct dom_sid sid;
	struct security_descriptor *sd;
	size_t sd_size;

	if (!StringToSid(cli, &sid, new_username))
		return EXIT_PARSE_ERROR;

	sd = make_sec_desc(talloc_tos(),
			   SECURITY_DESCRIPTOR_REVISION_1,
			   SEC_DESC_SELF_RELATIVE,
			   (change_mode == REQUEST_CHOWN) ? &sid : NULL,
			   (change_mode == REQUEST_CHGRP) ? &sid : NULL,
			   NULL, NULL, &sd_size);

	if (!set_secdesc(cli, filename, sd)) {
		return EXIT_FAILED;
	}

	return EXIT_OK;
}


/* The MSDN is contradictory over the ordering of ACE entries in an
   ACL.  However NT4 gives a "The information may have been modified
   by a computer running Windows NT 5.0" if denied ACEs do not appear
   before allowed ACEs. At
   http://technet.microsoft.com/en-us/library/cc781716.aspx the
   canonical order is specified as "Explicit Deny, Explicit Allow,
   Inherited ACEs unchanged" */

static int ace_compare(struct security_ace *ace1, struct security_ace *ace2)
{
	if (security_ace_equal(ace1, ace2))
		return 0;

	if ((ace1->flags & SEC_ACE_FLAG_INHERITED_ACE) &&
			!(ace2->flags & SEC_ACE_FLAG_INHERITED_ACE))
		return 1;
	if (!(ace1->flags & SEC_ACE_FLAG_INHERITED_ACE) &&
			(ace2->flags & SEC_ACE_FLAG_INHERITED_ACE))
		return -1;
	if ((ace1->flags & SEC_ACE_FLAG_INHERITED_ACE) &&
			(ace2->flags & SEC_ACE_FLAG_INHERITED_ACE))
		return NUMERIC_CMP(ace2->type, ace1->type);

	if (ace1->type != ace2->type) {
		/* note the reverse order */
		return NUMERIC_CMP(ace2->type, ace1->type);
	}
	if (dom_sid_compare(&ace1->trustee, &ace2->trustee))
		return dom_sid_compare(&ace1->trustee, &ace2->trustee);

	if (ace1->flags != ace2->flags)
		return NUMERIC_CMP(ace1->flags, ace2->flags);

	if (ace1->access_mask != ace2->access_mask)
		return NUMERIC_CMP(ace1->access_mask, ace2->access_mask);

	if (ace1->size != ace2->size)
		return NUMERIC_CMP(ace1->size, ace2->size);

	return memcmp(ace1, ace2, sizeof(struct security_ace));
}

static void sort_acl(struct security_acl *the_acl)
{
	uint32_t i;
	if (!the_acl) return;

	TYPESAFE_QSORT(the_acl->aces, the_acl->num_aces, ace_compare);

	for (i=1;i<the_acl->num_aces;) {
		if (security_ace_equal(&the_acl->aces[i-1],
				       &the_acl->aces[i])) {
			ARRAY_DEL_ELEMENT(
				the_acl->aces, i, the_acl->num_aces);
			the_acl->num_aces--;
		} else {
			i++;
		}
	}
}

/*****************************************************
set the ACLs on a file given a security descriptor
*******************************************************/

static int cacl_set_from_sd(struct cli_state *cli, const char *filename,
			    struct security_descriptor *sd, enum acl_mode mode,
			    bool numeric)
{
	struct security_descriptor *old = NULL;
	uint32_t i, j;
	size_t sd_size;
	int result = EXIT_OK;

	if (!sd) return EXIT_PARSE_ERROR;
	if (test_args) return EXIT_OK;

	if (mode != SMB_ACL_SET) {
		/*
		 * Do not fetch old ACL when it will be overwritten
		 * completely with a new one.
		 */
		old = get_secdesc(cli, filename);

		if (!old) {
			return EXIT_FAILED;
		}
	}

	/* the logic here is rather more complex than I would like */
	switch (mode) {
	case SMB_ACL_DELETE:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			bool found = False;

			for (j=0;old->dacl && j<old->dacl->num_aces;j++) {
				if (security_ace_equal(&sd->dacl->aces[i],
						       &old->dacl->aces[j])) {
					uint32_t k;
					for (k=j; k<old->dacl->num_aces-1;k++) {
						old->dacl->aces[k] = old->dacl->aces[k+1];
					}
					old->dacl->num_aces--;
					found = True;
					break;
				}
			}

			if (!found) {
				printf("ACL for ACE:");
				print_ace(cli, stdout, &sd->dacl->aces[i],
					  numeric);
				printf(" not found\n");
			}
		}
		break;

	case SMB_ACL_MODIFY:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			bool found = False;

			for (j=0;old->dacl && j<old->dacl->num_aces;j++) {
				if (dom_sid_equal(&sd->dacl->aces[i].trustee,
					      &old->dacl->aces[j].trustee)) {
					old->dacl->aces[j] = sd->dacl->aces[i];
					found = True;
				}
			}

			if (!found) {
				fstring str;

				SidToString(cli, str,
					    &sd->dacl->aces[i].trustee,
					    numeric);
				printf("ACL for SID %s not found\n", str);
			}
		}

		if (sd->owner_sid) {
			old->owner_sid = sd->owner_sid;
		}

		if (sd->group_sid) {
			old->group_sid = sd->group_sid;
		}

		break;

	case SMB_ACL_ADD:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			add_ace(&old->dacl, &sd->dacl->aces[i]);
		}
		break;

	case SMB_ACL_SET:
 		old = sd;
		break;
	}

	/* Denied ACE entries must come before allowed ones */
	sort_acl(old->dacl);

	/* Create new security descriptor and set it */

	/* We used to just have "WRITE_DAC_ACCESS" without WRITE_OWNER.
	   But if we're sending an owner, even if it's the same as the one
	   that already exists then W2K3 insists we open with WRITE_OWNER access.
	   I need to check that setting a SD with no owner set works against WNT
	   and W2K. JRA.
	*/

	sd = make_sec_desc(talloc_tos(),old->revision, old->type,
			   old->owner_sid, old->group_sid,
			   NULL, old->dacl, &sd_size);

	if (!set_secdesc(cli, filename, sd)) {
		result = EXIT_FAILED;
	}

	return result;
}

/*****************************************************
set the ACLs on a file given an ascii description
*******************************************************/

static int cacl_set(struct cli_state *cli, const char *filename,
		    char *the_acl, enum acl_mode mode, bool numeric)
{
	struct security_descriptor *sd = NULL;

	if (sddl) {
		const char *msg = NULL;
		size_t msg_offset = 0;
		enum ace_condition_flags flags =
			ACE_CONDITION_FLAG_ALLOW_DEVICE;
		sd = sddl_decode_err_msg(talloc_tos(),
					the_acl,
					get_domain_sid(cli),
					flags,
					&msg,
					&msg_offset);
		if (sd == NULL) {
			DBG_ERR("could not decode '%s'\n", the_acl);
			if (msg != NULL) {
				DBG_ERR("                  %*c\n",
					(int)msg_offset, '^');
				DBG_ERR("error '%s'\n", msg);
			}
		}
	} else {
		sd = sec_desc_parse(talloc_tos(), cli, the_acl);
	}

	if (sd == NULL) {
		return EXIT_PARSE_ERROR;
	}
	if (test_args) {
		return EXIT_OK;
	}
	return cacl_set_from_sd(cli, filename, sd, mode, numeric);
}

/*****************************************************
set the inherit on a file
*******************************************************/
static int inherit(struct cli_state *cli, const char *filename,
                   const char *type)
{
	struct security_descriptor *old,*sd;
	uint32_t oldattr;
	size_t sd_size;
	int result = EXIT_OK;

	old = get_secdesc(cli, filename);

	if (!old) {
		return EXIT_FAILED;
	}

        oldattr = get_fileinfo(cli,filename);

	if (strcmp(type,"allow")==0) {
		if ((old->type & SEC_DESC_DACL_PROTECTED) ==
                    SEC_DESC_DACL_PROTECTED) {
			uint32_t i;
			char *parentname,*temp;
			struct security_descriptor *parent;
			temp = talloc_strdup(talloc_tos(), filename);

			old->type=old->type & (~SEC_DESC_DACL_PROTECTED);

			/* look at parent and copy in all its inheritable ACL's. */
			string_replace(temp, '\\', '/');
			if (!parent_dirname(talloc_tos(),temp,&parentname,NULL)) {
				return EXIT_FAILED;
			}
			string_replace(parentname, '/', '\\');
			parent = get_secdesc(cli,parentname);
			if (parent == NULL) {
				return EXIT_FAILED;
			}
			for (i=0;i<parent->dacl->num_aces;i++) {
				struct security_ace *ace=&parent->dacl->aces[i];
				/* Add inherited flag to all aces */
				ace->flags=ace->flags|
				           SEC_ACE_FLAG_INHERITED_ACE;
				if ((oldattr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) {
					if ((ace->flags & SEC_ACE_FLAG_CONTAINER_INHERIT) ==
					    SEC_ACE_FLAG_CONTAINER_INHERIT) {
						add_ace(&old->dacl, ace);
					}
				} else {
					if ((ace->flags & SEC_ACE_FLAG_OBJECT_INHERIT) ==
					    SEC_ACE_FLAG_OBJECT_INHERIT) {
						/* clear flags for files */
						ace->flags=0;
						add_ace(&old->dacl, ace);
					}
				}
			}
                } else {
			printf("Already set to inheritable permissions.\n");
			return EXIT_FAILED;
                }
	} else if (strcmp(type,"remove")==0) {
		if ((old->type & SEC_DESC_DACL_PROTECTED) !=
                    SEC_DESC_DACL_PROTECTED) {
			old->type=old->type | SEC_DESC_DACL_PROTECTED;

			/* remove all inherited ACL's. */
			if (old->dacl) {
				int i;
				struct security_acl *temp=old->dacl;
				old->dacl=make_sec_acl(talloc_tos(), 3, 0, NULL);
				for (i=temp->num_aces-1;i>=0;i--) {
					struct security_ace *ace=&temp->aces[i];
					/* Remove all ace with INHERITED flag set */
					if ((ace->flags & SEC_ACE_FLAG_INHERITED_ACE) !=
					    SEC_ACE_FLAG_INHERITED_ACE) {
						add_ace(&old->dacl,ace);
					}
				}
			}
                } else {
			printf("Already set to no inheritable permissions.\n");
			return EXIT_FAILED;
                }
	} else if (strcmp(type,"copy")==0) {
		if ((old->type & SEC_DESC_DACL_PROTECTED) !=
                    SEC_DESC_DACL_PROTECTED) {
			old->type=old->type | SEC_DESC_DACL_PROTECTED;

			/*
			 * convert all inherited ACL's to non
			 * inherited ACL's.
			 */
			if (old->dacl) {
				uint32_t i;
				for (i=0;i<old->dacl->num_aces;i++) {
					struct security_ace *ace=&old->dacl->aces[i];
					/* Remove INHERITED FLAG from all aces */
					ace->flags=ace->flags&(~SEC_ACE_FLAG_INHERITED_ACE);
				}
			}
                } else {
			printf("Already set to no inheritable permissions.\n");
			return EXIT_FAILED;
                }
	}

	/* Denied ACE entries must come before allowed ones */
	sort_acl(old->dacl);

	sd = make_sec_desc(talloc_tos(),old->revision, old->type,
			   old->owner_sid, old->group_sid,
			   NULL, old->dacl, &sd_size);

	if (!set_secdesc(cli, filename, sd)) {
		result = EXIT_FAILED;
	}

	return result;
}

/*****************************************************
 Return a connection to a server.
*******************************************************/
static struct cli_state *connect_one(struct cli_credentials *creds,
				     const char *server, const char *share)
{
	struct cli_state *c = NULL;
	NTSTATUS nt_status;
	uint32_t flags = 0;
	struct smb_transports ts =
		smb_transports_parse("client smb transports",
				     lp_client_smb_transports());

	nt_status = cli_full_connection_creds(talloc_tos(),
					      &c,
					      lp_netbios_name(),
					      server,
					      NULL,
					      &ts,
					      share,
					      "?????",
					      creds,
					      flags);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("cli_full_connection failed! (%s)\n", nt_errstr(nt_status)));
		return NULL;
	}

	return c;
}

/*
 * Process resulting combination of mask & fname ensuring
 * terminated with wildcard
 */
static char *build_dirname(TALLOC_CTX *ctx,
	const char *mask, char *dir, char *fname)
{
	char *mask2 = NULL;
	char *p = NULL;

	mask2 = talloc_strdup(ctx, mask);
	if (!mask2) {
		return NULL;
	}
	p = strrchr_m(mask2, DIRSEP_CHAR);
	if (p) {
		p[1] = 0;
	} else {
		mask2[0] = '\0';
	}
	mask2 = talloc_asprintf_append(mask2,
				"%s\\*",
				fname);
	return mask2;
}

/*
 * Returns a copy of the ACL flags in ace modified according
 * to some inheritance rules.
 *   a) SEC_ACE_FLAG_INHERITED_ACE is propagated to children
 *   b) SEC_ACE_FLAG_INHERIT_ONLY is set on container children for OI (only)
 *   c) SEC_ACE_FLAG_OBJECT_INHERIT & SEC_ACE_FLAG_CONTAINER_INHERIT are
 *      stripped from flags to be propagated to non-container children
 *   d) SEC_ACE_FLAG_OBJECT_INHERIT & SEC_ACE_FLAG_CONTAINER_INHERIT are
 *      stripped from flags to be propagated if the NP flag
 *      SEC_ACE_FLAG_NO_PROPAGATE_INHERIT is present
 */

static uint8_t get_flags_to_propagate(bool is_container,
				struct security_ace *ace)
{
	uint8_t newflags = ace->flags;
	/* OBJECT inheritance */
	bool acl_objinherit = (ace->flags &
		SEC_ACE_FLAG_OBJECT_INHERIT) == SEC_ACE_FLAG_OBJECT_INHERIT;
	/* CONTAINER inheritance */
	bool acl_cntrinherit = (ace->flags &
		SEC_ACE_FLAG_CONTAINER_INHERIT) ==
			SEC_ACE_FLAG_CONTAINER_INHERIT;
	/* PROHIBIT inheritance */
	bool prohibit_inheritance = ((ace->flags &
		SEC_ACE_FLAG_NO_PROPAGATE_INHERIT) ==
			SEC_ACE_FLAG_NO_PROPAGATE_INHERIT);

	/* Assume we are not propagating the ACE */

	newflags &= ~SEC_ACE_FLAG_INHERITED_ACE;

	/* Inherit-only flag is not propagated to children */

	newflags &= ~SEC_ACE_FLAG_INHERIT_ONLY;
	/* all children need to have the SEC_ACE_FLAG_INHERITED_ACE set */
	if (acl_cntrinherit || acl_objinherit) {
		/*
		 * object inherit ( alone ) on a container needs
		 * SEC_ACE_FLAG_INHERIT_ONLY
		 */
		if (is_container) {
			if (acl_objinherit && !acl_cntrinherit) {
				newflags |= SEC_ACE_FLAG_INHERIT_ONLY;
			}
			/*
			 * this is tricky, the only time we would not
			 * propagate the ace for a container is if
			 * prohibit_inheritance is set and object inheritance
			 * alone is set
			 */
			if ((prohibit_inheritance
			    && acl_objinherit
			    && !acl_cntrinherit) == false) {
				newflags |= SEC_ACE_FLAG_INHERITED_ACE;
			}
		} else {
			/*
			 * don't apply object/container inheritance flags to
			 * non dirs
			 */
			newflags &= ~(SEC_ACE_FLAG_OBJECT_INHERIT
					| SEC_ACE_FLAG_CONTAINER_INHERIT
					| SEC_ACE_FLAG_INHERIT_ONLY);
			/*
			 * only apply ace to file if object inherit
			 */
			if (acl_objinherit) {
				newflags |= SEC_ACE_FLAG_INHERITED_ACE;
			}
		}

		/* if NP is specified strip NP and all OI/CI INHERIT flags */
		if (prohibit_inheritance) {
			newflags &= ~(SEC_ACE_FLAG_OBJECT_INHERIT
					| SEC_ACE_FLAG_CONTAINER_INHERIT
					| SEC_ACE_FLAG_INHERIT_ONLY
					| SEC_ACE_FLAG_NO_PROPAGATE_INHERIT);
		}
	}
	return newflags;
}

/*
 * This function builds a new acl for 'caclfile', first it removes any
 * existing inheritable ace(s) from the current acl of caclfile, secondly it
 * applies any inheritable acls of the parent of caclfile ( inheritable acls of
 * caclfile's parent are passed via acl_to_add member of cbstate )
 *
 */
static NTSTATUS propagate_inherited_aces(char *caclfile,
			struct cacl_callback_state *cbstate)
{
	TALLOC_CTX *aclctx = NULL;
	NTSTATUS status;
	int result;
	int fileattr;
	struct security_descriptor *old = NULL;
	bool is_container = false;
	struct security_acl *acl_to_add = cbstate->acl_to_add;
	struct security_acl *acl_to_remove = NULL;
	uint32_t i, j;

	aclctx = talloc_new(NULL);
	if (aclctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	old = get_secdesc_with_ctx(aclctx, cbstate->cli, caclfile);

	if (!old) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	/* inhibit propagation? */
	if ((old->type & SEC_DESC_DACL_PROTECTED) ==
		SEC_DESC_DACL_PROTECTED){
		status = NT_STATUS_OK;
		goto out;
	}

	fileattr = get_fileinfo(cbstate->cli, caclfile);
	is_container = (fileattr & FILE_ATTRIBUTE_DIRECTORY);

	/* find acl(s) that are inherited */
	for (j = 0; old->dacl && j < old->dacl->num_aces; j++) {

		if (old->dacl->aces[j].flags & SEC_ACE_FLAG_INHERITED_ACE) {
			if (!add_ace_with_ctx(aclctx, &acl_to_remove,
					      &old->dacl->aces[j])) {
				status = NT_STATUS_NO_MEMORY;
				goto out;
			}
		}
	}

	/* remove any acl(s) that are inherited */
	if (acl_to_remove) {
		for (i = 0; i < acl_to_remove->num_aces; i++) {
			struct security_ace ace = acl_to_remove->aces[i];
			for (j = 0; old->dacl && j < old->dacl->num_aces; j++) {

				if (security_ace_equal(&ace,
						  &old->dacl->aces[j])) {
					uint32_t k;
					for (k = j; k < old->dacl->num_aces-1;
						k++) {
						old->dacl->aces[k] =
							old->dacl->aces[k+1];
					}
					old->dacl->num_aces--;
					break;
				}
			}
		}
	}
	/* propagate any inheritable ace to be added */
	if (acl_to_add) {
		for (i = 0; i < acl_to_add->num_aces; i++) {
			struct security_ace ace = acl_to_add->aces[i];
			bool is_objectinherit = (ace.flags &
				SEC_ACE_FLAG_OBJECT_INHERIT) ==
					SEC_ACE_FLAG_OBJECT_INHERIT;
			bool is_inherited;
			/* don't propagate flags to a file unless OI */
			if (!is_objectinherit && !is_container) {
				continue;
			}
			/*
			 * adjust flags according to inheritance
			 * rules
			 */
			ace.flags = get_flags_to_propagate(is_container, &ace);
			is_inherited = (ace.flags &
				SEC_ACE_FLAG_INHERITED_ACE) ==
					SEC_ACE_FLAG_INHERITED_ACE;
			/* don't propagate non inherited flags */
			if (!is_inherited) {
				continue;
			}
			if (!add_ace_with_ctx(aclctx, &old->dacl, &ace)) {
				status = NT_STATUS_NO_MEMORY;
				goto out;
			}
		}
	}

	result = cacl_set_from_sd(cbstate->cli, caclfile,
				  old,
				  SMB_ACL_SET, cbstate->numeric);
	if (result != EXIT_OK) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	status = NT_STATUS_OK;
out:
	TALLOC_FREE(aclctx);
	return status;
}

/*
 * Returns true if 'ace' contains SEC_ACE_FLAG_OBJECT_INHERIT or
 * SEC_ACE_FLAG_CONTAINER_INHERIT
 */
static bool is_inheritable_ace(struct security_ace *ace)
{
	uint8_t flags = ace->flags;
	if (flags & (SEC_ACE_FLAG_OBJECT_INHERIT
			| SEC_ACE_FLAG_CONTAINER_INHERIT)) {
		return true;
	}
	return false;
}

/* This method does some basic sanity checking with respect to automatic
 * inheritance. e.g. it checks if it is possible to do a set, it detects illegal
 * attempts to set inherited permissions directly. Additionally this method
 * does some basic initialisation for instance it parses the ACL passed on the
 * command line.
 */
static NTSTATUS prepare_inheritance_propagation(TALLOC_CTX *ctx, char *filename,
			struct cacl_callback_state *cbstate)
{
	NTSTATUS result;
	char *the_acl = cbstate->the_acl;
	struct cli_state *cli = cbstate->cli;
	enum acl_mode mode = cbstate->mode;
	struct security_descriptor *sd = NULL;
	struct security_descriptor *old = NULL;
	uint32_t j;
	bool propagate = false;

	old = get_secdesc_with_ctx(ctx, cli, filename);
	if (old == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* parse acl passed on the command line */
	if (sddl) {
		const char *msg = NULL;
		size_t msg_offset = 0;
		enum ace_condition_flags flags =
			ACE_CONDITION_FLAG_ALLOW_DEVICE;

		cbstate->aclsd = sddl_decode_err_msg(ctx,
						     the_acl,
						     get_domain_sid(cli),
						     flags,
						     &msg,
						     &msg_offset);
		if (cbstate->aclsd == NULL) {
			DBG_ERR("could not decode '%s'\n", the_acl);
			if (msg != NULL) {
				DBG_ERR("                  %*c\n",
					(int)msg_offset, '^');
				DBG_ERR("error '%s'\n", msg);
			}
		}
	} else {
		cbstate->aclsd = sec_desc_parse(ctx, cli, the_acl);
	}

	if (!cbstate->aclsd) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	sd = cbstate->aclsd;

	/* set operation if inheritance is enabled doesn't make sense */
	if (mode == SMB_ACL_SET && ((old->type & SEC_DESC_DACL_PROTECTED) !=
		SEC_DESC_DACL_PROTECTED)){
		d_printf("Inheritance enabled at %s, can't apply set operation\n",filename);
		result = NT_STATUS_UNSUCCESSFUL;
		goto out;

	}

	/*
	 * search command line acl for any illegal SEC_ACE_FLAG_INHERITED_ACE
	 * flags that are set
	 */
	for (j = 0; sd->dacl && j < sd->dacl->num_aces; j++) {
		struct security_ace *ace = &sd->dacl->aces[j];
		if (ace->flags & SEC_ACE_FLAG_INHERITED_ACE) {
			d_printf("Illegal parameter %s\n", the_acl);
			result = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
		if (!propagate) {
			if (is_inheritable_ace(ace)) {
				propagate = true;
			}
		}
	}

	result = NT_STATUS_OK;
out:
	cbstate->acl_no_propagate = !propagate;
	return result;
}

/*
 * This method builds inheritable ace(s) from filename (which should be
 * a container) that need propagating to children in order to provide
 * automatic inheritance. Those inheritable ace(s) are stored in
 * acl_to_add member of cbstate for later processing
 * (see propagate_inherited_aces)
 */
static NTSTATUS get_inheritable_aces(TALLOC_CTX *ctx, char *filename,
			struct cacl_callback_state *cbstate)
{
	NTSTATUS result;
	struct cli_state *cli = NULL;
	struct security_descriptor *sd = NULL;
	struct security_acl *acl_to_add = NULL;
	uint32_t j;

	cli = cbstate->cli;
	sd = get_secdesc_with_ctx(ctx, cli, filename);

	if (sd == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Check if any inheritance related flags are used, if not then
	 * nothing to do. At the same time populate acls for inheritance
	 * related ace(s) that need to be added to or deleted from children as
	 * a result of inheritance propagation.
	 */

	for (j = 0; sd->dacl && j < sd->dacl->num_aces; j++) {
		struct security_ace *ace = &sd->dacl->aces[j];
		if (is_inheritable_ace(ace)) {
			bool added = add_ace_with_ctx(ctx, &acl_to_add, ace);
			if (!added) {
				result = NT_STATUS_NO_MEMORY;
				goto out;
			}
		}
	}
	cbstate->acl_to_add = acl_to_add;
	result = NT_STATUS_OK;
out:
	return result;
}

/*
 * Callback handler to handle child elements processed by cli_list,  we attempt
 * to propagate inheritable ace(s) to each child via the function
 * propagate_inherited_aces. Children that are themselves directories are passed
 * to cli_list again ( to descend the directory structure )
 */
static NTSTATUS cacl_set_cb(struct file_info *f,
			   const char *mask, void *state)
{
	struct cacl_callback_state *cbstate =
		(struct cacl_callback_state *)state;
	struct cli_state *cli = NULL;
	struct cli_credentials *creds = NULL;

	TALLOC_CTX *dirctx = NULL;
	NTSTATUS status;
	struct cli_state *targetcli = NULL;

	char *dir = NULL;
	char *dir_end = NULL;
	char *mask2 = NULL;
	char *targetpath = NULL;
	char *caclfile = NULL;

	dirctx = talloc_new(NULL);
	if (!dirctx) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	cli = cbstate->cli;
	creds = cbstate->creds;

	/* Work out the directory. */
	dir = talloc_strdup(dirctx, mask);
	if (!dir) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	dir_end = strrchr(dir, DIRSEP_CHAR);
	if (dir_end != NULL) {
		*dir_end = '\0';
	}

	if (!f->name || !f->name[0]) {
		d_printf("Empty dir name returned. Possible server misconfiguration.\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	if (f->attr & FILE_ATTRIBUTE_DIRECTORY) {
		struct cacl_callback_state dir_cbstate;
		uint16_t attribute = FILE_ATTRIBUTE_DIRECTORY
			| FILE_ATTRIBUTE_SYSTEM
			| FILE_ATTRIBUTE_HIDDEN;
		dir_end = NULL;

		/* ignore special '.' & '..' */
		if ((f->name == NULL) || ISDOT(f->name) || ISDOTDOT(f->name)) {
			status = NT_STATUS_OK;
			goto out;
		}

		mask2 = build_dirname(dirctx, mask, dir, f->name);
		if (mask2 == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		/* check for dfs */
		status = cli_resolve_path(dirctx, "", creds, cli,
			mask2, &targetcli, &targetpath);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		/*
		 * prepare path to caclfile, remove any existing wildcard
		 * chars and convert path separators.
		 */

		caclfile = talloc_strdup(dirctx, targetpath);
		if (!caclfile) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
		dir_end = strrchr(caclfile, '*');
		if (dir_end != NULL) {
			*dir_end = '\0';
		}

		string_replace(caclfile, '/', '\\');
		/*
		 * make directory specific copy of cbstate here
		 * (for this directory level) to be available as
		 * the parent cbstate for the children of this directory.
		 * Note: cbstate is overwritten for the current file being
		 *       processed.
		 */
		dir_cbstate = *cbstate;
		dir_cbstate.cli = targetcli;

		/*
		 * propagate any inherited ace from our parent
		 */
		status = propagate_inherited_aces(caclfile, &dir_cbstate);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		/*
		 * get inheritable ace(s) for this dir/container
		 * that will be propagated to its children
		 */
		status = get_inheritable_aces(dirctx, caclfile,
						      &dir_cbstate);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		/*
		 * ensure cacl_set_cb gets called for children
		 * of this directory (targetpath)
		 */
		status = cli_list(targetcli, targetpath,
			attribute, cacl_set_cb,
			(void *)&dir_cbstate);

		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

	} else {
		/*
		 * build full path to caclfile and replace '/' with '\' so
		 * other utility functions can deal with it
		 */

		targetpath = talloc_asprintf(dirctx, "%s/%s", dir, f->name);
		if (!targetpath) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
		string_replace(targetpath, '/', '\\');

		/* attempt to propagate any inherited ace to file caclfile */
		status = propagate_inherited_aces(targetpath, cbstate);

		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}
	status = NT_STATUS_OK;
out:
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("error %s: processing %s\n",
			nt_errstr(status),
			targetpath);
	}
	TALLOC_FREE(dirctx);
	return status;
}


/*
 * Wrapper around cl_list to descend the directory tree pointed to by 'filename',
 * helper callback function 'cacl_set_cb' handles the child elements processed
 * by cli_list.
 */
static int inheritance_cacl_set(char *filename,
			struct cacl_callback_state *cbstate)
{
	int result;
	NTSTATUS ntstatus;
	int fileattr;
	char *mask = NULL;
	struct cli_state *cli = cbstate->cli;
	TALLOC_CTX *ctx = NULL;
	bool isdirectory = false;
	uint16_t attribute = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM
				| FILE_ATTRIBUTE_HIDDEN;
	ctx = talloc_init("inherit_set");
	if (ctx == NULL) {
		d_printf("out of memory\n");
		result = EXIT_FAILED;
		goto out;
	}

	/* ensure we have a filename that starts with '\' */
	if (!filename || *filename != DIRSEP_CHAR) {
		/* illegal or no filename */
		result = EXIT_FAILED;
		d_printf("illegal or missing name '%s'\n", filename);
		goto out;
	}


	fileattr = get_fileinfo(cli, filename);
	isdirectory = (fileattr & FILE_ATTRIBUTE_DIRECTORY)
		== FILE_ATTRIBUTE_DIRECTORY;

	/*
	 * if we've got as far as here then we have already evaluated
	 * the args.
	 */
	if (test_args) {
		result = EXIT_OK;
		goto out;
	}

	mask = NULL;
	/* make sure we have a trailing '\*' for directory */
	if (!isdirectory) {
		mask = talloc_strdup(ctx, filename);
	} else if (strlen(filename) > 1) {
		/*
		 * if the passed file name doesn't have a trailing '\'
		 * append it.
		 */
		char *name_end = strrchr(filename, DIRSEP_CHAR);
		if (name_end != filename + strlen(filename) + 1) {
			mask = talloc_asprintf(ctx, "%s\\*", filename);
		} else {
			mask = talloc_strdup(ctx, filename);
		}
	} else {
		/* filename is a single '\', just append '*' */
		mask = talloc_asprintf_append(mask, "%s*", filename);
	}

	if (!mask) {
		result = EXIT_FAILED;
		goto out;
	}

	/*
	 * prepare for automatic propagation of the acl passed on the
	 * cmdline.
	 */

	ntstatus = prepare_inheritance_propagation(ctx, filename,
							   cbstate);
	if (!NT_STATUS_IS_OK(ntstatus)) {
		d_printf("error: %s processing %s\n",
			 nt_errstr(ntstatus), filename);
		result = EXIT_FAILED;
		goto out;
	}

	result = cacl_set_from_sd(cli, filename, cbstate->aclsd,
				cbstate->mode, cbstate->numeric);

	/*
	 * strictly speaking it could be considered an error if a file was
	 * specified with '--propagate-inheritance'. However we really want
	 * to eventually get rid of '--propagate-inheritance' so we will be
	 * more forgiving here and instead just exit early.
	 */
	if (!isdirectory || (result != EXIT_OK)) {
		goto out;
	}

	/* check if there is actually any need to propagate */
	if (cbstate->acl_no_propagate) {
		goto out;
	}
	/* get inheritable attributes this parent container (e.g. filename) */
	ntstatus = get_inheritable_aces(ctx, filename, cbstate);
	if (NT_STATUS_IS_OK(ntstatus)) {
		/* process children */
		ntstatus = cli_list(cli, mask, attribute,
				cacl_set_cb,
				(void *)cbstate);
	}

	if (!NT_STATUS_IS_OK(ntstatus)) {
		d_printf("error: %s processing %s\n",
			 nt_errstr(ntstatus), filename);
		result = EXIT_FAILED;
		goto out;
	}

out:
	TALLOC_FREE(ctx);
	return result;
}

struct diritem {
       struct diritem *prev, *next;
       /*
	* dirname and targetpath below are sanitized,
	* e.g.
	*   + start and end with '\'
	*   + have no trailing '*'
	*   + all '/' have been converted to '\'
	*/
       char *dirname;
       char  *targetpath;
       struct cli_state *targetcli;
};

struct save_restore_stats
{
	int success;
	int failure;
};

struct dump_context {
	struct diritem *list;
	struct cli_credentials *creds;
	struct cli_state *cli;
	struct save_restore_stats *stats;
	int save_fd;
	struct diritem *dir;
	NTSTATUS status;
};

static int write_dacl(struct dump_context *ctx,
		      struct cli_state *cli,
		      const char *filename,
		      const char *origfname)
{
	struct security_descriptor *sd = NULL;
	char *str = NULL;
	const char *output_fmt = "%s\r\n%s\r\n";
	const char *tmp = NULL;
	char *out_str = NULL;
	uint8_t *dest = NULL;
	ssize_t s_len;
	size_t d_len;
	bool ok;
	int result;
	TALLOC_CTX *frame = talloc_stackframe();

	if (test_args) {
		return EXIT_OK;
	}

	if (ctx->save_fd < 0) {
		DBG_ERR("error processing %s no file descriptor\n", filename);
		result = EXIT_FAILED;
		goto out;
	}

	sd = get_secdesc(cli, filename);
	if (sd == NULL) {
		result = EXIT_FAILED;
		goto out;
	}

	sd->owner_sid = NULL;
	sd->group_sid = NULL;

	str = sddl_encode(frame, sd, get_domain_sid(cli));
	if (str == NULL) {
		DBG_ERR("error processing %s couldn't encode DACL\n", filename);
		result = EXIT_FAILED;
		goto out;
	}
	/*
	 * format of icacls save file is
	 * a line containing the path of the file/dir
	 * followed by a line containing the sddl format
	 * of the dacl.
	 * The format of the strings are null terminated
	 * 16-bit Unicode. Each line is terminated by "\r\n"
	 */

	tmp = origfname;
	/* skip leading '\' */
	if (tmp[0] == '\\') {
		tmp++;
	}
	out_str = talloc_asprintf(frame, output_fmt, tmp, str);

	if (out_str == NULL) {
		result = EXIT_FAILED;
		goto out;
	}

	s_len = strlen(out_str);

	ok = convert_string_talloc(out_str,
				   CH_UNIX,
				   CH_UTF16,
				   out_str,
				   s_len, (void **)(void *)&dest, &d_len);
	if (!ok) {
		DBG_ERR("error processing %s out of memory\n", tmp);
		result = EXIT_FAILED;
		goto out;
	}

	if (write(ctx->save_fd, dest, d_len) != d_len) {
		DBG_ERR("error processing %s failed to write to file.\n", tmp);
		result = EXIT_FAILED;
		goto out;
	}
	fsync(ctx->save_fd);

	result = EXIT_OK;
	ctx->stats->success += 1;
	fprintf(stdout, "Successfully processed file: %s\n", tmp);
out:
	TALLOC_FREE(frame);
	if (result != EXIT_OK) {
		ctx->stats->failure += 1;
	}
	return result;
}

/*
 * Sanitize directory name.
 * Given a directory name 'dir' ensure it;
 *    o starts with '\'
 *    o ends with '\'
 *    o doesn't end with trailing '*'
 *    o ensure all '/' are converted to '\'
 */

static char *sanitize_dirname(TALLOC_CTX *ctx,
			 const char *dir)
{
	char *mask = NULL;
	char *name_end = NULL;

	mask = talloc_strdup(ctx, dir);
	name_end = strrchr(mask, '*');
	if (name_end) {
		*name_end = '\0';
	}

	name_end = strrchr(mask, DIRSEP_CHAR);

	if (strlen(mask) > 0 && name_end != mask + (strlen(mask) - 1)) {
		mask = talloc_asprintf(ctx, "%s\\", mask);
	}

	string_replace(mask, '/', '\\');
	return mask;
}

/*
 * Process each entry (child) of a directory.
 * Each entry, regardless of whether it is itself a file or directory
 * has it's dacl written to the restore/save file.
 * Each directory is saved to context->list (for further processing)
 * write_dacl will update the stats (success/fail)
 */
static NTSTATUS cacl_dump_dacl_cb(struct file_info *f,
				  const char *mask, void *state)
{
	struct dump_context *ctx = talloc_get_type_abort(state,
							 struct dump_context);

	NTSTATUS status;

	char *mask2 = NULL;
	char *targetpath = NULL;
	char *unresolved = NULL;

	/*
	 * if we have already encountered an error
	 * bail out
	 */
	if (!NT_STATUS_IS_OK(ctx->status)) {
		return ctx->status;
	}

	if (!f->name || !f->name[0]) {
		DBG_ERR("Empty dir name returned. Possible server "
			"misconfiguration.\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	mask2 = sanitize_dirname(ctx, mask);
	if (!mask2) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	if (f->attr & FILE_ATTRIBUTE_DIRECTORY) {
		struct diritem *item = NULL;

		/* ignore special '.' & '..' */
		if ((f->name == NULL) || ISDOT(f->name) || ISDOTDOT(f->name)) {
			status = NT_STATUS_OK;
			goto out;
		}

		/* Work out the directory. */
		unresolved = sanitize_dirname(ctx, ctx->dir->dirname);
		if (!unresolved) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		unresolved = talloc_asprintf(ctx, "%s%s", unresolved, f->name);

		if (unresolved == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		item = talloc_zero(ctx, struct diritem);
		if (item == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		item->dirname = unresolved;

		mask2 = talloc_asprintf(ctx, "%s%s", mask2, f->name);
		if (!mask2) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		status = cli_resolve_path(ctx, "", ctx->creds, ctx->cli,
					  mask2, &item->targetcli, &targetpath);

		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("error failed to resolve: %s\n",
				nt_errstr(status));
			goto out;
		}

		item->targetpath = sanitize_dirname(ctx, targetpath);
		if (!item->targetpath) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		if (write_dacl(ctx,
			       item->targetcli,
			       item->targetpath, unresolved) != EXIT_OK) {
			status = NT_STATUS_UNSUCCESSFUL;
			/*
			 * cli_list happily ignores error encountered
			 * when processing the callback so we need
			 * to save any error status encountered while
			 * processing directories (so we can stop recursing
			 * those as soon as possible).
			 * Changing the current behaviour of the callback
			 * handling by cli_list would be I think be too
			 * risky.
			 */
			ctx->status = status;
			goto out;
		}

		DLIST_ADD_END(ctx->list, item);

	} else {
		unresolved = sanitize_dirname(ctx, ctx->dir->dirname);
		if (!unresolved) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		unresolved = talloc_asprintf(ctx, "%s%s", unresolved, f->name);

		if (!unresolved) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
		/*
		 * build full path to the file and replace '/' with '\' so
		 * other utility functions can deal with it
		 */

		targetpath = talloc_asprintf(ctx, "%s%s", mask2, f->name);

		if (!targetpath) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		if (write_dacl(ctx,
			       ctx->dir->targetcli,
			       targetpath, unresolved) != EXIT_OK) {
			status = NT_STATUS_UNSUCCESSFUL;
			/*
			 * cli_list happily ignores error encountered
			 * when processing the callback so we need
			 * to save any error status encountered while
			 * processing directories (so we can stop recursing
			 * those as soon as possible).
			 * Changing the current behaviour of the callback
			 * handling by cli_list would be I think be too
			 * risky.
			 */
			ctx->status = status;
			goto out;
		}
	}
	status = NT_STATUS_OK;
out:
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("error %s: processing %s\n",
			nt_errstr(status), targetpath);
	}
	return status;
}

/*
 * dump_ctx contains a list of directories to be processed
 *    + each directory 'dir' is scanned by cli_list, the cli_list
 *      callback 'cacl_dump_dacl_cb' writes out the dacl of each
 *      child of 'dir' (regardless of whether it is a dir or file)
 *      to the restore/save file. Additionally any directories encountered
 *      are returned in the passed in dump_ctx->list member
 *    + the directory list returned from cli_list is passed and processed
 *      by recursively calling dump_dacl_dirtree
 *
 */
static int dump_dacl_dirtree(struct dump_context *dump_ctx)
{
	struct diritem *item = NULL;
	struct dump_context *new_dump_ctx = NULL;
	int result;
	for (item = dump_ctx->list; item; item = item->next) {
		uint16_t attribute = FILE_ATTRIBUTE_DIRECTORY
		    | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN;
		NTSTATUS status;
		char *mask = NULL;

		new_dump_ctx = talloc_zero(dump_ctx, struct dump_context);

		if (new_dump_ctx == NULL) {
			DBG_ERR("out of memory\n");
			result = EXIT_FAILED;
			goto out;
		}

		if (item->targetcli == NULL) {
			status = cli_resolve_path(new_dump_ctx,
						  "",
						  dump_ctx->creds,
						  dump_ctx->cli,
						  item->dirname,
						  &item->targetcli,
						  &item->targetpath);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("failed to resolve path %s "
					"error: %s\n",
					item->dirname, nt_errstr(status));
				result = EXIT_FAILED;
				goto out;
			}
		}
		new_dump_ctx->creds = dump_ctx->creds;
		new_dump_ctx->save_fd = dump_ctx->save_fd;
		new_dump_ctx->stats = dump_ctx->stats;
		new_dump_ctx->dir = item;
		new_dump_ctx->cli = item->targetcli;

		mask = talloc_asprintf(new_dump_ctx, "%s*",
				       new_dump_ctx->dir->targetpath);
		status = cli_list(new_dump_ctx->dir->targetcli,
				  mask,
				  attribute, cacl_dump_dacl_cb, new_dump_ctx);

		if (!NT_STATUS_IS_OK(status) ||
		    !NT_STATUS_IS_OK(new_dump_ctx->status)) {
			NTSTATUS tmpstatus;
			if (!NT_STATUS_IS_OK(status)) {
				/*
				 * cli_list failed for some reason
				 * so we need to update the failure stat
				 */
				new_dump_ctx->stats->failure += 1;
				tmpstatus = status;
			} else {
				/* cacl_dump_dacl_cb should have updated stat */
				tmpstatus = new_dump_ctx->status;
			}
			DBG_ERR("error %s: processing %s\n",
				nt_errstr(tmpstatus), item->dirname);
			result = EXIT_FAILED;
			goto out;
		}
		result = dump_dacl_dirtree(new_dump_ctx);
		if (result != EXIT_OK) {
			goto out;
		}
	}

	result = EXIT_OK;
out:
	TALLOC_FREE(new_dump_ctx);
	return result;
}

static int cacl_dump_dacl(struct cli_state *cli,
			  struct cli_credentials *creds,
			  char *filename)
{
	int fileattr;
	char *mask = NULL;
	TALLOC_CTX *ctx = NULL;
	bool isdirectory = false;
	int result;
	struct dump_context *dump_ctx = NULL;
	struct save_restore_stats stats = {0};
	struct diritem *item = NULL;
	struct cli_state *targetcli = NULL;
	char *targetpath = NULL;
	NTSTATUS status;

	ctx = talloc_init("cacl_dump");
	if (ctx == NULL) {
		DBG_ERR("out of memory\n");
		result = EXIT_FAILED;
		goto out;
	}

	dump_ctx = talloc_zero(ctx, struct dump_context);
	if (dump_ctx == NULL) {
		DBG_ERR("out of memory\n");
		result = EXIT_FAILED;
		goto out;
	}

	dump_ctx->save_fd = open(save_file,
				 O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);

	if (dump_ctx->save_fd < 0) {
		result = EXIT_FAILED;
		goto out;
	}

	dump_ctx->creds = creds;
	dump_ctx->cli = cli;
	dump_ctx->stats = &stats;

	/* ensure we have a filename that starts with '\' */
	if (!filename || *filename != DIRSEP_CHAR) {
		/* illegal or no filename */
		result = EXIT_FAILED;
		DBG_ERR("illegal or missing name '%s'\n", filename);
		goto out;
	}

	status = cli_resolve_path(dump_ctx, "",
				  dump_ctx->creds,
				  dump_ctx->cli,
				  filename, &targetcli, &targetpath);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed resolve %s\n", filename);
		result = EXIT_FAILED;
		goto out;
	}

	fileattr = get_fileinfo(targetcli, targetpath);
	isdirectory = (fileattr & FILE_ATTRIBUTE_DIRECTORY)
	    == FILE_ATTRIBUTE_DIRECTORY;

	/*
	 * if we've got as far as here then we have already evaluated
	 * the args.
	 */
	if (test_args) {
		result = EXIT_OK;
		goto out;
	}

	mask = NULL;
	/* make sure we have a trailing '\*' for directory */
	if (!isdirectory) {
		mask = talloc_strdup(ctx, filename);
	} else if (strlen(filename) > 1) {
		mask = sanitize_dirname(ctx, filename);
	} else {
		/* filename is a single '\' */
		mask = talloc_strdup(ctx, filename);
	}
	if (!mask) {
		result = EXIT_FAILED;
		goto out;
	}

	write_dacl(dump_ctx, targetcli, targetpath, filename);
	if (isdirectory && recurse) {
		item = talloc_zero(dump_ctx, struct diritem);
		if (!item) {
			result = EXIT_FAILED;
			goto out;
		}
		item->dirname = mask;
		DLIST_ADD_END(dump_ctx->list, item);
		dump_dacl_dirtree(dump_ctx);
	}

	fprintf(stdout, "Successfully processed %d files: "
		"Failed processing %d files\n",
		dump_ctx->stats->success, dump_ctx->stats->failure);
	result = EXIT_OK;
out:
	if (dump_ctx && dump_ctx->save_fd > 0) {
		close(dump_ctx->save_fd);
	}
	TALLOC_FREE(ctx);
	return result;
}

struct restore_dacl {
	const char *path;
	struct security_descriptor *sd;
};

/*
 * Restore dacls from 'savefile' produced by
 * 'icacls name /save' or 'smbcacls --save'
 */
static int cacl_restore(struct cli_state *cli,
			struct cli_credentials *creds,
			bool numeric, const char *restorefile)
{
	int restore_fd;
	int result;
	struct save_restore_stats stats = { 0 };

	char **lines = NULL;
	char *content = NULL;
	char *convert_content = NULL;
	size_t content_size;
	struct restore_dacl *entries = NULL;
	int numlines, i = 0;
	bool ok;
	struct dom_sid *sid = NULL;

	if (restorefile == NULL) {
		DBG_ERR("No restore file specified\n");
		result = EXIT_FAILED;
		goto out;
	}

	if (test_args) {
		result = EXIT_OK;
		goto out;
	}

	restore_fd = open(restorefile, O_RDONLY, S_IRUSR | S_IWUSR);
	if (restore_fd < 0) {
		DBG_ERR("Failed to open %s.\n", restorefile);
		result = EXIT_FAILED;
		goto out;
	}

	content = fd_load(restore_fd, &content_size, 0, talloc_tos());

	close(restore_fd);

	if (content == NULL) {
		DBG_ERR("Failed to load content from %s.\n", restorefile);
		result = EXIT_FAILED;
		goto out;
	}

	ok = convert_string_talloc(talloc_tos(),
				   CH_UTF16,
				   CH_UNIX,
				   content,
				   utf16_len_n(content, content_size),
				   (void **)(void *)&convert_content,
				   &content_size);

	TALLOC_FREE(content);

	if (!ok) {
		DBG_ERR("Failed to convert content from %s "
			"to CH_UNIX.\n", restorefile);
		result = EXIT_FAILED;
		goto out;
	}

	lines = file_lines_parse(convert_content,
				 content_size, &numlines, talloc_tos());

	if (lines == NULL) {
		DBG_ERR("Failed to parse lines from content of %s.",
			restorefile);
		result = EXIT_FAILED;
		goto out;
	}

	entries = talloc_zero_array(lines, struct restore_dacl, numlines / 2);

	if (entries == NULL) {
		DBG_ERR("error processing %s, out of memory\n", restorefile);
		result = EXIT_FAILED;
		goto out;
	}

	sid = get_domain_sid(cli);

	while (i < numlines) {
		int index = i / 2;
		int first_line = (i % 2) == 0;

		if (first_line) {
			char *tmp = NULL;
			tmp = lines[i];
			/* line can be blank if root of share */
			if (strlen(tmp) == 0) {
				entries[index].path = talloc_strdup(lines,
								    "\\");
			} else {
				entries[index].path = lines[i];
			}
		} else {
			const char *msg = NULL;
			size_t msg_offset = 0;
			enum ace_condition_flags flags =
				ACE_CONDITION_FLAG_ALLOW_DEVICE;
			entries[index].sd = sddl_decode_err_msg(lines,
								lines[i],
								sid,
								flags,
								&msg,
								&msg_offset);
			if(entries[index].sd == NULL) {
				DBG_ERR("could not decode '%s'\n", lines[i]);
				if (msg != NULL) {
					DBG_ERR("                  %*c\n",
						(int)msg_offset, '^');
					DBG_ERR("error '%s'\n", msg);
				}
				result = EXIT_FAILED;
				goto out;
			}
			entries[index].sd->type |=
			    SEC_DESC_DACL_AUTO_INHERIT_REQ;
			entries[index].sd->type |= SEC_DESC_SACL_AUTO_INHERITED;
		}
		i++;
	}
	for (i = 0; i < (numlines / 2); i++) {
		int mode = SMB_ACL_SET;
		int set_result;
		struct cli_state *targetcli = NULL;
		char *targetpath = NULL;
		NTSTATUS status;

		/* check for dfs */
		status = cli_resolve_path(talloc_tos(),
					  "",
					  creds,
					  cli,
					  entries[i].path,
					  &targetcli, &targetpath);

		if (!NT_STATUS_IS_OK(status)) {
			printf("Error failed to process file: %s\n",
			       entries[i].path);
			stats.failure += 1;
			continue;
		}

		set_result = cacl_set_from_sd(targetcli,
					      targetpath,
					      entries[i].sd, mode, numeric);

		if (set_result == EXIT_OK) {
			printf("Successfully processed file: %s\n",
			       entries[i].path);
			stats.success += 1;
		} else {
			printf("Error failed to process file: %s\n",
			       entries[i].path);
			stats.failure += 1;
		}
	}

	result = EXIT_OK;
out:
	TALLOC_FREE(lines);
	fprintf(stdout, "Successfully processed %d files: "
		"Failed processing %d files\n", stats.success, stats.failure);
	return result;
}

/****************************************************************************
  main program
****************************************************************************/
int main(int argc, char *argv[])
{
	const char **argv_const = discard_const_p(const char *, argv);
	char *share;
	int opt;
	enum acl_mode mode = SMB_ACL_SET;
	static char *the_acl = NULL;
	enum chown_mode change_mode = REQUEST_NONE;
	int result;
	char *path;
	char *filename = NULL;
	poptContext pc;
	/* numeric is set when the user wants numeric SIDs and ACEs rather
	   than going via LSA calls to resolve them */
	int numeric = 0;
	struct cli_state *targetcli = NULL;
	struct cli_credentials *creds = NULL;
	char *targetfile = NULL;
	NTSTATUS status;
	bool ok;
	struct loadparm_context *lp_ctx = NULL;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "delete",
			.shortName  = 'D',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'D',
			.descrip    = "Delete an acl",
			.argDescrip = "ACL",
		},
		{
			.longName   = "modify",
			.shortName  = 'M',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'M',
			.descrip    = "Modify an acl",
			.argDescrip = "ACL",
		},
		{
			.longName   = "add",
			.shortName  = 'a',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'a',
			.descrip    = "Add an acl",
			.argDescrip = "ACL",
		},
		{
			.longName   = "set",
			.shortName  = 'S',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'S',
			.descrip    = "Set acls",
			.argDescrip = "ACLS",
		},
		{
			.longName   = "chown",
			.shortName  = 'C',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'C',
			.descrip    = "Change ownership of a file",
			.argDescrip = "USERNAME",
		},
		{
			.longName   = "chgrp",
			.shortName  = 'G',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'G',
			.descrip    = "Change group ownership of a file",
			.argDescrip = "GROUPNAME",
		},
		{
			.longName   = "inherit",
			.shortName  = 'I',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'I',
			.descrip    = "Inherit allow|remove|copy",
		},
		{
			.longName   = "propagate-inheritance",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &inheritance,
			.val        = 1,
			.descrip    = "Supports propagation of inheritable ACE(s) when used in conjunction with add, delete, set or modify",
		},
		{
			.longName   = "save",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &save_file,
			.val        = 1,
			.descrip    = "stores the DACLs in sddl format of the "
				      "specified file or folder for later use "
				      "with restore. SACLS, owner or integrity"
				      " labels are not stored",
		},
		{
			.longName   = "restore",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &restore_file,
			.val        = 1,
			.descrip    = "applies the stored DACLS to files in "
				      "directory.",
		},
		{
			.longName   = "recurse",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &recurse,
			.val        = 1,
			.descrip    = "indicates the operation is performed "
				      "on directory and all files/directories"
				      " below. (only applies to save option)",
		},
		{
			.longName   = "numeric",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &numeric,
			.val        = 1,
			.descrip    = "Don't resolve sids or masks to names",
		},
		{
			.longName   = "sddl",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &sddl,
			.val        = 1,
			.descrip    = "Output and input acls in sddl format",
		},
		{
			.longName   = "query-security-info",
			.shortName  = 0,
			.argInfo    = POPT_ARG_INT,
			.arg        = &query_sec_info,
			.val        = 1,
			.descrip    = "The security-info flags for queries"
		},
		{
			.longName   = "set-security-info",
			.shortName  = 0,
			.argInfo    = POPT_ARG_INT,
			.arg        = &set_sec_info,
			.val        = 1,
			.descrip    = "The security-info flags for modifications"
		},
		{
			.longName   = "test-args",
			.shortName  = 't',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &test_args,
			.val        = 1,
			.descrip    = "Test arguments"
		},
		{
			.longName   = "domain-sid",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &domain_sid,
			.val        = 0,
			.descrip    = "Domain SID for sddl",
			.argDescrip = "SID"},
		{
			.longName   = "maximum-access",
			.shortName  = 'x',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'x',
			.descrip    = "Query maximum permissions",
		},
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_LEGACY_S3
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

	struct cli_state *cli;
	TALLOC_CTX *frame = talloc_stackframe();
	const char *owner_username = "";
	char *server;

	smb_init_locale();

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(frame);
		exit(1);
	}
	lp_ctx = samba_cmdline_get_lp_ctx();
	/* set default debug level to 1 regardless of what smb.conf sets */
	lpcfg_set_cmdline(lp_ctx, "log level", "1");

	setlinebuf(stdout);

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv_const,
				    long_options,
				    0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	poptSetOtherOptionHelp(pc, "//server1/share1 filename\nACLs look like: "
		"'ACL:user:[ALLOWED|DENIED]/flags/permissions'");

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'S':
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			mode = SMB_ACL_SET;
			break;

		case 'D':
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			mode = SMB_ACL_DELETE;
			break;

		case 'M':
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			mode = SMB_ACL_MODIFY;
			break;

		case 'a':
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			mode = SMB_ACL_ADD;
			break;

		case 'C':
			owner_username = poptGetOptArg(pc);
			change_mode = REQUEST_CHOWN;
			break;

		case 'G':
			owner_username = poptGetOptArg(pc);
			change_mode = REQUEST_CHGRP;
			break;

		case 'I':
			owner_username = poptGetOptArg(pc);
			change_mode = REQUEST_INHERIT;
			break;
		case 'm':
			lpcfg_set_cmdline(lp_ctx, "client max protocol", poptGetOptArg(pc));
			break;
		case 'x':
			want_mxac = true;
			break;
		case POPT_ERROR_BADOPT:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
	}
	if (inheritance && !the_acl) {
		poptPrintUsage(pc, stderr, 0);
		return -1;
	}

	if(!poptPeekArg(pc)) {
		poptPrintUsage(pc, stderr, 0);
		return -1;
	}

	path = talloc_strdup(frame, poptGetArg(pc));
	if (!path) {
		return -1;
	}

	if (strncmp(path, "\\\\", 2) && strncmp(path, "//", 2)) {
		printf("Invalid argument: %s\n", path);
		return -1;
	}

	if(!poptPeekArg(pc)) {
		poptPrintUsage(pc, stderr, 0);
		return -1;
	}

	filename = talloc_strdup(frame, poptGetArg(pc));
	if (!filename) {
		return -1;
	}

	poptFreeContext(pc);
	samba_cmdline_burn(argc, argv);

	string_replace(path,'/','\\');

	server = talloc_strdup(frame, path+2);
	if (!server) {
		return -1;
	}
	share = strchr_m(server,'\\');
	if (share == NULL) {
		printf("Invalid argument\n");
		return -1;
	}

	*share = 0;
	share++;

	creds = samba_cmdline_get_creds();

	/* Make connection to server */
	if (!test_args) {
		cli = connect_one(creds, server, share);
		if (!cli) {
			exit(EXIT_FAILED);
		}
	} else {
		exit(0);
	}

	string_replace(filename, '/', '\\');
	if (filename[0] != '\\') {
		filename = talloc_asprintf(frame,
				"\\%s",
				filename);
		if (!filename) {
			return -1;
		}
	}

	status = cli_resolve_path(frame,
				  "",
				  creds,
				  cli,
				  filename,
				  &targetcli,
				  &targetfile);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("cli_resolve_path failed for %s! (%s)\n", filename, nt_errstr(status)));
		return -1;
	}

	/* Perform requested action */

	if (change_mode == REQUEST_INHERIT) {
		result = inherit(targetcli, targetfile, owner_username);
	} else if (change_mode != REQUEST_NONE) {
		result = owner_set(targetcli, change_mode, targetfile, owner_username);
	} else if (the_acl) {
		if (inheritance) {
			struct cacl_callback_state cbstate = {
				.creds = creds,
				.cli = targetcli,
				.mode = mode,
				.the_acl = the_acl,
				.numeric = numeric,
			};
			result = inheritance_cacl_set(targetfile, &cbstate);
		} else {
			result =  cacl_set(targetcli,
					   targetfile,
					   the_acl,
					   mode,
					   numeric);
		}
	} else {
		if (save_file || restore_file) {
			sddl = 1;
			if (save_file) {
				result = cacl_dump_dacl(cli, creds, filename);
			} else {
				result = cacl_restore(targetcli,
						      creds,
						      numeric, restore_file);
			}
		} else {
			result = cacl_dump(targetcli, targetfile, numeric);
		}
	}

	gfree_all();
	TALLOC_FREE(frame);

	return result;
}
