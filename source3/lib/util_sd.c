/*
   Unix SMB/CIFS implementation.
   Security Descriptor (SD) helper functions

   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Tim Potter      2000
   Copyright (C) Jeremy Allison  2000
   Copyright (C) Jelmer Vernooij 2003

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
#include "libsmb/libsmb.h"
#include "util_sd.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "../libcli/security/security.h"
#include "rpc_client/cli_pipe.h"
#include "rpc_client/cli_lsarpc.h"

/* These values discovered by inspection */

struct perm_value {
	const char *perm;
	uint32 mask;
};

static const struct perm_value special_values[] = {
	{ "R", SEC_RIGHTS_FILE_READ },
	{ "W", SEC_RIGHTS_FILE_WRITE },
	{ "X", SEC_RIGHTS_FILE_EXECUTE },
	{ "D", SEC_STD_DELETE },
	{ "P", SEC_STD_WRITE_DAC },
	{ "O", SEC_STD_WRITE_OWNER },
	{ NULL, 0 },
};

static const struct perm_value standard_values[] = {
	{ "READ",   SEC_RIGHTS_DIR_READ|SEC_DIR_TRAVERSE },
	{ "CHANGE", SEC_RIGHTS_DIR_READ|SEC_STD_DELETE|\
	  SEC_RIGHTS_DIR_WRITE|SEC_DIR_TRAVERSE },
	{ "FULL",   SEC_RIGHTS_DIR_ALL },
	{ NULL, 0 },
};

static const struct {
	uint16_t mask;
	const char *str;
	const char *desc;
} sec_desc_ctrl_bits[] = {
	{SEC_DESC_OWNER_DEFAULTED,       "OD", "Owner Defaulted"},
	{SEC_DESC_GROUP_DEFAULTED,       "GD", "Group Defaulted"},
	{SEC_DESC_DACL_PRESENT,          "DP", "DACL Present"},
	{SEC_DESC_DACL_DEFAULTED,        "DD", "DACL Defaulted"},
	{SEC_DESC_SACL_PRESENT,          "SP", "SACL Present"},
	{SEC_DESC_SACL_DEFAULTED,        "SD", "SACL Defaulted"},
	{SEC_DESC_DACL_TRUSTED,          "DT", "DACL Trusted"},
	{SEC_DESC_SERVER_SECURITY,       "SS", "Server Security"},
	{SEC_DESC_DACL_AUTO_INHERIT_REQ, "DR", "DACL Inheritance Required"},
	{SEC_DESC_SACL_AUTO_INHERIT_REQ, "SR", "SACL Inheritance Required"},
	{SEC_DESC_DACL_AUTO_INHERITED,   "DI", "DACL Auto Inherited"},
	{SEC_DESC_SACL_AUTO_INHERITED,   "SI", "SACL Auto Inherited"},
	{SEC_DESC_DACL_PROTECTED,        "PD", "DACL Protected"},
	{SEC_DESC_SACL_PROTECTED,        "PS", "SACL Protected"},
	{SEC_DESC_RM_CONTROL_VALID,      "RM", "RM Control Valid"},
	{SEC_DESC_SELF_RELATIVE ,        "SR", "Self Relative"},
};

/* Open cli connection and policy handle */
static NTSTATUS cli_lsa_lookup_sid(struct cli_state *cli,
				   const struct dom_sid *sid,
				   TALLOC_CTX *mem_ctx,
				   enum lsa_SidType *type,
				   char **domain, char **name)
{
	uint16 orig_cnum = cli_state_get_tid(cli);
	struct rpc_pipe_client *p = NULL;
	struct policy_handle handle;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	enum lsa_SidType *types;
	char **domains;
	char **names;

	status = cli_tree_connect(cli, "IPC$", "?????", "", 0);
	if (!NT_STATUS_IS_OK(status)) {
		goto tcon_fail;
	}

	status = cli_rpc_pipe_open_noauth(cli, &ndr_table_lsarpc,
					  &p);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = rpccli_lsa_open_policy(p, talloc_tos(), True,
					GENERIC_EXECUTE_ACCESS, &handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = rpccli_lsa_lookup_sids(p, talloc_tos(), &handle, 1, sid,
					&domains, &names, &types);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	*type = types[0];
	*domain = talloc_move(mem_ctx, &domains[0]);
	*name = talloc_move(mem_ctx, &names[0]);

	status = NT_STATUS_OK;
 fail:
	TALLOC_FREE(p);
	cli_tdis(cli);
 tcon_fail:
	cli_state_set_tid(cli, orig_cnum);
	TALLOC_FREE(frame);
	return status;
}

/* convert a SID to a string, either numeric or username/group */
void SidToString(struct cli_state *cli, fstring str, const struct dom_sid *sid,
		 bool numeric)
{
	char *domain = NULL;
	char *name = NULL;
	enum lsa_SidType type;
	NTSTATUS status;

	sid_to_fstring(str, sid);

	if (numeric || cli == NULL) {
		return;
	}

	status = cli_lsa_lookup_sid(cli, sid, talloc_tos(), &type,
				    &domain, &name);

	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	if (*domain) {
		slprintf(str, sizeof(fstring) - 1, "%s%s%s",
			domain, lp_winbind_separator(), name);
	} else {
		fstrcpy(str, name);
	}
}

static NTSTATUS cli_lsa_lookup_name(struct cli_state *cli,
				    const char *name,
				    enum lsa_SidType *type,
				    struct dom_sid *sid)
{
	uint16 orig_cnum = cli_state_get_tid(cli);
	struct rpc_pipe_client *p;
	struct policy_handle handle;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	struct dom_sid *sids;
	enum lsa_SidType *types;

	status = cli_tree_connect(cli, "IPC$", "?????", "", 0);
	if (!NT_STATUS_IS_OK(status)) {
		goto tcon_fail;
	}

	status = cli_rpc_pipe_open_noauth(cli, &ndr_table_lsarpc,
					  &p);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = rpccli_lsa_open_policy(p, talloc_tos(), True,
					GENERIC_EXECUTE_ACCESS, &handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = rpccli_lsa_lookup_names(p, talloc_tos(), &handle, 1, &name,
					 NULL, 1, &sids, &types);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	*type = types[0];
	*sid = sids[0];

	status = NT_STATUS_OK;
 fail:
	TALLOC_FREE(p);
	cli_tdis(cli);
 tcon_fail:
	cli_state_set_tid(cli, orig_cnum);
	TALLOC_FREE(frame);
	return status;
}

/* convert a string to a SID, either numeric or username/group */
bool StringToSid(struct cli_state *cli, struct dom_sid *sid, const char *str)
{
	enum lsa_SidType type;

	if (string_to_sid(sid, str)) {
		return true;
	}

	if (cli == NULL) {
		return false;
	}

	return NT_STATUS_IS_OK(cli_lsa_lookup_name(cli, str, &type, sid));
}

static void print_ace_flags(FILE *f, uint8_t flags)
{
	char *str = talloc_strdup(NULL, "");

	if (!str) {
		goto out;
	}

	if (flags & SEC_ACE_FLAG_OBJECT_INHERIT) {
		str = talloc_asprintf(str, "%s%s",
				str, "OI|");
		if (!str) {
			goto out;
		}
	}
	if (flags & SEC_ACE_FLAG_CONTAINER_INHERIT) {
		str = talloc_asprintf(str, "%s%s",
				str, "CI|");
		if (!str) {
			goto out;
		}
	}
	if (flags & SEC_ACE_FLAG_NO_PROPAGATE_INHERIT) {
		str = talloc_asprintf(str, "%s%s",
				str, "NP|");
		if (!str) {
			goto out;
		}
	}
	if (flags & SEC_ACE_FLAG_INHERIT_ONLY) {
		str = talloc_asprintf(str, "%s%s",
				str, "IO|");
		if (!str) {
			goto out;
		}
	}
	if (flags & SEC_ACE_FLAG_INHERITED_ACE) {
		str = talloc_asprintf(str, "%s%s",
				str, "I|");
		if (!str) {
			goto out;
		}
	}
	/* Ignore define SEC_ACE_FLAG_SUCCESSFUL_ACCESS ( 0x40 )
	   and SEC_ACE_FLAG_FAILED_ACCESS ( 0x80 ) as they're
	   audit ace flags. */

	if (str[strlen(str)-1] == '|') {
		str[strlen(str)-1] = '\0';
		fprintf(f, "/%s/", str);
	} else {
		fprintf(f, "/0x%x/", flags);
	}
	TALLOC_FREE(str);
	return;

  out:
	fprintf(f, "/0x%x/", flags);
}

/* print an ACE on a FILE, using either numeric or ascii representation */
void print_ace(struct cli_state *cli, FILE *f, struct security_ace *ace,
	       bool numeric)
{
	const struct perm_value *v;
	fstring sidstr;
	int do_print = 0;
	uint32 got_mask;

	SidToString(cli, sidstr, &ace->trustee, numeric);

	fprintf(f, "%s:", sidstr);

	if (numeric) {
		fprintf(f, "%d/0x%x/0x%08x",
			ace->type, ace->flags, ace->access_mask);
		return;
	}

	/* Ace type */

	if (ace->type == SEC_ACE_TYPE_ACCESS_ALLOWED) {
		fprintf(f, "ALLOWED");
	} else if (ace->type == SEC_ACE_TYPE_ACCESS_DENIED) {
		fprintf(f, "DENIED");
	} else {
		fprintf(f, "%d", ace->type);
	}

	print_ace_flags(f, ace->flags);

	/* Standard permissions */

	for (v = standard_values; v->perm; v++) {
		if (ace->access_mask == v->mask) {
			fprintf(f, "%s", v->perm);
			return;
		}
	}

	/* Special permissions.  Print out a hex value if we have
	   leftover bits in the mask. */

	got_mask = ace->access_mask;

 again:
	for (v = special_values; v->perm; v++) {
		if ((ace->access_mask & v->mask) == v->mask) {
			if (do_print) {
				fprintf(f, "%s", v->perm);
			}
			got_mask &= ~v->mask;
		}
	}

	if (!do_print) {
		if (got_mask != 0) {
			fprintf(f, "0x%08x", ace->access_mask);
		} else {
			do_print = 1;
			goto again;
		}
	}
}

static bool parse_ace_flags(const char *str, unsigned int *pflags)
{
	const char *p = str;
	*pflags = 0;

	while (*p) {
		if (strnequal(p, "OI", 2)) {
			*pflags |= SEC_ACE_FLAG_OBJECT_INHERIT;
			p += 2;
		} else if (strnequal(p, "CI", 2)) {
			*pflags |= SEC_ACE_FLAG_CONTAINER_INHERIT;
			p += 2;
		} else if (strnequal(p, "NP", 2)) {
			*pflags |= SEC_ACE_FLAG_NO_PROPAGATE_INHERIT;
			p += 2;
		} else if (strnequal(p, "IO", 2)) {
			*pflags |= SEC_ACE_FLAG_INHERIT_ONLY;
			p += 2;
		} else if (*p == 'I') {
			*pflags |= SEC_ACE_FLAG_INHERITED_ACE;
			p += 1;
		} else if (*p) {
			return false;
		}

		switch (*p) {
		case '|':
			p++;
		case '\0':
			continue;
		default:
			return false;
		}
	}
	return true;
}

/* parse an ACE in the same format as print_ace() */
bool parse_ace(struct cli_state *cli, struct security_ace *ace,
	       const char *orig_str)
{
	char *p;
	const char *cp;
	char *tok;
	unsigned int atype = 0;
	unsigned int aflags = 0;
	unsigned int amask = 0;
	struct dom_sid sid;
	uint32_t mask;
	const struct perm_value *v;
	char *str = SMB_STRDUP(orig_str);
	TALLOC_CTX *frame = talloc_stackframe();

	if (!str) {
		TALLOC_FREE(frame);
		return False;
	}

	ZERO_STRUCTP(ace);
	p = strchr_m(str,':');
	if (!p) {
		printf("ACE '%s': missing ':'.\n", orig_str);
		SAFE_FREE(str);
		TALLOC_FREE(frame);
		return False;
	}
	*p = '\0';
	p++;
	/* Try to parse numeric form */

	if (sscanf(p, "%u/%u/%u", &atype, &aflags, &amask) == 3 &&
	    StringToSid(cli, &sid, str)) {
		goto done;
	}

	/* Try to parse text form */

	if (!StringToSid(cli, &sid, str)) {
		printf("ACE '%s': failed to convert '%s' to SID\n",
			orig_str, str);
		SAFE_FREE(str);
		TALLOC_FREE(frame);
		return False;
	}

	cp = p;
	if (!next_token_talloc(frame, &cp, &tok, "/")) {
		printf("ACE '%s': failed to find '/' character.\n",
			orig_str);
		SAFE_FREE(str);
		TALLOC_FREE(frame);
		return False;
	}

	if (strncmp(tok, "ALLOWED", strlen("ALLOWED")) == 0) {
		atype = SEC_ACE_TYPE_ACCESS_ALLOWED;
	} else if (strncmp(tok, "DENIED", strlen("DENIED")) == 0) {
		atype = SEC_ACE_TYPE_ACCESS_DENIED;
	} else {
		printf("ACE '%s': missing 'ALLOWED' or 'DENIED' entry at '%s'\n",
			orig_str, tok);
		SAFE_FREE(str);
		TALLOC_FREE(frame);
		return False;
	}

	/* Only numeric form accepted for flags at present */

	if (!next_token_talloc(frame, &cp, &tok, "/")) {
		printf("ACE '%s': bad flags entry at '%s'\n",
			orig_str, tok);
		SAFE_FREE(str);
		TALLOC_FREE(frame);
		return False;
	}

	if (tok[0] < '0' || tok[0] > '9') {
		if (!parse_ace_flags(tok, &aflags)) {
			printf("ACE '%s': bad named flags entry at '%s'\n",
				orig_str, tok);
			SAFE_FREE(str);
			TALLOC_FREE(frame);
			return False;
		}
	} else if (strnequal(tok, "0x", 2)) {
		if (!sscanf(tok, "%x", &aflags)) {
			printf("ACE '%s': bad hex flags entry at '%s'\n",
				orig_str, tok);
			SAFE_FREE(str);
			TALLOC_FREE(frame);
			return False;
		}
	} else {
		if (!sscanf(tok, "%u", &aflags)) {
			printf("ACE '%s': bad integer flags entry at '%s'\n",
				orig_str, tok);
			SAFE_FREE(str);
			TALLOC_FREE(frame);
			return False;
		}
	}

	if (!next_token_talloc(frame, &cp, &tok, "/")) {
		printf("ACE '%s': missing / at '%s'\n",
			orig_str, tok);
		SAFE_FREE(str);
		TALLOC_FREE(frame);
		return False;
	}

	if (strncmp(tok, "0x", 2) == 0) {
		if (sscanf(tok, "%u", &amask) != 1) {
			printf("ACE '%s': bad hex number at '%s'\n",
				orig_str, tok);
			SAFE_FREE(str);
			TALLOC_FREE(frame);
			return False;
		}
		goto done;
	}

	for (v = standard_values; v->perm; v++) {
		if (strcmp(tok, v->perm) == 0) {
			amask = v->mask;
			goto done;
		}
	}

	p = tok;

	while(*p) {
		bool found = False;

		for (v = special_values; v->perm; v++) {
			if (v->perm[0] == *p) {
				amask |= v->mask;
				found = True;
			}
		}

		if (!found) {
			printf("ACE '%s': bad permission value at '%s'\n",
				orig_str, p);
			SAFE_FREE(str);
			TALLOC_FREE(frame);
			return False;
		}
		p++;
	}

	if (*p) {
		TALLOC_FREE(frame);
		SAFE_FREE(str);
		return False;
	}

 done:
	mask = amask;
	init_sec_ace(ace, &sid, atype, mask, aflags);
	TALLOC_FREE(frame);
	SAFE_FREE(str);
	return True;
}

static void print_acl_ctrl(FILE *file, uint16_t ctrl, bool numeric)
{
	int i;
	const char* separator = "";

	fprintf(file, "CONTROL:");
	if (numeric) {
		fprintf(file, "0x%x\n", ctrl);
		return;
	}

	for (i = ARRAY_SIZE(sec_desc_ctrl_bits) - 1; i >= 0; i--) {
		if (ctrl & sec_desc_ctrl_bits[i].mask) {
			fprintf(file, "%s%s",
				separator, sec_desc_ctrl_bits[i].str);
			separator = "|";
		}
	}
	fputc('\n', file);
}

/* print a ascii version of a security descriptor on a FILE handle */
void sec_desc_print(struct cli_state *cli, FILE *f,
		    struct security_descriptor *sd, bool numeric)
{
	fstring sidstr;
	uint32 i;

	fprintf(f, "REVISION:%d\n", sd->revision);
	print_acl_ctrl(f, sd->type, numeric);

	/* Print owner and group sid */

	if (sd->owner_sid) {
		SidToString(cli, sidstr, sd->owner_sid, numeric);
	} else {
		fstrcpy(sidstr, "");
	}

	fprintf(f, "OWNER:%s\n", sidstr);

	if (sd->group_sid) {
		SidToString(cli, sidstr, sd->group_sid, numeric);
	} else {
		fstrcpy(sidstr, "");
	}

	fprintf(f, "GROUP:%s\n", sidstr);

	/* Print aces */
	for (i = 0; sd->dacl && i < sd->dacl->num_aces; i++) {
		struct security_ace *ace = &sd->dacl->aces[i];
		fprintf(f, "ACL:");
		print_ace(cli, f, ace, numeric);
		fprintf(f, "\n");
	}

}
