/*
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Hewlett-Packard Company           1999.
 *  Copyright (C) Jeremy Allison                    2001.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

extern int DEBUGLEVEL;

extern fstring global_myworkgroup;
extern pstring global_myname;
extern DOM_SID global_sam_sid;

extern rid_name domain_group_rids[];
extern rid_name domain_alias_rids[];
extern rid_name builtin_alias_rids[];

/*******************************************************************
  This next function should be replaced with something that
  dynamically returns the correct user info..... JRA.
 ********************************************************************/

static BOOL get_sampwd_entries(SAM_USER_INFO_21 *pw_buf, int start_idx,
                                int *total_entries, int *num_entries,
                                int max_num_entries, uint16 acb_mask)
{
    void *vp = NULL;
    struct sam_passwd *pwd = NULL;

    (*num_entries) = 0;
    (*total_entries) = 0;

    if (pw_buf == NULL)
        return False;

    vp = startsmbpwent(False);
    if (!vp) {
        DEBUG(0, ("get_sampwd_entries: Unable to open SMB password database.\n"));
        return False;
    }

    while (((pwd = getsam21pwent(vp)) != NULL) && (*num_entries) < max_num_entries) {
        int user_name_len;

        if (start_idx > 0) {
            /* skip the requested number of entries.
               not very efficient, but hey...
             */
            start_idx--;
            continue;
        }

        user_name_len = strlen(pwd->smb_name)+1;
        init_unistr2(&(pw_buf[(*num_entries)].uni_user_name), pwd->smb_name, user_name_len);
        init_uni_hdr(&(pw_buf[(*num_entries)].hdr_user_name), user_name_len);
        pw_buf[(*num_entries)].user_rid = pwd->user_rid;
        memset((char *)pw_buf[(*num_entries)].nt_pwd, '\0', 16);

        /* Now check if the NT compatible password is available. */
        if (pwd->smb_nt_passwd != NULL) {
            memcpy( pw_buf[(*num_entries)].nt_pwd , pwd->smb_nt_passwd, 16);
        }

        pw_buf[(*num_entries)].acb_info = (uint16)pwd->acct_ctrl;

        DEBUG(5, ("entry idx: %d user %s, rid 0x%x, acb %x",
                  (*num_entries), pwd->smb_name,
                  pwd->user_rid, pwd->acct_ctrl));

        if (acb_mask == 0 || (pwd->acct_ctrl & acb_mask)) {
            DEBUG(5,(" acb_mask %x accepts\n", acb_mask));
            (*num_entries)++;
        }
        else
        {
            DEBUG(5,(" acb_mask %x rejects\n", acb_mask));
        }

        (*total_entries)++;
    }

    endsmbpwent(vp);

    return (*num_entries) > 0;
}

/*******************************************************************
 This function uses the username map file and tries to map a UNIX
 user name to an DOS name.  (Sort of the reverse of the
 map_username() function.)  Since more than one DOS name can map
 to the UNIX name, to reverse the mapping you have to specify
 which corresponding DOS name you want; that's where the name_idx
 parameter comes in.  Returns the string requested or NULL if it
 fails or can't complete the request for any reason.  This doesn't
 handle group names (starting with '@') or names starting with
 '+' or '&'.  If they are encountered, they are skipped.
********************************************************************/

static char *unmap_unixname(char *unix_user_name, int name_idx)
{
	char *mapfile = lp_username_map();
	char **lines;
	static pstring tok;
	int i;

	if (!*unix_user_name) return NULL;
	if (!*mapfile) return NULL;

	lines = file_lines_load(mapfile, NULL,False);
	if (!lines) {
		DEBUG(0,("unmap_unixname: can't open username map %s\n", mapfile));
		return NULL;
	}

	DEBUG(5,("unmap_unixname: scanning username map %s, index: %d\n", mapfile, name_idx));

	for (i=0; lines[i]; i++) {
		char *unixname = lines[i];
		char *dosname = strchr(unixname,'=');

		if (!dosname)
			continue;

		*dosname++ = 0;

		while (isspace(*unixname))
			unixname++;
		if ('!' == *unixname) {
			unixname++;
			while (*unixname && isspace(*unixname))
				unixname++;
		}
    
		if (!*unixname || strchr("#;",*unixname))
			continue;

		if (strncmp(unixname, unix_user_name, strlen(unix_user_name)))
			continue;

		/* We have matched the UNIX user name */

		while(next_token(&dosname, tok, LIST_SEP, sizeof(tok))) {
			if (!strchr("@&+", *tok)) {
				name_idx--;
				if (name_idx < 0 ) {
					break;
				}
			}
		}

		if (name_idx >= 0) {
			DEBUG(0,("unmap_unixname: index too high - not that many DOS names\n"));
			file_lines_free(lines);
			return NULL;
		} else {
			file_lines_free(lines);
			return tok;
		}
	}

	DEBUG(0,("unmap_unixname: Couldn't find the UNIX user name\n"));
	file_lines_free(lines);
	return NULL;
}

/*******************************************************************
 This function sets up a list of users taken from the list of
 users that UNIX knows about, as well as all the user names that
 Samba maps to a valid UNIX user name.  (This should work with
 /etc/passwd or NIS.)
********************************************************************/

static BOOL get_passwd_entries(SAM_USER_INFO_21 *pw_buf,
				int start_idx,
				int *total_entries, int *num_entries,
				int max_num_entries,
				uint16 acb_mask)
{
	static struct passwd *pwd = NULL;
	static uint32 pw_rid;
	static BOOL orig_done = False;
	static int current_idx = 0;
	static int mapped_idx = 0;
	char *sep;

	DEBUG(5, ("get_passwd_entries: retrieving a list of UNIX users\n"));

	(*num_entries) = 0;
	(*total_entries) = 0;

	/* Skip all this stuff if we're in appliance mode */

	if (lp_hide_local_users()) goto done;

	if (pw_buf == NULL) return False;

	if (current_idx == 0) {
		sys_setpwent();
	}

	/* These two cases are inefficient, but should be called very rarely */
	/* they are the cases where the starting index isn't picking up      */
	/* where we left off last time.  It is efficient when it starts over */
	/* at zero though.                                                   */
	if (start_idx > current_idx) {
		/* We aren't far enough; advance to start_idx */
		while (current_idx < start_idx) {
			char *unmap_name;

			if(!orig_done) {
				if ((pwd = sys_getpwent()) == NULL) break;
				current_idx++;
				orig_done = True;
			}

			while (((unmap_name = unmap_unixname(pwd->pw_name, mapped_idx)) != NULL) && 
			        (current_idx < start_idx)) {
				current_idx++;
				mapped_idx++;
			}

			if (unmap_name == NULL) {
				orig_done = False;
				mapped_idx = 0;
			}
		}
	} else if (start_idx < current_idx) {
		/* We are already too far; start over and advance to start_idx */
		sys_endpwent();
		sys_setpwent();
		current_idx = 0;
		mapped_idx = 0;
		orig_done = False;
		while (current_idx < start_idx) {
			char *unmap_name;

			if(!orig_done) {
				if ((pwd = sys_getpwent()) == NULL) break;
				current_idx++;
				orig_done = True;
			}

			while (((unmap_name = unmap_unixname(pwd->pw_name, mapped_idx)) != NULL) && 
			        (current_idx < start_idx)) {
				current_idx++;
				mapped_idx++;
			}

			if (unmap_name == NULL) {
				orig_done = False;
				mapped_idx = 0;
			}
		}
	}

	sep = lp_winbind_separator();

	/* now current_idx == start_idx */
	while ((*num_entries) < max_num_entries) {
		int user_name_len;
		char *unmap_name;

		/* This does the original UNIX user itself */
		if(!orig_done) {
			if ((pwd = sys_getpwent()) == NULL) break;

			/* Don't enumerate winbind users as they are not local */

			if (strchr(pwd->pw_name, *sep) != NULL) {
				continue;
			}

			user_name_len = strlen(pwd->pw_name);
			
			/* skip the trust account stored in the /etc/passwd file */
			if (pwd->pw_name[user_name_len-1]=='$')
				continue;
			
			pw_rid = pdb_uid_to_user_rid(pwd->pw_uid);
			ZERO_STRUCTP(&pw_buf[(*num_entries)]);
			init_unistr2(&(pw_buf[(*num_entries)].uni_user_name), pwd->pw_name, user_name_len);
			init_uni_hdr(&(pw_buf[(*num_entries)].hdr_user_name), user_name_len);
			pw_buf[(*num_entries)].user_rid = pw_rid;
			memset((char *)pw_buf[(*num_entries)].nt_pwd, '\0', 16);

			pw_buf[(*num_entries)].acb_info = ACB_NORMAL;

			DEBUG(5, ("get_passwd_entries: entry idx %d user %s, rid 0x%x\n", (*num_entries), pwd->pw_name, pw_rid));

			(*num_entries)++;
			(*total_entries)++;
			current_idx++;
			orig_done = True;
		}

		/* This does all the user names that map to the UNIX user */
		while (((unmap_name = unmap_unixname(pwd->pw_name, mapped_idx)) != NULL) && 
		        (*num_entries < max_num_entries)) {
			user_name_len = strlen(unmap_name);
			ZERO_STRUCTP(&pw_buf[(*num_entries)]);
			init_unistr2(&(pw_buf[(*num_entries)].uni_user_name), unmap_name, user_name_len);
			init_uni_hdr(&(pw_buf[(*num_entries)].hdr_user_name), user_name_len);
			pw_buf[(*num_entries)].user_rid = pw_rid;
			memset((char *)pw_buf[(*num_entries)].nt_pwd, '\0', 16);

			pw_buf[(*num_entries)].acb_info = ACB_NORMAL;

			DEBUG(5, ("get_passwd_entries: entry idx %d user %s, rid 0x%x\n", (*num_entries), pwd->pw_name, pw_rid));

			(*num_entries)++;
			(*total_entries)++;
			current_idx++;
			mapped_idx++;
		}

		if (unmap_name == NULL) {
			/* done with 'aliases', go on to next UNIX user */
			orig_done = False;
			mapped_idx = 0;
		}
	}

	if (pwd == NULL) {
		/* totally done, reset everything */
		sys_endpwent();
		current_idx = 0;
		mapped_idx = 0;
	}

done:
	return (*num_entries) > 0;
}

/*******************************************************************
 _samr_close_hnd
 ********************************************************************/

uint32 _samr_close_hnd(pipes_struct *p, SAMR_Q_CLOSE_HND *q_u, SAMR_R_CLOSE_HND *r_u)
{
	/* close the policy handle */
	if (!close_lsa_policy_hnd(&q_u->pol))
		return NT_STATUS_OBJECT_NAME_INVALID;

	DEBUG(5,("samr_reply_close_hnd: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_open_domain
 ********************************************************************/

uint32 _samr_open_domain(pipes_struct *p, SAMR_Q_OPEN_DOMAIN *q_u, SAMR_R_OPEN_DOMAIN *r_u)
{
	/* find the connection policy handle. */
	if (find_lsa_policy_by_hnd(q_u->pol) == -1))
		return NT_STATUS_INVALID_HANDLE;

	/* get a (unique) handle.  open a policy on it. */
	if (!open_lsa_policy_hnd(&r_u->domain_pol))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	/* associate the domain SID with the (unique) handle. */
	if (!set_lsa_policy_samr_sid(&r_u->domain_pol, &q_u->dom_sid.sid))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	close_lsa_policy_hnd(&r_u->domain_pol);

	DEBUG(5,("samr_open_domain: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _samr_get_usrdom_pwinfo
 ********************************************************************/

uint32 _samr_get_usrdom_pwinfo(pipes_struct *p, SAMR_Q_GET_USRDOM_PWINFO *q_u, SAMR_R_GET_USRDOM_PWINFO *r_u)
{
	/* find the policy handle.  open a policy on it. */
	if (find_lsa_policy_by_hnd(&q_u->user_pol) == -1)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	/* find the user's rid */
	if (get_lsa_policy_samr_rid(&q_u->user_pol) == 0xffffffff)) {
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	init_samr_r_get_usrdom_pwinfo(&r_u, NT_STATUS_NOPROBLEMO);

	DEBUG(5,("_samr_get_usrdom_pwinfo: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _samr_query_sec_obj
 ********************************************************************/

uint32 _samr_query_sec_obj(pipes_struct *p, SAMR_Q_QUERY_SEC_OBJ *q_u, SAMR_R_QUERY_SEC_OBJ *r_u)
{
	prs_struct *rdata = &p->out_data.rdata;
	DOM_SID pol_sid;

	/* find the policy handle.  open a policy on it. */
	if ((find_lsa_policy_by_hnd(&q_u->user_pol)) == -1))
		return NT_STATUS_INVALID_HANDLE;

HERE !!!

	/* Get the SID. */
	if (!get_lsa_policy_samr_sid(&q_u->user_pol, &pol_sid))
		return NT_STATUS_OBJECT_TYPE_MISMATCH;

	{
		DOM_SID user_sid;
		DOM_SID everyone_sid;

		user_sid = global_sam_sid;

		SMB_ASSERT_ARRAY(user_sid.sub_auths, user_sid.num_auths+1);

		/*
		 * Add the user RID.
		 */
		user_sid.sub_auths[user_sid.num_auths++] = rid;
		
			string_to_sid(&everyone_sid, "S-1-1");

			/* maybe need another 1 or 2 (S-1-5-0x20-0x220 and S-1-5-20-0x224) */
			/* these two are DOMAIN_ADMIN and DOMAIN_ACCT_OP group RIDs */
			init_dom_sid3(&(sid[0]), 0x035b, 0x0002, &everyone_sid);
			init_dom_sid3(&(sid[1]), 0x0044, 0x0002, &user_sid);
	}

	init_samr_r_unknown_3(&r_u,
				0x0001, 0x8004,
				0x00000014, 0x0002, 0x0070,
				2, sid, status);

	DEBUG(5,("samr_unknown_3: %d\n", __LINE__));

	/* store the response in the SMB stream */
	if(!samr_io_r_unknown_3("", &r_u, rdata, 0))
		return False;

	DEBUG(5,("samr_unknown_3: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_enum_dom_users
 ********************************************************************/

static uint32 _samr_enum_dom_users(pipes_struct *p, SAMR_Q_ENUM_DOM_USERS *q_u, SAMR_R_ENUM_DOM_USERS *r_u)
{
	SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES];
	int num_entries;
	int total_entries;
	
	r_u->total_num_entries = 0;

	/* find the policy handle.  open a policy on it. */
	if (find_lsa_policy_by_hnd(&q_u->pol) == -1))
		return NT_STATUS_INVALID_HANDLE;

	DEBUG(5,("_samr_enum_dom_users: %d\n", __LINE__));

	become_root();
	get_sampwd_entries(pass, 0, &total_entries, &num_entries, MAX_SAM_ENTRIES, q_u->acb_mask);
	unbecome_root();

	init_samr_r_enum_dom_users(r_u, total_entries,
	                           q_u->unknown_0, num_entries,
	                           pass, r_u->status);

	DEBUG(5,("_samr_enum_dom_users: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_enum_dom_groups
 ********************************************************************/

static uint32 _samr_enum_dom_groups(pipes_struct *p, SAMR_Q_ENUM_DOM_GROUPS *q_u, SAMR_R_ENUM_DOM_GROUPS *r_u)
{
	SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES];
	int num_entries;
	BOOL got_grps;
	char *dummy_group = "Domain Admins";
	
	r_u->num_entries = 0;

	/* find the policy handle.  open a policy on it. */
	if (find_lsa_policy_by_hnd(&q_u->pol) == -1))
		return NT_STATUS_INVALID_HANDLE;

	DEBUG(5,("samr_reply_enum_dom_groups: %d\n", __LINE__));

	got_grps = True;
	num_entries = 1;
	ZERO_STRUCTP(&pass[0]);
	init_unistr2(&pass[0].uni_user_name, dummy_group, strlen(dummy_group)+1);
	pass[0].user_rid = DOMAIN_GROUP_RID_ADMINS;

	if (got_grps)
		init_samr_r_enum_dom_groups(r_u, q_u->start_idx, num_entries, pass, NT_STATUS_NOPROBLEMO);

	DEBUG(5,("samr_enum_dom_groups: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_enum_dom_aliases
 ********************************************************************/

static uint32 _samr_enum_dom_aliases(pipes_struct *p, SAMR_Q_ENUM_DOM_ALIASES *q_u, SAMR_R_ENUM_DOM_ALIASES *r_u)
{
	SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES];
	int num_entries = 0;
	DOM_SID sid;
	fstring sid_str;
	fstring sam_sid_str;
	struct group *grp;
	
	/* find the policy handle.  open a policy on it. */
	if (!get_lsa_policy_samr_sid(&q_u->pol, &sid))
		return NT_STATUS_INVALID_HANDLE;

	sid_to_string(sid_str, &sid);
	sid_to_string(sam_sid_str, &global_sam_sid);

	DEBUG(5,("samr_reply_enum_dom_aliases: sid %s\n", sid_str));

	/* well-known aliases */
	if (strequal(sid_str, "S-1-5-32")) {
		char *name;
		while (!lp_hide_local_users() &&
				num_entries < MAX_SAM_ENTRIES && 
				((name = builtin_alias_rids[num_entries].name) != NULL)) {
			init_unistr2(&pass[num_entries].uni_user_name, name, strlen(name)+1);
			pass[num_entries].user_rid = builtin_alias_rids[num_entries].rid;
			num_entries++;
		}
	} else if (strequal(sid_str, sam_sid_str) && !lp_hide_local_users()) {
		char *name;
		char *sep;

		sep = lp_winbind_separator();

		/* local aliases */
		/* we return the UNIX groups here.  This seems to be the right */
		/* thing to do, since NT member servers return their local     */
                /* groups in the same situation.                               */
		setgrent();

		while (num_entries < MAX_SAM_ENTRIES && ((grp = getgrent()) != NULL)) {
			int i;
			uint32 trid;
			name = grp->gr_name;

			/* Don't return winbind groups as they are not local! */

			if (strchr(name, *sep) != NULL)
				continue;

			trid = pdb_gid_to_group_rid(grp->gr_gid);
			for( i = 0; i < num_entries; i++)
				if ( pass[i].user_rid == trid ) break;

			if ( i < num_entries )
				continue; /* rid was there, dup! */

			init_unistr2(&(pass[num_entries].uni_user_name), name, strlen(name)+1);
			pass[num_entries].user_rid = trid;
			num_entries++;
		}

		endgrent();
	}
		
	init_samr_r_enum_dom_aliases(r_u, num_entries, pass, NT_STATUS_NOPROBLEMO);

	DEBUG(5,("samr_enum_dom_aliases: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

