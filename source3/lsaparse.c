/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Luke Leighton 1996 - 1997  Paul Ashton 1997
   
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

extern int DEBUGLEVEL;


/*******************************************************************
reads or writes an LSA_R_OPEN_POL structure.
********************************************************************/
char* lsa_io_r_open_pol(BOOL io, LSA_R_OPEN_POL *r_p, char *q, char *base, int align)
{
	if (r_p == NULL) return NULL;

	q = smb_io_pol_hnd(io, &(r_p->pol), q, base, align);

	RW_IVAL(io, q, r_p->status, 0); q += 4;

	return q;
}

/*******************************************************************
reads or writes an LSA_Q_QUERY_INFO structure.
********************************************************************/
char* lsa_io_q_query(BOOL io, LSA_Q_QUERY_INFO *q_q, char *q, char *base, int align)
{
	if (q_q == NULL) return NULL;

	q = smb_io_pol_hnd(io, &(q_q->pol), q, base, align);

	RW_SVAL(io, q, q_q->info_class, 0); q += 2;

	return q;
}

/*******************************************************************
reads or writes an LSA_Q_QUERY_INFO structure.
********************************************************************/
char* lsa_io_r_query(BOOL io, LSA_R_QUERY_INFO *r_q, char *q, char *base, int align)
{
	if (r_q == NULL) return NULL;

	RW_IVAL(io, q, r_q->undoc_buffer, 0); q += 4;

	if (r_q->undoc_buffer != 0)
	{
		RW_SVAL(io, q, r_q->info_class, 0); q += 2;

		switch (r_q->info_class)
		{
			case 3:
			{
				q = smb_io_dom_query_3(io, &(r_q->dom.id3), q, base, align);
				break;
			}
			case 5:
			{
				q = smb_io_dom_query_5(io, &(r_q->dom.id3), q, base, align);
				break;
			}
			default:
			{
				/* PANIC! */
				break;
			}
		}
	}

	RW_IVAL(io, q, r_q->status, 0); q += 4;

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_q_lookup_sids(BOOL io, LSA_Q_LOOKUP_SIDS *q_s, char *q, char *base, int align)
{
	int i;

	if (q_s == NULL) return NULL;

	q = align_offset(q, base, align);
	
    q = smb_io_pol_hnd(io, &(q_s->pol_hnd), q, base, align); /* policy handle */

	RW_IVAL(io, q, q_s->num_entries, 0); q += 4;
	RW_IVAL(io, q, q_s->buffer_dom_sid, 0); q += 4; /* undocumented domain SID buffer pointer */
	RW_IVAL(io, q, q_s->buffer_dom_name, 0); q += 4; /* undocumented domain name buffer pointer */

	for (i = 0; i < q_s->num_entries; i++)
	{
		RW_IVAL(io, q, q_s->buffer_lookup_sids[i], 0); q += 4; /* undocumented domain SID pointers to be looked up. */
	}

	for (i = 0; i < q_s->num_entries; i++)
	{
		q = smb_io_dom_sid(io, &(q_s->dom_sids[i]), q, base, align); /* domain SIDs to be looked up. */
	}

	RW_PCVAL(io, q, q_s->undoc, 16); q += 16; /* completely undocumented 16 bytes */

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_r_lookup_sids(BOOL io, LSA_R_LOOKUP_SIDS *r_s, char *q, char *base, int align)
{
	int i;

	if (r_s == NULL) return NULL;

	q = align_offset(q, base, align);
	
	q = smb_io_dom_r_ref(io, &(r_s->dom_ref), q, base, align); /* domain reference info */

	RW_IVAL(io, q, r_s->num_entries, 0); q += 4;
	RW_IVAL(io, q, r_s->undoc_buffer, 0); q += 4;
	RW_IVAL(io, q, r_s->num_entries2, 0); q += 4;

	for (i = 0; i < r_s->num_entries2; i++)
	{
		q = smb_io_dom_sid2(io, &(r_s->dom_sid[i]), q, base, align); /* domain SIDs being looked up */
	}

	RW_IVAL(io, q, r_s->num_entries3, 0); q += 4;

	RW_IVAL(io, q, r_s->status, 0); q += 4;

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_q_lookup_rids(BOOL io, LSA_Q_LOOKUP_RIDS *q_r, char *q, char *base, int align)
{
	int i;

	if (q_r == NULL) return NULL;

	q = align_offset(q, base, align);
	
    q = smb_io_pol_hnd(io, &(q_r->pol_hnd), q, base, align); /* policy handle */

	RW_IVAL(io, q, q_r->num_entries, 0); q += 4;
	RW_IVAL(io, q, q_r->num_entries2, 0); q += 4;
	RW_IVAL(io, q, q_r->buffer_dom_sid, 0); q += 4; /* undocumented domain SID buffer pointer */
	RW_IVAL(io, q, q_r->buffer_dom_name, 0); q += 4; /* undocumented domain name buffer pointer */

	for (i = 0; i < q_r->num_entries; i++)
	{
		q = smb_io_dom_name(io, &(q_r->lookup_name[i]), q, base, 0); /* names to be looked up */
	}

	RW_PCVAL(io, q, q_r->undoc, UNKNOWN_LEN); q += UNKNOWN_LEN; /* completely undocumented bytes of unknown length */

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_r_lookup_rids(BOOL io, LSA_R_LOOKUP_RIDS *r_r, char *q, char *base, int align)
{
	int i;

	if (r_r == NULL) return NULL;

	q = align_offset(q, base, align);
	
	q = smb_io_dom_r_ref(io, &(r_r->dom_ref), q, base, align); /* domain reference info */

	RW_IVAL(io, q, r_r->num_entries, 0); q += 4;
	RW_IVAL(io, q, r_r->undoc_buffer, 0); q += 4;
	RW_IVAL(io, q, r_r->num_entries2, 0); q += 4;

	for (i = 0; i < r_r->num_entries2; i++)
	{
		q = smb_io_dom_rid2(io, &(r_r->dom_rid[i]), q, base, align); /* domain RIDs being looked up */
	}

	RW_IVAL(io, q, r_r->num_entries3, 0); q += 4;

	RW_IVAL(io, q, r_r->status, 0); q += 4;

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_q_req_chal(BOOL io, LSA_Q_REQ_CHAL *q_c, char *q, char *base, int align)
{
	if (q_c == NULL) return NULL;

	q = align_offset(q, base, align);
    
	q = smb_io_unistr2(io, &(q_c->uni_logon_srv), q, base, align); /* logon server unicode string */
	q = smb_io_unistr2(io, &(q_c->uni_logon_clnt), q, base, align); /* logon client unicode string */
	q = smb_io_chal(io, &(q_c->clnt_chal), q, base, align); /* client challenge */

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_r_req_chal(BOOL io, LSA_R_REQ_CHAL *r_c, char *q, char *base, int align)
{
	if (r_c == NULL) return NULL;

	q = align_offset(q, base, align);
    
	q = smb_io_chal(io, &(r_c->srv_chal), q, base, align); /* server challenge */

	RW_IVAL(io, q, r_c->status, 0); q += 4;

	return q;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_q_auth_2(BOOL io, LSA_Q_AUTH_2 *q_a, char *q, char *base, int align)
{
	if (q_a == NULL) return NULL;

	q = align_offset(q, base, align);
    
	q = smb_io_log_info (io, &(q_a->clnt_id), q, base, align); /* client identification info */
	q = smb_io_chal     (io, &(q_a->clnt_chal), q, base, align); /* client-calculated credentials */
	q = smb_io_neg_flags(io, &(q_a->clnt_flgs), q, base, align);

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_r_auth_2(BOOL io, LSA_R_AUTH_2 *r_a, char *q, char *base, int align)
{
	if (r_a == NULL) return NULL;

	q = align_offset(q, base, align);
    
	q = smb_io_chal     (io, &(r_a->srv_chal), q, base, align); /* server challenge */
	q = smb_io_neg_flags(io, &(r_a->srv_flgs), q, base, align);

	RW_IVAL(io, q, r_a->status, 0); q += 4;

	return q;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_q_srv_pwset(BOOL io, LSA_Q_SRV_PWSET *q_s, char *q, char *base, int align)
{
	if (q_s == NULL) return NULL;

	q = align_offset(q, base, align);
    
	q = smb_io_clnt_info(io, &(q_s->clnt_id), q, base, align); /* client identification/authentication info */
	RW_PCVAL(io, q, q_s->pwd, 16); q += 16; /* new password - undocumented */

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_r_srv_pwset(BOOL io, LSA_R_SRV_PWSET *r_s, char *q, char *base, int align)
{
	if (r_s == NULL) return NULL;

	q = align_offset(q, base, align);
    
	q = smb_io_cred(io, &(r_s->srv_cred), q, base, align); /* server challenge */

	RW_IVAL(io, q, r_s->status, 0); q += 4;

	return q;
}

/* LSA_USER_INFO */

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_user_info(BOOL io, LSA_USER_INFO *usr, char *q, char *base, int align)
{
	int i;

	if (usr == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, usr->undoc_buffer, 0); q += 4;

	q = smb_io_time(io, &(usr->logon_time)           , q, base, align); /* logon time */
	q = smb_io_time(io, &(usr->logoff_time)          , q, base, align); /* logoff time */
	q = smb_io_time(io, &(usr->kickoff_time)         , q, base, align); /* kickoff time */
	q = smb_io_time(io, &(usr->pass_last_set_time)   , q, base, align); /* password last set time */
	q = smb_io_time(io, &(usr->pass_can_change_time) , q, base, align); /* password can change time */
	q = smb_io_time(io, &(usr->pass_must_change_time), q, base, align); /* password must change time */

	q = smb_io_unihdr(io, &(usr->hdr_user_name)   , q, base, align); /* username unicode string header */
	q = smb_io_unihdr(io, &(usr->hdr_full_name)   , q, base, align); /* user's full name unicode string header */
	q = smb_io_unihdr(io, &(usr->hdr_logon_script), q, base, align); /* logon script unicode string header */
	q = smb_io_unihdr(io, &(usr->hdr_profile_path), q, base, align); /* profile path unicode string header */
	q = smb_io_unihdr(io, &(usr->hdr_home_dir)    , q, base, align); /* home directory unicode string header */
	q = smb_io_unihdr(io, &(usr->hdr_dir_drive)   , q, base, align); /* home directory drive unicode string header */

	RW_SVAL(io, q, usr->logon_count , 0); q += 2;  /* logon count */
	RW_SVAL(io, q, usr->bad_pw_count, 0); q += 2; /* bad password count */

	RW_IVAL(io, q, usr->user_id      , 0); q += 4;       /* User ID */
	RW_IVAL(io, q, usr->group_id     , 0); q += 4;      /* Group ID */
	RW_IVAL(io, q, usr->num_groups   , 0); q += 4;    /* num groups */
	RW_IVAL(io, q, usr->buffer_groups, 0); q += 4; /* undocumented buffer pointer to groups. */
	RW_IVAL(io, q, usr->user_flgs    , 0); q += 4;     /* user flags */

	RW_PCVAL(io, q, usr->sess_key, 16); q += 16; /* unused user session key */

	q = smb_io_unihdr(io, &(usr->hdr_logon_srv), q, base, align); /* logon server unicode string header */
	q = smb_io_unihdr(io, &(usr->hdr_logon_dom), q, base, align); /* logon domain unicode string header */

	RW_IVAL(io, q, usr->buffer_dom_id, 0); q += 4; /* undocumented logon domain id pointer */
	RW_PCVAL(io, q, usr->padding, 40); q += 40; /* unused padding bytes? */

	RW_IVAL(io, q, usr->num_other_sids, 0); q += 4; /* 0 - num_sids */
	RW_IVAL(io, q, usr->buffer_other_sids, 0); q += 4; /* NULL - undocumented pointer to SIDs. */
	
	q = smb_io_unistr2(io, &(usr->uni_user_name)   , q, base, align); /* username unicode string */
	q = smb_io_unistr2(io, &(usr->uni_full_name)   , q, base, align); /* user's full name unicode string */
	q = smb_io_unistr2(io, &(usr->uni_logon_script), q, base, align); /* logon script unicode string */
	q = smb_io_unistr2(io, &(usr->uni_profile_path), q, base, align); /* profile path unicode string */
	q = smb_io_unistr2(io, &(usr->uni_home_dir)    , q, base, align); /* home directory unicode string */
	q = smb_io_unistr2(io, &(usr->uni_dir_drive)   , q, base, align); /* home directory drive unicode string */

	RW_IVAL(io, q, usr->num_groups2, 0); q += 4;        /* num groups */
	for (i = 0; i < usr->num_groups2; i++)
	{
		q = smb_io_gid(io, &(usr->gids[i]), q, base, align); /* group info */
	}

	q = smb_io_unistr2(io, &( usr->uni_logon_srv), q, base, align); /* logon server unicode string */
	q = smb_io_unistr2(io, &( usr->uni_logon_dom), q, base, align); /* logon domain unicode string */

	q = smb_io_dom_sid(io, &(usr->dom_sid), q, base, align);           /* domain SID */

	for (i = 0; i < usr->num_other_sids; i++)
	{
		q = smb_io_dom_sid(io, &(usr->other_sids[i]), q, base, align); /* other domain SIDs */
	}

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_q_sam_logon(BOOL io, LSA_Q_SAM_LOGON *q_l, char *q, char *base, int align)
{
	if (q_l == NULL) return NULL;

	q = align_offset(q, base, align);
	
	q = smb_io_sam_info(io, &(q_l->sam_id), q, base, align);           /* domain SID */

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_r_sam_logon(BOOL io, LSA_R_SAM_LOGON *r_l, char *q, char *base, int align)
{
	if (r_l == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, r_l->buffer_creds, 0); q += 4; /* undocumented buffer pointer */
	q = smb_io_cred(io, &(r_l->srv_creds), q, base, align); /* server credentials.  server time stamp appears to be ignored. */

	RW_IVAL(io, q, r_l->buffer_user, 0); q += 4;
	if (r_l->buffer_user != 0)
	{
		q = lsa_io_user_info(io, r_l->user, q, base, align);
	}

	RW_IVAL(io, q, r_l->auth_resp, 0); q += 4; /* 1 - Authoritative response; 0 - Non-Auth? */

	RW_IVAL(io, q, r_l->status, 0); q += 4;

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_q_sam_logoff(BOOL io, LSA_Q_SAM_LOGOFF *q_l, char *q, char *base, int align)
{
	if (q_l == NULL) return NULL;

	q = align_offset(q, base, align);
	
	q = smb_io_sam_info(io, &(q_l->sam_id), q, base, align);           /* domain SID */

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* lsa_io_r_sam_logoff(BOOL io, LSA_R_SAM_LOGOFF *r_l, char *q, char *base, int align)
{
	if (r_l == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, r_l->buffer_creds, 0); q += 4; /* undocumented buffer pointer */
	q = smb_io_cred(io, &(r_l->srv_creds), q, base, align); /* server credentials.  server time stamp appears to be ignored. */

	RW_IVAL(io, q, r_l->status, 0); q += 4;

	return q;
}

#if 0
/*******************************************************************
reads or writes a structure.
********************************************************************/
 char* lsa_io_(BOOL io, *, char *q, char *base, int align)
{
	if (== NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, , 0); q += 4;

	return q;
}
#endif
