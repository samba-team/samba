/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Pipe SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1997,
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997.
   Copyright (C) Paul Ashton  1997.
   
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
/*
   This file handles reply_ calls on named pipes that the server
   makes to handle specific protocols
*/


#include "includes.h"
#include "trans2.h"
#include "nterr.h"

extern int DEBUGLEVEL;

extern BOOL sam_logon_in_ssb;
extern pstring samlogon_user;

#ifdef NTDOMAIN

static void make_lsa_r_req_chal(LSA_R_REQ_CHAL *r_c,
                                DOM_CHAL *srv_chal, int status)
{
	DEBUG(6,("make_lsa_r_req_chal: %d\n", __LINE__));
	memcpy(r_c->srv_chal.data, srv_chal->data, sizeof(srv_chal->data));
	r_c->status = status;
}

static int lsa_reply_req_chal(LSA_Q_REQ_CHAL *q_c, char *q, char *base,
					DOM_CHAL *srv_chal)
{
	LSA_R_REQ_CHAL r_c;

	DEBUG(6,("lsa_reply_req_chal: %d\n", __LINE__));

	/* set up the LSA REQUEST CHALLENGE response */
	make_lsa_r_req_chal(&r_c, srv_chal, 0);

	/* store the response in the SMB stream */
	q = lsa_io_r_req_chal(False, &r_c, q, base, 4, 0);

	DEBUG(6,("lsa_reply_req_chal: %d\n", __LINE__));

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

static void make_lsa_r_auth_2(LSA_R_AUTH_2 *r_a,
                              DOM_CHAL *resp_cred, NEG_FLAGS *flgs, int status)
{
	memcpy(  r_a->srv_chal.data, resp_cred->data, sizeof(resp_cred->data));
	memcpy(&(r_a->srv_flgs)    , flgs           , sizeof(r_a->srv_flgs));
	r_a->status = status;
}

static int lsa_reply_auth_2(LSA_Q_AUTH_2 *q_a, char *q, char *base,
				DOM_CHAL *resp_cred, int status)
{
	LSA_R_AUTH_2 r_a;

	/* set up the LSA AUTH 2 response */

	make_lsa_r_auth_2(&r_a, resp_cred, &(q_a->clnt_flgs), status);

	/* store the response in the SMB stream */
	q = lsa_io_r_auth_2(False, &r_a, q, base, 4, 0);

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

static void make_lsa_r_srv_pwset(LSA_R_SRV_PWSET *r_s,
                             DOM_CRED *srv_cred, int status)  
{
	DEBUG(5,("make_lsa_r_srv_pwset: %d\n", __LINE__));

	memcpy(&(r_s->srv_cred), srv_cred, sizeof(r_s->srv_cred));
	r_s->status = status;

	DEBUG(5,("make_lsa_r_srv_pwset: %d\n", __LINE__));
}

static int lsa_reply_srv_pwset(LSA_Q_SRV_PWSET *q_s, char *q, char *base,
				DOM_CRED *srv_cred, int status)
{
	LSA_R_SRV_PWSET r_s;

	DEBUG(5,("lsa_srv_pwset: %d\n", __LINE__));

	/* set up the LSA Server Password Set response */
	make_lsa_r_srv_pwset(&r_s, srv_cred, status);

	/* store the response in the SMB stream */
	q = lsa_io_r_srv_pwset(False, &r_s, q, base, 4, 0);

	DEBUG(5,("lsa_srv_pwset: %d\n", __LINE__));

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

static void make_lsa_user_info(LSA_USER_INFO *usr,

	NTTIME *logon_time,
	NTTIME *logoff_time,
	NTTIME *kickoff_time,
	NTTIME *pass_last_set_time,
	NTTIME *pass_can_change_time,
	NTTIME *pass_must_change_time,

	char *user_name,
	char *full_name,
	char *logon_script,
	char *profile_path,
	char *home_dir,
	char *dir_drive,

	uint16 logon_count,
	uint16 bad_pw_count,

	uint32 user_id,
	uint32 group_id,
	uint32 num_groups,
	DOM_GID *gids,
	uint32 user_flgs,

	char sess_key[16],

	char *logon_srv,
	char *logon_dom,

	char *dom_sid,
	char *other_sids) /* space-delimited set of SIDs */ 
{
	/* only cope with one "other" sid, right now. */
	/* need to count the number of space-delimited sids */
	int i;
	int num_other_sids = 0;

	int len_user_name    = strlen(user_name   );
	int len_full_name    = strlen(full_name   );
	int len_logon_script = strlen(logon_script);
	int len_profile_path = strlen(profile_path);
	int len_home_dir     = strlen(home_dir    );
	int len_dir_drive    = strlen(dir_drive   );

	int len_logon_srv    = strlen(logon_srv);
	int len_logon_dom    = strlen(logon_dom);

	usr->ptr_user_info = 1; /* yes, we're bothering to put USER_INFO data here */

	usr->logon_time            = *logon_time;
	usr->logoff_time           = *logoff_time;
	usr->kickoff_time          = *kickoff_time;
	usr->pass_last_set_time    = *pass_last_set_time;
	usr->pass_can_change_time  = *pass_can_change_time;
	usr->pass_must_change_time = *pass_must_change_time;

	make_uni_hdr(&(usr->hdr_user_name   ), len_user_name   , len_user_name   , 4);
	make_uni_hdr(&(usr->hdr_full_name   ), len_full_name   , len_full_name   , 4);
	make_uni_hdr(&(usr->hdr_logon_script), len_logon_script, len_logon_script, 4);
	make_uni_hdr(&(usr->hdr_profile_path), len_profile_path, len_profile_path, 4);
	make_uni_hdr(&(usr->hdr_home_dir    ), len_home_dir    , len_home_dir    , 4);
	make_uni_hdr(&(usr->hdr_dir_drive   ), len_dir_drive   , len_dir_drive   , 4);

	usr->logon_count = logon_count;
	usr->bad_pw_count = bad_pw_count;

	usr->user_id = user_id;
	usr->group_id = group_id;
	usr->num_groups = num_groups;
	usr->buffer_groups = 1; /* indicates fill in groups, below, even if there are none */
	usr->user_flgs = user_flgs;

	if (sess_key != NULL)
	{
		memcpy(usr->sess_key, sess_key, sizeof(usr->sess_key));
	}
	else
	{
		bzero(usr->sess_key, sizeof(usr->sess_key));
	}

	make_uni_hdr(&(usr->hdr_logon_srv), len_logon_srv, len_logon_srv, 4);
	make_uni_hdr(&(usr->hdr_logon_dom), len_logon_dom, len_logon_dom, 4);

	usr->buffer_dom_id = dom_sid ? 1 : 0; /* yes, we're bothering to put a domain SID in */

	bzero(usr->padding, sizeof(usr->padding));

	num_other_sids = make_dom_sids(other_sids, usr->other_sids, LSA_MAX_SIDS);

	usr->num_other_sids = num_other_sids;
	usr->buffer_other_sids = num_other_sids != 0 ? 1 : 0; 
	
	make_unistr2(&(usr->uni_user_name   ), user_name   , len_user_name   );
	make_unistr2(&(usr->uni_full_name   ), full_name   , len_full_name   );
	make_unistr2(&(usr->uni_logon_script), logon_script, len_logon_script);
	make_unistr2(&(usr->uni_profile_path), profile_path, len_profile_path);
	make_unistr2(&(usr->uni_home_dir    ), home_dir    , len_home_dir    );
	make_unistr2(&(usr->uni_dir_drive   ), dir_drive   , len_dir_drive   );

	usr->num_groups2 = num_groups;
	for (i = 0; i < num_groups; i++)
	{
		usr->gids[i] = gids[i];
	}

	make_unistr2(&(usr->uni_logon_srv), logon_srv, len_logon_srv);
	make_unistr2(&(usr->uni_logon_dom), logon_dom, len_logon_dom);

	make_dom_sid(&(usr->dom_sid), dom_sid);
	/* "other" sids are set up above */
}


static int lsa_reply_sam_logon(LSA_Q_SAM_LOGON *q_s, char *q, char *base,
				DOM_CRED *srv_cred, LSA_USER_INFO *user_info)
{
	LSA_R_SAM_LOGON r_s;

	/* XXXX maybe we want to say 'no', reject the client's credentials */
	r_s.buffer_creds = 1; /* yes, we have valid server credentials */
	memcpy(&(r_s.srv_creds), srv_cred, sizeof(r_s.srv_creds));

	/* store the user information, if there is any. */
	r_s.user = user_info;
	if (user_info != NULL && user_info->ptr_user_info != 0)
	{
		r_s.switch_value = 3; /* indicates type of validation user info */
		r_s.status = 0;
	}
	else
	{
		r_s.switch_value = 0; /* don't know what this value is supposed to be */
		r_s.status = 0xC000000|NT_STATUS_NO_SUCH_USER;
	}

	r_s.auth_resp = 1; /* authoritative response */

	/* store the response in the SMB stream */
	q = lsa_io_r_sam_logon(False, &r_s, q, base, 4, 0);

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}


static int lsa_reply_sam_logoff(LSA_Q_SAM_LOGOFF *q_s, char *q, char *base,
				DOM_CRED *srv_cred, 
				uint32 status)
{
	LSA_R_SAM_LOGOFF r_s;

	/* XXXX maybe we want to say 'no', reject the client's credentials */
	r_s.buffer_creds = 1; /* yes, we have valid server credentials */
	memcpy(&(r_s.srv_creds), srv_cred, sizeof(r_s.srv_creds));

	r_s.status = status;

	/* store the response in the SMB stream */
	q = lsa_io_r_sam_logoff(False, &r_s, q, base, 4, 0);

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}


static BOOL update_dcinfo(int cnum, uint16 vuid,
		struct dcinfo *dc, DOM_CHAL *clnt_chal, char *mach_acct)
{
    struct smb_passwd *smb_pass;
	int i;

	unbecome_user();
	smb_pass = get_smbpwnam(mach_acct);
	if (!become_user(cnum, vuid))
	{
		DEBUG(0,("update_dcinfo: become_user failed\n"));
		return False;
	}

	if (smb_pass != NULL)
	{
		memcpy(dc->md4pw, smb_pass->smb_nt_passwd, sizeof(dc->md4pw));
		DEBUG(5,("dc->md4pw(%d) :", sizeof(dc->md4pw)));
		dump_data(5, dc->md4pw, 16);
	}
	else
	{
		/* No such machine account. Should error out here, but we'll
		   print and carry on */
		DEBUG(1,("No account in domain for %s\n", mach_acct));
		return False;
	}

	{
		fstring foo;
		for (i = 0; i < 16; i++) sprintf(foo+i*2,"%02x ", dc->md4pw[i]);
		DEBUG(4,("pass %s %s\n", mach_acct, foo));
	}

	/* copy the client credentials */
	memcpy(dc->clnt_chal.data, clnt_chal->data, sizeof(clnt_chal->data));
	memcpy(dc->clnt_cred.data, clnt_chal->data, sizeof(clnt_chal->data));

	/* create a server challenge for the client */
	/* PAXX: set these to random values. */
	/* lkcl: paul, you mentioned that it doesn't really matter much */
	dc->srv_chal.data[0] = 0x11111111;
	dc->srv_chal.data[1] = 0x11111111;
	dc->srv_cred.data[0] = 0x11111111;
	dc->srv_cred.data[1] = 0x11111111;

	/* from client / server challenges and md4 password, generate sess key */
	cred_session_key(&(dc->clnt_chal), &(dc->srv_chal),
	                   dc->md4pw, dc->sess_key);

	DEBUG(6,("update_dcinfo: %d\n", __LINE__));

	return True;
}

static void api_lsa_req_chal( int cnum, uint16 vuid,
                              user_struct *vuser,
                              char *param, char *data,
                              char **rdata, int *rdata_len )
{
	LSA_Q_REQ_CHAL q_r;

	fstring mach_acct;

	/* grab the challenge... */
	lsa_io_q_req_chal(True, &q_r, data + 0x18, data, 4, 0);

	fstrcpy(mach_acct, unistrn2(q_r.uni_logon_clnt.buffer,
	                            q_r.uni_logon_clnt.uni_str_len));

	strcat(mach_acct, "$");

	DEBUG(6,("q_r.clnt_chal.data: %lx %lx\n",
	         q_r.clnt_chal.data[0], q_r.clnt_chal.data[1]));

	update_dcinfo(cnum, vuid, &(vuser->dc), &(q_r.clnt_chal), mach_acct);

	/* construct reply.  return status is always 0x0 */
	*rdata_len = lsa_reply_req_chal(&q_r, *rdata + 0x18, *rdata,
					&(vuser->dc.srv_chal));

}

static void api_lsa_auth_2( user_struct *vuser,
                            char *param, char *data,
                            char **rdata, int *rdata_len )
{
	LSA_Q_AUTH_2 q_a;

	DOM_CHAL srv_cred;
	UTIME srv_time;

	srv_time.time = 0;

	/* grab the challenge... */
	lsa_io_q_auth_2(True, &q_a, data + 0x18, data, 4, 0);

	/* check that the client credentials are valid */
	cred_assert(&(q_a.clnt_chal), vuser->dc.sess_key,
                &(vuser->dc.clnt_cred), srv_time);

	/* create server challenge for inclusion in the reply */
	cred_create(vuser->dc.sess_key, &(vuser->dc.srv_cred), srv_time, &srv_cred);

	/* copy the received client credentials for use next time */
	memcpy(vuser->dc.clnt_cred.data, &(q_a.clnt_chal.data), sizeof(q_a.clnt_chal.data));
	memcpy(vuser->dc.srv_cred .data, &(q_a.clnt_chal.data), sizeof(q_a.clnt_chal.data));

	/* construct reply. */
	*rdata_len = lsa_reply_auth_2(&q_a, *rdata + 0x18, *rdata,
					&srv_cred, 0x0);
}


static BOOL deal_with_credentials(user_struct *vuser,
			DOM_CRED *clnt_cred, DOM_CRED *srv_cred)
{
	UTIME new_clnt_time;
	uint32 new_cred;

	DEBUG(5,("deal_with_credentials: %d\n", __LINE__));

	/* increment client time by one second */
	new_clnt_time.time = clnt_cred->timestamp.time + 1;

	/* first 4 bytes of the new seed is old client 4 bytes + clnt time + 1 */
	new_cred = IVAL(vuser->dc.clnt_cred.data, 0);
	new_cred += new_clnt_time.time;

	DEBUG(5,("deal_with_credentials: new_cred[0]=%lx\n", new_cred));

	/* doesn't matter that server time is 0 */
	srv_cred->timestamp.time = 0;

	/* check that the client credentials are valid */
	if (!cred_assert(&(clnt_cred->challenge), vuser->dc.sess_key,
                    &(vuser->dc.clnt_cred), clnt_cred->timestamp))
	{
		return False;
	}

	DEBUG(5,("deal_with_credentials: new_clnt_time=%lx\n", new_clnt_time.time));

	/* create server credentials for inclusion in the reply */
	cred_create(vuser->dc.sess_key, &(vuser->dc.clnt_cred), new_clnt_time,
	            &(srv_cred->challenge));
	
	DEBUG(5,("deal_with_credentials: clnt_cred[0]=%lx\n",
	          vuser->dc.clnt_cred.data[0]));

	/* store new seed in client and server credentials */
	SIVAL(vuser->dc.clnt_cred.data, 0, new_cred);
	SIVAL(vuser->dc.srv_cred .data, 0, new_cred);

	return True;
}

static void api_lsa_srv_pwset( user_struct *vuser,
                               char *param, char *data,
                               char **rdata, int *rdata_len )
{
	LSA_Q_SRV_PWSET q_a;

	DOM_CRED srv_cred;

	/* grab the challenge and encrypted password ... */
	lsa_io_q_srv_pwset(True, &q_a, data + 0x18, data, 4, 0);

	/* checks and updates credentials.  creates reply credentials */
	deal_with_credentials(vuser, &(q_a.clnt_id.cred), &srv_cred);

	DEBUG(5,("api_lsa_srv_pwset: %d\n", __LINE__));

	/* construct reply.  always indicate failure.  nt keeps going... */
	*rdata_len = lsa_reply_srv_pwset(&q_a, *rdata + 0x18, *rdata,
					&srv_cred,
	                NT_STATUS_WRONG_PASSWORD|0xC0000000);
}


static void api_lsa_sam_logoff( user_struct *vuser,
                               char *param, char *data,
                               char **rdata, int *rdata_len )
{
	LSA_Q_SAM_LOGOFF q_l;

	DOM_CRED srv_cred;

	/* grab the challenge... */
	lsa_io_q_sam_logoff(True, &q_l, data + 0x18, data, 4, 0);

	/* checks and updates credentials.  creates reply credentials */
	deal_with_credentials(vuser, &(q_l.sam_id.client.cred), &srv_cred);

	/* construct reply.  always indicate success */
	*rdata_len = lsa_reply_sam_logoff(&q_l, *rdata + 0x18, *rdata,
					&srv_cred,
	                0x0);
}


static void api_lsa_sam_logon( user_struct *vuser,
                               char *param, char *data,
                               char **rdata, int *rdata_len )
{
	LSA_Q_SAM_LOGON q_l;
	LSA_USER_INFO usr_info;

	DOM_CRED srv_creds;

	lsa_io_q_sam_logon(True, &q_l, data + 0x18, data, 4, 0);

	/* checks and updates credentials.  creates reply credentials */
	deal_with_credentials(vuser, &(q_l.sam_id.client.cred), &srv_creds);

	usr_info.ptr_user_info = 0;

	if (vuser != NULL)
	{
		DOM_GID gids[LSA_MAX_GROUPS];
		int num_gids;
		NTTIME dummy_time;
		pstring logon_script;
		pstring profile_path;
		pstring home_dir;
		pstring home_drive;
		pstring my_name;
		pstring my_workgroup;
		pstring domain_groups;
		pstring dom_sid;
		pstring other_sids;
		fstring tmp;
		extern pstring myname;
		uint32 r_uid;
		uint32 r_gid;

		dummy_time.low  = 0xffffffff;
		dummy_time.high = 0x7fffffff;

		get_myname(myname, NULL);

		pstrcpy(samlogon_user, unistr2(q_l.sam_id.auth.id1.uni_user_name.buffer));

		DEBUG(3,("SAM Logon. Domain:[%s].  User:[%s]\n",
		          lp_workgroup(), samlogon_user));

		/* hack to get standard_sub_basic() to use the sam logon username */
		sam_logon_in_ssb = True;

		pstrcpy(logon_script, lp_logon_script     ());
		pstrcpy(profile_path, lp_logon_path       ());
		pstrcpy(dom_sid     , lp_domain_sid       ());
		pstrcpy(other_sids  , lp_domain_other_sids());
		pstrcpy(my_workgroup, lp_workgroup        ());

		pstrcpy(home_drive  , lp_logon_drive      ());
		pstrcpy(home_dir    , lp_logon_home       ());

		/* any additional groups this user is in.  e.g power users */
		pstrcpy(domain_groups, lp_domain_groups());

		/* can only be a user or a guest.  cannot be guest _and_ admin */
		if (user_in_list(samlogon_user, lp_domain_guest_users()))
		{
			sprintf(tmp, " %ld/7 ", DOMAIN_GROUP_RID_GUESTS);
			strcat(domain_groups, tmp);

			DEBUG(3,("domain guest access %s granted\n", tmp));
		}
		else
		{
			sprintf(tmp, " %ld/7 ", DOMAIN_GROUP_RID_USERS);
			strcat(domain_groups, tmp);

			DEBUG(3,("domain user access %s granted\n", tmp));

			if (user_in_list(samlogon_user, lp_domain_admin_users()))
			{
				sprintf(tmp, " %ld/7 ", DOMAIN_GROUP_RID_ADMINS);
				strcat(domain_groups, tmp);

				DEBUG(3,("domain admin access %s granted\n", tmp));
			}
		}

		num_gids = make_dom_gids(domain_groups, gids);

		sam_logon_in_ssb = False;

		pstrcpy(my_name     , myname           );
		strupper(my_name);

		if (name_to_rid(samlogon_user, &r_uid, &r_gid))
		{
			make_lsa_user_info(&usr_info,

		               &dummy_time, /* logon_time */
		               &dummy_time, /* logoff_time */
		               &dummy_time, /* kickoff_time */
		               &dummy_time, /* pass_last_set_time */
		               &dummy_time, /* pass_can_change_time */
		               &dummy_time, /* pass_must_change_time */

		               samlogon_user, /* user_name */
		               vuser->real_name, /* full_name */
		               logon_script, /* logon_script */
		               profile_path, /* profile_path */
		               home_dir, /* home_dir */
		               home_drive, /* dir_drive */

		               0, /* logon_count */
		               0, /* bad_pw_count */

		               r_uid, /* RID user_id */
		               r_gid, /* RID group_id */
		               num_gids,    /* uint32 num_groups */
		               gids, /* DOM_GID *gids */
		               0x20, /* uint32 user_flgs */

		               NULL, /* char sess_key[16] */

		               my_name     , /* char *logon_srv */
		               my_workgroup, /* char *logon_dom */

		               dom_sid,     /* char *dom_sid */
		               other_sids); /* char *other_sids */
		}
	}

	*rdata_len = lsa_reply_sam_logon(&q_l, *rdata + 0x18, *rdata,
					&srv_creds, &usr_info);
}


BOOL api_netlogrpcTNP(int cnum,int uid, char *param,char *data,
		     int mdrcnt,int mprcnt,
		     char **rdata,char **rparam,
		     int *rdata_len,int *rparam_len)
{
	user_struct *vuser;

	RPC_HDR hdr;

	if (data == NULL)
	{
		DEBUG(2,("api_netlogrpcTNP: NULL data received\n"));
		return False;
	}

	smb_io_rpc_hdr(True, &hdr, data, data, 4, 0);

	if (hdr.pkt_type == RPC_BIND) /* RPC BIND */
	{
		DEBUG(4,("netlogon rpc bind %x\n",hdr.pkt_type));
		LsarpcTNP1(data,rdata,rdata_len);
		return True;
	}

	DEBUG(4,("netlogon TransactNamedPipe op %x\n",hdr.cancel_count));

	if ((vuser = get_valid_user_struct(uid)) == NULL) return False;

	DEBUG(3,("Username of UID %d is %s\n", vuser->uid, vuser->name));

	switch (hdr.cancel_count)
	{
		case LSA_REQCHAL:
		{
			DEBUG(3,("LSA_REQCHAL\n"));
			api_lsa_req_chal(cnum, uid, vuser, param, data, rdata, rdata_len);
			create_rpc_reply(hdr.call_id, *rdata, *rdata_len);
			break;
		}

		case LSA_AUTH2:
		{
			DEBUG(3,("LSA_AUTH2\n"));
			api_lsa_auth_2(vuser, param, data, rdata, rdata_len);
			create_rpc_reply(hdr.call_id, *rdata, *rdata_len);
			break;
		}

		case LSA_SRVPWSET:
		{
			DEBUG(3,("LSA_SRVPWSET\n"));
			api_lsa_srv_pwset(vuser, param, data, rdata, rdata_len);
			create_rpc_reply(hdr.call_id, *rdata, *rdata_len);
			break;
		}

		case LSA_SAMLOGON:
		{
			DEBUG(3,("LSA_SAMLOGON\n"));
			api_lsa_sam_logon(vuser, param, data, rdata, rdata_len);
			create_rpc_reply(hdr.call_id, *rdata, *rdata_len);
			break;
		}

		case LSA_SAMLOGOFF:
		{
			DEBUG(3,("LSA_SAMLOGOFF\n"));
			api_lsa_sam_logoff(vuser, param, data, rdata, rdata_len);
			create_rpc_reply(hdr.call_id, *rdata, *rdata_len);
			break;
		}

		default:
		{
  			DEBUG(4, ("**** netlogon, unknown code: %lx\n", hdr.cancel_count));
			break;
		}
	}

	return True;
}

#endif /* NTDOMAIN */
