
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

extern int DEBUGLEVEL;


/****************************************************************************
do a LSA Open Policy
****************************************************************************/
BOOL lsa_open_policy(struct cli_state *cli, uint16 fnum,
			char *server_name, POLICY_HND *hnd,
			BOOL sec_qos)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_OPEN_POL q_o;
	LSA_SEC_QOS qos;
	BOOL valid_pol = False;

	if (hnd == NULL) return False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api LSA_OPENPOLICY */

	DEBUG(4,("LSA Open Policy\n"));

	/* store the parameters */
	if (sec_qos)
	{
		make_lsa_sec_qos(&qos, 2, 1, 0, 0x20000000);
		make_q_open_pol(&q_o, 0x5c, 0, 0, &qos);
	}
	else
	{
		make_q_open_pol(&q_o, 0x5c, 0, 0x1, NULL);
	}

	/* turn parameters into data stream */
	lsa_io_q_open_pol("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, fnum, LSA_OPENPOLICY, &buf, &rbuf))
	{
		LSA_R_OPEN_POL r_o;
		BOOL p;

		lsa_io_r_open_pol("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_OPENPOLICY: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the policy handle */
			memcpy(hnd, r_o.pol.data, sizeof(hnd->data));
			valid_pol = True;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_pol;
}

/****************************************************************************
do a LSA Lookup Names
****************************************************************************/
BOOL lsa_lookup_names(struct cli_state *cli, uint16 fnum,
			POLICY_HND *hnd,
			int num_names,
			const char **names,
			DOM_SID **sids,
			int *num_sids)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_LOOKUP_NAMES q_l;
	BOOL valid_response = False;

	if (hnd == NULL || num_sids == 0 || sids == NULL) return False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api LSA_LOOKUP_NAMES */

	DEBUG(4,("LSA Lookup NAMEs\n"));

	/* store the parameters */
	make_q_lookup_names(&q_l, hnd, num_names, names);

	/* turn parameters into data stream */
	lsa_io_q_lookup_names("", &q_l, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, fnum, LSA_LOOKUPNAMES, &buf, &rbuf))
	{
		LSA_R_LOOKUP_NAMES r_l;
		DOM_R_REF ref;
		DOM_RID2 t_rids[MAX_LOOKUP_SIDS];
		BOOL p;

		ZERO_STRUCT(ref);
		ZERO_STRUCT(t_rids);

		r_l.dom_ref = &ref;
		r_l.dom_rid = t_rids;

		lsa_io_r_lookup_names("", &r_l, &rbuf, 0);
		p = rbuf.offset != 0;
		
		if (p && r_l.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_LOOKUP_NAMES: %s\n", get_nt_error_msg(r_l.status)));
			p = False;
		}

		if (p)
		{
			if (r_l.undoc_buffer != 0 && ref.undoc_buffer != 0)
			{
				valid_response = True;
			}
		}

		if (num_sids != NULL && valid_response)
		{
			(*num_sids) = r_l.num_entries;
		}
		if (valid_response)
		{
			int i;
			for (i = 0; i < r_l.num_entries; i++)
			{
				if (t_rids[i].rid_idx >= ref.num_ref_doms_1 &&
				    t_rids[i].rid_idx != 0xffffffff)
				{
					DEBUG(0,("LSA_LOOKUP_NAMES: domain index %d out of bounds\n",
					          t_rids[i].rid_idx));
					valid_response = False;
					break;
				}
			}
		}

		if (sids != NULL && valid_response && r_l.num_entries != 0)
		{
			(*sids) = (DOM_SID*)malloc((*num_sids) * sizeof(DOM_SID));
		}

		if (sids != NULL && (*sids) != NULL)
		{
			int i;
			/* take each name, construct a SID */
			for (i = 0; i < (*num_sids); i++)
			{
				uint32 dom_idx = t_rids[i].rid_idx;
				uint32 dom_rid = t_rids[i].rid;
				DOM_SID *sid = &(*sids)[i];
				if (dom_idx != 0xffffffff)
				{
					sid_copy(sid, &ref.ref_dom[dom_idx].ref_dom.sid);
					if (dom_rid != 0xffffffff)
					{
					sid_append_rid(sid, dom_rid);
					}
				}
				else
				{
					ZERO_STRUCTP(sid);
				}
			}
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_response;
}

/****************************************************************************
do a LSA Lookup SIDs
****************************************************************************/
BOOL lsa_lookup_sids(struct cli_state *cli, uint16 fnum,
			POLICY_HND *hnd,
			int num_sids,
			DOM_SID **sids,
			char ***names,
			int *num_names)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_LOOKUP_SIDS q_l;
	BOOL valid_response = False;

	if (hnd == NULL || num_sids == 0 || sids == NULL) return False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api LSA_LOOKUP_SIDS */

	DEBUG(4,("LSA Lookup SIDs\n"));

	/* store the parameters */
	make_q_lookup_sids(&q_l, hnd, num_sids, sids, 1);

	/* turn parameters into data stream */
	lsa_io_q_lookup_sids("", &q_l, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, fnum, LSA_LOOKUPSIDS, &buf, &rbuf))
	{
		LSA_R_LOOKUP_SIDS r_l;
		DOM_R_REF ref;
		LSA_TRANS_NAME_ENUM t_names;
		BOOL p;

		r_l.dom_ref = &ref;
		r_l.names   = &t_names;

		lsa_io_r_lookup_sids("", &r_l, &rbuf, 0);
		p = rbuf.offset != 0;
		
		if (p && r_l.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_LOOKUP_SIDS: %s\n", get_nt_error_msg(r_l.status)));
			p = False;
		}

		if (p)
		{
			if (t_names.ptr_trans_names != 0 && ref.undoc_buffer != 0)
			{
				valid_response = True;
			}
		}

		if (num_names != NULL && valid_response)
		{
			(*num_names) = t_names.num_entries;
		}
		if (valid_response)
		{
			int i;
			for (i = 0; i < t_names.num_entries; i++)
			{
				if (t_names.name[i].domain_idx >= ref.num_ref_doms_1)
				{
					DEBUG(0,("LSA_LOOKUP_SIDS: domain index out of bounds\n"));
					valid_response = False;
					break;
				}
			}
		}

		if (names != NULL && valid_response && t_names.num_entries != 0)
		{
			(*names) = (char**)malloc((*num_names) * sizeof(char*));
		}

		if (names != NULL && (*names) != NULL)
		{
			int i;
			/* take each name, construct a \DOMAIN\name string */
			for (i = 0; i < (*num_names); i++)
			{
				fstring name;
				fstring dom_name;
				fstring full_name;
				uint32 dom_idx = t_names.name[i].domain_idx;

				if (dom_idx != 0xffffffff)
				{
					fstrcpy(dom_name, unistr2_to_str(&ref.ref_dom[dom_idx].uni_dom_name));
					fstrcpy(name    , unistr2_to_str(&t_names.uni_name[i]));
					
					memset(full_name, 0, sizeof(full_name));

					slprintf(full_name, sizeof(full_name)-1, "%s\\%s",
						 dom_name, name);

					(*names)[i] = strdup(full_name);
				}
				else
				{
					(*names)[i] = NULL;
				}
			}
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_response;
}

/****************************************************************************
do a LSA Query Info Policy
****************************************************************************/
BOOL lsa_query_info_pol(struct cli_state *cli, uint16 fnum,
			POLICY_HND *hnd, uint16 info_class,
			fstring domain_name, DOM_SID *domain_sid)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_QUERY_INFO q_q;
	BOOL valid_response = False;

	ZERO_STRUCTP(domain_sid);
	domain_name[0] = 0;

	if (hnd == NULL || domain_name == NULL || domain_sid == NULL) return False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api LSA_QUERYINFOPOLICY */

	DEBUG(4,("LSA Query Info Policy\n"));

	/* store the parameters */
	make_q_query(&q_q, hnd, info_class);

	/* turn parameters into data stream */
	lsa_io_q_query("", &q_q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, fnum, LSA_QUERYINFOPOLICY, &buf, &rbuf))
	{
		LSA_R_QUERY_INFO r_q;
		BOOL p;

		lsa_io_r_query("", &r_q, &rbuf, 0);
		p = rbuf.offset != 0;
		
		if (p && r_q.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_QUERYINFOPOLICY: %s\n", get_nt_error_msg(r_q.status)));
			p = False;
		}

		if (p && r_q.info_class != q_q.info_class)
		{
			/* report different info classes */
			DEBUG(0,("LSA_QUERYINFOPOLICY: error info_class (q,r) differ - (%x,%x)\n",
					q_q.info_class, r_q.info_class));
			p = False;
		}

		if (p)
		{
			fstring sid_str;
			/* ok, at last: we're happy. */
			switch (r_q.info_class)
			{
				case 3:
				{
					if (r_q.dom.id3.buffer_dom_name != 0)
					{
						char *dom_name = unistrn2(r_q.dom.id3.uni_domain_name.buffer,
									  r_q.dom.id3.uni_domain_name.uni_str_len);
						fstrcpy(domain_name, dom_name);
					}
					if (r_q.dom.id3.buffer_dom_sid != 0)
					{
						*domain_sid = r_q.dom.id3.dom_sid.sid;
					}

					valid_response = True;
					break;
				}
				case 5:
				{
					if (r_q.dom.id5.buffer_dom_name != 0)
					{
						char *dom_name = unistrn2(r_q.dom.id5.uni_domain_name.buffer,
									  r_q.dom.id5.uni_domain_name.uni_str_len);
						fstrcpy(domain_name, dom_name);
					}
					if (r_q.dom.id5.buffer_dom_sid != 0)
					{
						*domain_sid = r_q.dom.id5.dom_sid.sid;
					}

					valid_response = True;
					break;
				}
				default:
				{
					DEBUG(3,("LSA_QUERYINFOPOLICY: unknown info class\n"));
					domain_name[0] = 0;

					break;
				}
			}
		
			sid_to_string(sid_str, domain_sid);
			DEBUG(3,("LSA_QUERYINFOPOLICY (level %x): domain:%s  domain sid:%s\n",
			          r_q.info_class, domain_name, sid_str));
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_response;
}

/****************************************************************************
do a LSA Close
****************************************************************************/
BOOL lsa_close(struct cli_state *cli, uint16 fnum, POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_CLOSE q_c;
    BOOL valid_close = False;

	if (hnd == NULL) return False;

	/* create and send a MSRPC command with api LSA_OPENPOLICY */

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("LSA Close\n"));

	/* store the parameters */
	make_lsa_q_close(&q_c, hnd);

	/* turn parameters into data stream */
	lsa_io_q_close("", &q_c, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, fnum, LSA_CLOSE, &buf, &rbuf))
	{
		LSA_R_CLOSE r_c;
		BOOL p;

		lsa_io_r_close("", &r_c, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(0,("LSA_CLOSE: %s\n", get_nt_error_msg(r_c.status)));
			p = False;
		}

		if (p)
		{
			/* check that the returned policy handle is all zeros */
			int i;
			valid_close = True;

			for (i = 0; i < sizeof(r_c.pol.data); i++)
			{
				if (r_c.pol.data[i] != 0)
				{
					valid_close = False;
					break;
				}
			}	
			if (!valid_close)
			{
				DEBUG(0,("LSA_CLOSE: non-zero handle returned\n"));
			}
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_close;
}


