/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jeremy Allison                    1999.
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

/****************************************************************************
do a LSA Open Policy
****************************************************************************/

BOOL do_lsa_open_policy(struct cli_state *cli,
			char *system_name, POLICY_HND *hnd,
			BOOL sec_qos)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_OPEN_POL q_o;
	LSA_SEC_QOS qos;
	LSA_R_OPEN_POL r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf , MAX_PDU_FRAG_LEN, 4, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, 4, cli->mem_ctx, UNMARSHALL );

	/* create and send a MSRPC command with api LSA_OPENPOLICY */

	DEBUG(4,("LSA Open Policy\n"));

	/* store the parameters */
	if (sec_qos) {
		init_lsa_sec_qos(&qos, 2, 1, 0, 0x20000000);
		init_q_open_pol(&q_o, 0x5c, 0, 0, &qos);
	} else {
		init_q_open_pol(&q_o, 0x5c, 0, 0x1, NULL);
	}

	/* turn parameters into data stream */
	if(!lsa_io_q_open_pol("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, LSA_OPENPOLICY, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	if(!lsa_io_r_open_pol("", &r_o, &rbuf, 0)) {
		DEBUG(0,("do_lsa_open_policy: Failed to unmarshall LSA_R_OPEN_POL\n"));
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("LSA_OPENPOLICY: %s\n", get_nt_error_msg(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	} else {
		/* ok, at last: we're happy. return the policy handle */
		memcpy(hnd, &r_o.pol, sizeof(*hnd));
	}

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a LSA Query Info Policy
****************************************************************************/
BOOL do_lsa_query_info_pol(struct cli_state *cli,
			POLICY_HND *hnd, uint16 info_class,
			fstring domain_name, DOM_SID *domain_sid)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_QUERY_INFO q_q;
	LSA_R_QUERY_INFO r_q;
	fstring sid_str;

	ZERO_STRUCTP(domain_sid);
	domain_name[0] = 0;

	if (hnd == NULL || domain_name == NULL || domain_sid == NULL)
		return False;

	prs_init(&buf , MAX_PDU_FRAG_LEN, 4, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, 4, cli->mem_ctx, UNMARSHALL );

	/* create and send a MSRPC command with api LSA_QUERYINFOPOLICY */

	DEBUG(4,("LSA Query Info Policy\n"));

	/* store the parameters */
	init_q_query(&q_q, hnd, info_class);

	/* turn parameters into data stream */
	if(!lsa_io_q_query("", &q_q, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, LSA_QUERYINFOPOLICY, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	if(!lsa_io_r_query("", &r_q, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_q.status != 0) {
		/* report error code */
		DEBUG(0,("LSA_QUERYINFOPOLICY: %s\n", get_nt_error_msg(r_q.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_q.info_class != q_q.info_class) {
		/* report different info classes */
		DEBUG(0,("LSA_QUERYINFOPOLICY: error info_class (q,r) differ - (%x,%x)\n",
				q_q.info_class, r_q.info_class));
		prs_mem_free(&rbuf);
		return False;
	}

	/* ok, at last: we're happy. */
	switch (r_q.info_class) {
	case 3:
		if (r_q.dom.id3.buffer_dom_name != 0) {
			char *dom_name = dos_unistrn2(r_q.dom.id3.uni_domain_name.buffer,
						  r_q.dom.id3.uni_domain_name.uni_str_len);
			fstrcpy(domain_name, dom_name);
		}
		if (r_q.dom.id3.buffer_dom_sid != 0)
			*domain_sid = r_q.dom.id3.dom_sid.sid;
		break;
	case 5:
		if (r_q.dom.id5.buffer_dom_name != 0) {
			char *dom_name = dos_unistrn2(r_q.dom.id5.uni_domain_name.buffer,
						  r_q.dom.id5.uni_domain_name.uni_str_len);
			fstrcpy(domain_name, dom_name);
		}
		if (r_q.dom.id5.buffer_dom_sid != 0)
			*domain_sid = r_q.dom.id5.dom_sid.sid;
		break;
	default:
		DEBUG(3,("LSA_QUERYINFOPOLICY: unknown info class\n"));
		domain_name[0] = 0;

		prs_mem_free(&rbuf);
		return False;
	}
		
	sid_to_string(sid_str, domain_sid);
	DEBUG(3,("LSA_QUERYINFOPOLICY (level %x): domain:%s  domain sid:%s\n",
	          r_q.info_class, domain_name, sid_str));

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a LSA Close
****************************************************************************/

BOOL do_lsa_close(struct cli_state *cli, POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	LSA_Q_CLOSE q_c;
	LSA_R_CLOSE r_c;
	int i;

	if (hnd == NULL)
		return False;

	/* create and send a MSRPC command with api LSA_OPENPOLICY */

	prs_init(&buf , MAX_PDU_FRAG_LEN, 4, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, 4, cli->mem_ctx, UNMARSHALL );

	DEBUG(4,("LSA Close\n"));

	/* store the parameters */
	init_lsa_q_close(&q_c, hnd);

	/* turn parameters into data stream */
	if(!lsa_io_q_close("", &q_c, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, LSA_CLOSE, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	if(!lsa_io_r_close("", &r_c, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_c.status != 0) {
		/* report error code */
		DEBUG(0,("LSA_CLOSE: %s\n", get_nt_error_msg(r_c.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	/* check that the returned policy handle is all zeros */

#if 0
	for (i = 0; i < sizeof(r_c.pol.data); i++) {
		if (r_c.pol.data[i] != 0) {
			DEBUG(0,("LSA_CLOSE: non-zero handle returned\n"));
			prs_mem_free(&rbuf);
			return False;
		}
	}
#endif

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
obtain a server's SAM SID and save it in the secrets database
****************************************************************************/

BOOL cli_lsa_get_domain_sid(struct cli_state *cli, char *server)
{
	fstring domain;
	POLICY_HND pol;
	DOM_SID sid;
	BOOL res, res2, res3;

	res = cli_nt_session_open(cli, PIPE_LSARPC);
	res2 = res ? do_lsa_open_policy(cli, server, &pol, 0) : False;
	res3 = res2 ? do_lsa_query_info_pol(cli, &pol, 5, domain, &sid) : False;

	res3 = res3 ? secrets_store_domain_sid(domain, &sid) : False;

	res2 = res2 ? do_lsa_close(cli, &pol) : False;
	cli_nt_session_close(cli);
	
	return res3;
}

/****************************************************************************
do a LSA Open Policy
****************************************************************************/
uint32 lsa_open_policy(const char *system_name, POLICY_HND *hnd,
		       BOOL sec_qos, uint32 des_access)
{
	prs_struct rbuf;
	prs_struct buf;
	LSA_Q_OPEN_POL q_o;
	LSA_SEC_QOS qos;
	struct cli_connection *con = NULL;
	uint32 result;

	if (!cli_connection_init(system_name, PIPE_LSARPC, &con)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (hnd == NULL) return NT_STATUS_UNSUCCESSFUL;

	prs_init(&buf, MAX_PDU_FRAG_LEN, 4, NULL, False);
	prs_init(&rbuf, 0, 4, NULL, True);

	/* create and send a MSRPC command with api LSA_OPENPOLICY */

	DEBUG(4, ("LSA Open Policy\n"));

	/* store the parameters */
	if (sec_qos) {
		init_lsa_sec_qos(&qos, 2, 1, 0, des_access);
		init_q_open_pol(&q_o, '\\', 0, des_access, &qos);
	} else {
		init_q_open_pol(&q_o, '\\', 0, des_access, NULL);
	}

	/* turn parameters into data stream */
	if (lsa_io_q_open_pol("", &q_o, &buf, 0) &&
	    rpc_con_pipe_req(con, LSA_OPENPOLICY, &buf, &rbuf)) {
		LSA_R_OPEN_POL r_o;
		BOOL p;

		lsa_io_r_open_pol("", &r_o, &rbuf, 0);
		p = rbuf.data_offset != 0;

		result = r_o.status;

		if (p && r_o.status != 0) {
			/* report error code */
			DEBUG(0,
			      ("LSA_OPENPOLICY: %s\n",
			       get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p) {

			/* Return the policy handle */

			*hnd = r_o.pol;

                        if (!RpcHndList_set_connection(hnd, con)) {
				result = NT_STATUS_NO_MEMORY;
			}
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf);

	return result;
}

/****************************************************************************
do a LSA Close
****************************************************************************/
uint32 lsa_close(POLICY_HND *hnd)
{
        prs_struct rbuf;
        prs_struct buf;
        LSA_Q_CLOSE q_c;
	uint32 result;

        if (hnd == NULL) return False;

        /* Create and send a MSRPC command with api LSA_OPENPOLICY */

        prs_init(&buf, MAX_PDU_FRAG_LEN, 4, NULL, False);
        prs_init(&rbuf, 0, 4, NULL, True);

        DEBUG(4, ("LSA Close\n"));

        /* Store the parameters */

        init_lsa_q_close(&q_c, hnd);

        /* Turn parameters into data stream */

        if (lsa_io_q_close("", &q_c, &buf, 0) &&
            rpc_hnd_pipe_req(hnd, LSA_CLOSE, &buf, &rbuf)) {
                LSA_R_CLOSE r_c;
                BOOL p;

                lsa_io_r_close("", &r_c, &rbuf, 0);
                p = rbuf.data_offset != 0;
		result = r_c.status;

                if (p && r_c.status != 0) {

                        /* Report error code */

                        DEBUG(0, ("LSA_CLOSE: %s\n",
                                  get_nt_error_msg(r_c.status)));

                        p = False;
                }

        }

        prs_mem_free(&rbuf);
        prs_mem_free(&buf);

        return result;
}

/****************************************************************************
do a LSA Lookup SIDs
****************************************************************************/
uint32 lsa_lookup_sids(POLICY_HND *hnd, int num_sids, DOM_SID *sids,
		       char ***names, uint32 **types, int *num_names)
{
	prs_struct rbuf;
	prs_struct buf;
	LSA_Q_LOOKUP_SIDS q_l;
	TALLOC_CTX *ctx = talloc_init();
	uint32 result;

	ZERO_STRUCT(q_l);

	if (hnd == NULL || num_sids == 0 || sids == NULL) return False;

	if (num_names != NULL) {
		*num_names = 0;
	}

	if (types != NULL) {
		*types = NULL;
	}

	if (names != NULL) {
		*names = NULL;
	}

	prs_init(&buf, MAX_PDU_FRAG_LEN, 4, ctx, False);
	prs_init(&rbuf, 0, 4, ctx, True);

	/* Create and send a MSRPC command with api LSA_LOOKUP_SIDS */

	DEBUG(4, ("LSA Lookup SIDs\n"));

	/* Store the parameters */

	init_q_lookup_sids(ctx, &q_l, hnd, num_sids, sids, 1);

	/* turn parameters into data stream */
	if (lsa_io_q_lookup_sids("", &q_l, &buf, 0) &&
	    rpc_hnd_pipe_req(hnd, LSA_LOOKUPSIDS, &buf, &rbuf)) {
		LSA_R_LOOKUP_SIDS r_l;
		DOM_R_REF ref;
		LSA_TRANS_NAME_ENUM t_names;
		BOOL p, valid_response;

		r_l.dom_ref = &ref;
		r_l.names = &t_names;

		lsa_io_r_lookup_sids("", &r_l, &rbuf, 0);
		p = rbuf.data_offset != 0;
		result = r_l.status;

		if (p && r_l.status != 0 &&
		    r_l.status != 0x107 &&
		    r_l.status != (0xC0000000 | NT_STATUS_NONE_MAPPED)) {

			/* Report error code */

			DEBUG(1, ("LSA_LOOKUP_SIDS: %s\n",
				  get_nt_error_msg(r_l.status)));

			return r_l.status;
		}

		result = NT_STATUS_NOPROBLEMO;

		if (p) {
			if (t_names.ptr_trans_names != 0
			    && r_l.ptr_dom_ref != 0) {
				valid_response = True;
			}
		}

		if (num_names != NULL && valid_response) {
			(*num_names) = t_names.num_entries;
		}

		if (valid_response) {
			uint32 i;

			for (i = 0; i < t_names.num_entries; i++) {
				if ((t_names.name[i].domain_idx >=
				     ref.num_ref_doms_1)
				    && (t_names.name[i].domain_idx !=
					0xffffffff)) {
					DEBUG(0,
					      ("LSA_LOOKUP_SIDS: domain index out of bounds\n"));
					valid_response = False;
					break;
				}
			}
		}

		if (types != NULL && valid_response && (*num_names) != 0) {
			(*types) = (uint32 *) malloc((*num_names) * 
						     sizeof(uint32));
		}

		if (names != NULL && valid_response && (*num_names) != 0) {
			(*names) = (char **)malloc((*num_names) * 
						   sizeof(char *));
		}

		if (names != NULL && (*names) != NULL) {
			int i;

			/* Take each name, construct a \DOMAIN\name string */

			for (i = 0; i < (*num_names); i++) {
				fstring name;
				fstring dom_name;
				fstring full_name;
				uint32 dom_idx = t_names.name[i].domain_idx;

				if (dom_idx != 0xffffffff) {
					unistr2_to_ascii(dom_name,
							 &ref.
							 ref_dom[dom_idx].
							 uni_dom_name,
							 sizeof(dom_name) -
							 1);
					unistr2_to_ascii(name,
							 &t_names.uni_name[i],
							 sizeof(name) - 1);

					memset(full_name, 0,
					       sizeof(full_name));

					slprintf(full_name,
						 sizeof(full_name) - 1,
						 "%s\\%s", dom_name, name);

					(*names)[i] = strdup(full_name);
					if (types != NULL && 
					    (*types) != NULL) {
						(*types)[i] = t_names.name[i].sid_name_use;
					}
				} else {
					(*names)[i] = NULL;
					if (types != NULL && 
					    (*types) != NULL) {
						(*types)[i] = SID_NAME_UNKNOWN;
					}
				}
			}
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf);

	return result;
}

/****************************************************************************
do a LSA Lookup Names
****************************************************************************/
uint32 lsa_lookup_names(POLICY_HND *hnd, int num_names, char **names,
			DOM_SID **sids, uint32 **types, int *num_sids)
{
	prs_struct rbuf;
	prs_struct buf;
	LSA_Q_LOOKUP_NAMES q_l;
	BOOL valid_response = False;
	TALLOC_CTX *ctx = talloc_init();
	uint32 result;

	if (hnd == NULL || num_sids == 0 || sids == NULL) return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, 4, ctx, False);
	prs_init(&rbuf, 0, 4, ctx, True);

	/* create and send a MSRPC command with api LSA_LOOKUP_NAMES */

	DEBUG(4, ("LSA Lookup NAMEs\n"));

	/* store the parameters */
	init_q_lookup_names(ctx, &q_l, hnd, num_names, names);

	/* turn parameters into data stream */
	if (lsa_io_q_lookup_names("", &q_l, &buf, 0) &&
	    rpc_hnd_pipe_req(hnd, LSA_LOOKUPNAMES, &buf, &rbuf)) {
		LSA_R_LOOKUP_NAMES r_l;
		DOM_R_REF ref;
		DOM_RID2 t_rids[MAX_LOOKUP_SIDS];
		BOOL p;

		ZERO_STRUCT(ref);
		ZERO_STRUCT(t_rids);

		r_l.dom_ref = &ref;
		r_l.dom_rid = t_rids;

		lsa_io_r_lookup_names("", &r_l, &rbuf, 0);
		p = rbuf.data_offset != 0;

		if (p && r_l.status != 0) {
			/* report error code */
			DEBUG(1,
			      ("LSA_LOOKUP_NAMES: %s\n",
			       get_nt_error_msg(r_l.status)));
			p = False;

			return r_l.status;
		}

		result = r_l.status;

		if (p) {
			if (r_l.ptr_dom_ref != 0 && r_l.ptr_entries != 0) {
				valid_response = True;
			}
		}

		if (num_sids != NULL && valid_response) {
			(*num_sids) = r_l.num_entries;
		}

		if (valid_response) {
			uint32 i;

			for (i = 0; i < r_l.num_entries; i++) {
				if (t_rids[i].rid_idx >= ref.num_ref_doms_1 &&
				    t_rids[i].rid_idx != 0xffffffff) {
					DEBUG(0,
					      ("LSA_LOOKUP_NAMES: domain index %d out of bounds\n",
					       t_rids[i].rid_idx));
					valid_response = False;
					break;
				}
			}
		}

		if (types != NULL && valid_response && r_l.num_entries != 0) {
			(*types) = (uint32 *) malloc((*num_sids) * 
						     sizeof(uint32));
		}

		if (sids != NULL && valid_response && r_l.num_entries != 0) {
			(*sids) = (DOM_SID *) malloc((*num_sids) * 
						     sizeof(DOM_SID));
		}

		if (sids != NULL && (*sids) != NULL) {
			int i;

			/* Take each name, construct a SID */

			for (i = 0; i < (*num_sids); i++) {
				uint32 dom_idx = t_rids[i].rid_idx;
				uint32 dom_rid = t_rids[i].rid;
				DOM_SID *sid = &(*sids)[i];

				if (dom_idx != 0xffffffff) {

					sid_copy(sid,
						 &ref.ref_dom[dom_idx].
						 ref_dom.sid);

					if (dom_rid != 0xffffffff) {
						sid_append_rid(sid, dom_rid);
					}

					if (types != NULL && 
					    (*types) != NULL) {
						(*types)[i] = t_rids[i].type;
					}

				} else {
					ZERO_STRUCTP(sid);

					if (types != NULL && 
					    (*types) != NULL) {
						(*types)[i] = SID_NAME_UNKNOWN;
					}
				}
			}
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf);

	return result;
}
