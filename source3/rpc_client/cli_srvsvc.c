/* 
   Unix SMB/CIFS implementation.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Tim Potter 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002
   
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

WERROR cli_srvsvc_net_srv_get_info(struct cli_state *cli, 
				   TALLOC_CTX *mem_ctx,
				   uint32 switch_value, SRV_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SRV_Q_NET_SRV_GET_INFO q;
	SRV_R_NET_SRV_GET_INFO r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_srv_q_net_srv_get_info(&q, cli->srv_name_slash, switch_value);

	/* Marshall data and send request */

	if (!srv_io_q_net_srv_get_info("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SRV_NET_SRV_GET_INFO, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	r.ctr = ctr;

	if (!srv_io_r_net_srv_get_info("", &r, &rbuf, 0))
		goto done;

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

WERROR cli_srvsvc_net_share_enum(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				 uint32 info_level, SRV_SHARE_INFO_CTR *ctr,
				 int preferred_len, ENUM_HND *hnd)
{
	prs_struct qbuf, rbuf;
	SRV_Q_NET_SHARE_ENUM q;
	SRV_R_NET_SHARE_ENUM r;
	WERROR result = W_ERROR(ERRgeneral);
	int i;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_srv_q_net_share_enum(
		&q, cli->srv_name_slash, info_level, preferred_len, hnd);

	/* Marshall data and send request */

	if (!srv_io_q_net_share_enum("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SRV_NET_SHARE_ENUM_ALL, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!srv_io_r_net_share_enum("", &r, &rbuf, 0))
		goto done;

	result = r.status;

	if (!W_ERROR_IS_OK(result))
		goto done;

	/* Oh yuck yuck yuck - we have to copy all the info out of the
	   SRV_SHARE_INFO_CTR in the SRV_R_NET_SHARE_ENUM as when we do a
	   prs_mem_free() it will all be invalidated.  The various share
	   info structures suck badly too.  This really is gross. */

	ZERO_STRUCTP(ctr);

	if (!r.ctr.num_entries)
		goto done;

	ctr->info_level = info_level;
	ctr->num_entries = r.ctr.num_entries;

	switch(info_level) {
	case 1:
		ctr->share.info1 = (SRV_SHARE_INFO_1 *)talloc(
			mem_ctx, sizeof(SRV_SHARE_INFO_1) * ctr->num_entries);
		
		memset(ctr->share.info1, 0, sizeof(SRV_SHARE_INFO_1));

		for (i = 0; i < ctr->num_entries; i++) {
			SRV_SHARE_INFO_1 *info1 = &ctr->share.info1[i];
			char *s;
			
			/* Copy pointer crap */

			memcpy(&info1->info_1, &r.ctr.share.info1[i].info_1, 
			       sizeof(SH_INFO_1));

			/* Duplicate strings */

			s = unistr2_tdup(mem_ctx, &r.ctr.share.info1[i].info_1_str.uni_netname);
			if (s)
				init_unistr2(&info1->info_1_str.uni_netname, s, UNI_STR_TERMINATE);
		
			s = unistr2_tdup(mem_ctx, &r.ctr.share.info1[i].info_1_str.uni_remark);
			if (s)
				init_unistr2(&info1->info_1_str.uni_remark, s, UNI_STR_TERMINATE);

		}		

		break;
	case 2:
		ctr->share.info2 = (SRV_SHARE_INFO_2 *)talloc(
			mem_ctx, sizeof(SRV_SHARE_INFO_2) * ctr->num_entries);
		
		memset(ctr->share.info2, 0, sizeof(SRV_SHARE_INFO_2));

		for (i = 0; i < ctr->num_entries; i++) {
			SRV_SHARE_INFO_2 *info2 = &ctr->share.info2[i];
			char *s;
			
			/* Copy pointer crap */

			memcpy(&info2->info_2, &r.ctr.share.info2[i].info_2, 
			       sizeof(SH_INFO_2));

			/* Duplicate strings */

			s = unistr2_tdup(mem_ctx, &r.ctr.share.info2[i].info_2_str.uni_netname);
			if (s)
				init_unistr2(&info2->info_2_str.uni_netname, s, UNI_STR_TERMINATE);

			s = unistr2_tdup(mem_ctx, &r.ctr.share.info2[i].info_2_str.uni_remark);
			if (s)
				init_unistr2(&info2->info_2_str.uni_remark, s, UNI_STR_TERMINATE);

			s = unistr2_tdup(mem_ctx, &r.ctr.share.info2[i].info_2_str.uni_path);
			if (s)
				init_unistr2(&info2->info_2_str.uni_path, s, UNI_STR_TERMINATE);

			s = unistr2_tdup(mem_ctx, &r.ctr.share.info2[i].info_2_str.uni_passwd);
			if (s)
				init_unistr2(&info2->info_2_str.uni_passwd, s, UNI_STR_TERMINATE);
		}
		break;
	}
 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

WERROR cli_srvsvc_net_share_del(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				const char *sharename)
{
	prs_struct qbuf, rbuf;
	SRV_Q_NET_SHARE_DEL q;
	SRV_R_NET_SHARE_DEL r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_srv_q_net_share_del(&q, cli->srv_name_slash, sharename);

	/* Marshall data and send request */

	if (!srv_io_q_net_share_del("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SRV_NET_SHARE_DEL, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!srv_io_r_net_share_del("", &r, &rbuf, 0))
		goto done;

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

WERROR cli_srvsvc_net_share_add(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				const char *netname, uint32 type, 
				const char *remark, uint32 perms, 
				uint32 max_uses, uint32 num_uses, 
				const char *path, const char *passwd)
{
	prs_struct qbuf, rbuf;
	SRV_Q_NET_SHARE_ADD q;
	SRV_R_NET_SHARE_ADD r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	init_srv_q_net_share_add(&q,cli->srv_name_slash, netname, type, remark,
				 perms, max_uses, num_uses, path, passwd);

	/* Marshall data and send request */

	if (!srv_io_q_net_share_add("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SRV_NET_SHARE_ADD, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!srv_io_r_net_share_add("", &r, &rbuf, 0))
		goto done;

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;	
}

WERROR cli_srvsvc_net_remote_tod(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				 char *server, TIME_OF_DAY_INFO *tod)
{
	prs_struct qbuf, rbuf;
	SRV_Q_NET_REMOTE_TOD q;
	SRV_R_NET_REMOTE_TOD r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_srv_q_net_remote_tod(&q, cli->srv_name_slash);

	/* Marshall data and send request */

	if (!srv_io_q_net_remote_tod("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SRV_NET_REMOTE_TOD, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	r.tod = tod;

	if (!srv_io_r_net_remote_tod("", &r, &rbuf, 0))
		goto done;

	result = r.status;

	if (!W_ERROR_IS_OK(result))
		goto done;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;	
}

WERROR cli_srvsvc_net_file_enum(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				uint32 file_level, const char *user_name,
				SRV_FILE_INFO_CTR *ctr,	int preferred_len,
				ENUM_HND *hnd)
{
	prs_struct qbuf, rbuf;
	SRV_Q_NET_FILE_ENUM q;
	SRV_R_NET_FILE_ENUM r;
	WERROR result = W_ERROR(ERRgeneral);
	int i;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_srv_q_net_file_enum(&q, cli->srv_name_slash, NULL, user_name, 
				 file_level, ctr, preferred_len, hnd);

	/* Marshall data and send request */

	if (!srv_io_q_net_file_enum("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SRV_NET_FILE_ENUM, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!srv_io_r_net_file_enum("", &r, &rbuf, 0))
		goto done;

	result = r.status;

	if (!W_ERROR_IS_OK(result))
		goto done;

	/* copy the data over to the ctr */

	ZERO_STRUCTP(ctr);

	ctr->switch_value = file_level;

	ctr->num_entries = ctr->num_entries2 = r.ctr.num_entries;
	
	switch(file_level) {
	case 3:
		ctr->file.info3 = (SRV_FILE_INFO_3 *)talloc(
			mem_ctx, sizeof(SRV_FILE_INFO_3) * ctr->num_entries);

		memset(ctr->file.info3, 0, 
		       sizeof(SRV_FILE_INFO_3) * ctr->num_entries);

		for (i = 0; i < r.ctr.num_entries; i++) {
			SRV_FILE_INFO_3 *info3 = &ctr->file.info3[i];
			char *s;
			
			/* Copy pointer crap */

			memcpy(&info3->info_3, &r.ctr.file.info3[i].info_3, 
			       sizeof(FILE_INFO_3));

			/* Duplicate strings */

			s = unistr2_tdup(mem_ctx, &r.ctr.file.info3[i].info_3_str.uni_path_name);
			if (s)
				init_unistr2(&info3->info_3_str.uni_path_name, s, UNI_STR_TERMINATE);
		
			s = unistr2_tdup(mem_ctx, &r.ctr.file.info3[i].info_3_str.uni_user_name);
			if (s)
				init_unistr2(&info3->info_3_str.uni_user_name, s, UNI_STR_TERMINATE);

		}		

		break;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

WERROR cli_srvsvc_net_file_close(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				 uint32 file_id)
{
	prs_struct qbuf, rbuf;
	SRV_Q_NET_FILE_CLOSE q;
	SRV_R_NET_FILE_CLOSE r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_srv_q_net_file_close(&q, cli->srv_name_slash, file_id);

	/* Marshall data and send request */

	if (!srv_io_q_net_file_close("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SRV_NET_FILE_CLOSE, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!srv_io_r_net_file_close("", &r, &rbuf, 0))
		goto done;

	result = r.status;
 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);
	return result;
}
