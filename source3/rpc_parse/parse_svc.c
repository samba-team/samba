
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


#include "includes.h"

extern int DEBUGLEVEL;

/*******************************************************************
 make_svc_q_open_sc_man
 ********************************************************************/
void make_svc_q_open_sc_man(SVC_Q_OPEN_SC_MAN *q_u,
				char *server, char *database,
				uint32 des_access)  
{
	DEBUG(5,("make_svc_q_open_sc_man\n"));

	make_buf_unistr2(&(q_u->uni_srv_name), &(q_u->ptr_srv_name), server);
	make_buf_unistr2(&(q_u->uni_db_name ), &(q_u->ptr_db_name), database);
	q_u->des_access = des_access;

}

/*******************************************************************
reads or writes a SVC_Q_OPEN_SC_MAN structure.
********************************************************************/
void svc_io_q_open_sc_man(char *desc, SVC_Q_OPEN_SC_MAN *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_q_open_sc_man");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_u->ptr_srv_name));
	smb_io_unistr2("", &(q_u->uni_srv_name), q_u->ptr_srv_name, ps, depth); 
	prs_align(ps);

	prs_uint32("ptr_db_name", ps, depth, &(q_u->ptr_db_name));
	smb_io_unistr2("", &(q_u->uni_db_name), q_u->ptr_db_name, ps, depth); 
	prs_align(ps);

	prs_uint32("des_access", ps, depth, &(q_u->des_access));
	prs_align(ps);
}

/*******************************************************************
 make_svc_r_open_sc_man
 ********************************************************************/
void make_svc_r_open_sc_man(SVC_R_OPEN_SC_MAN *r_u, POLICY_HND *hnd,
				uint32 status)  
{
	DEBUG(5,("make_svc_r_unknown_0: %d\n", __LINE__));

	memcpy(&(r_u->pol), hnd, sizeof(r_u->pol));
	r_u->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_r_open_sc_man(char *desc,  SVC_R_OPEN_SC_MAN *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_r_open_sc_man");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(r_u->pol), ps, depth);

	prs_uint32("status      ", ps, depth, &(r_u->status));
}

/*******************************************************************
 make_svc_q_open_service
 ********************************************************************/
void make_svc_q_open_service(SVC_Q_OPEN_SERVICE *q_u,
				POLICY_HND *hnd,
				char *server,
				uint32 des_access)  
{
	DEBUG(5,("make_svc_q_open_service\n"));

	memcpy(&(q_u->scman_pol), hnd, sizeof(q_u->scman_pol));
	make_unistr2(&(q_u->uni_svc_name), server, strlen(server)+1);
	q_u->des_access = des_access;

}

/*******************************************************************
reads or writes a SVC_Q_OPEN_SERVICE structure.
********************************************************************/
void svc_io_q_open_service(char *desc, SVC_Q_OPEN_SERVICE *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_q_open_service");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(q_u->scman_pol), ps, depth);
	prs_align(ps);

	smb_io_unistr2("", &(q_u->uni_svc_name), 1, ps, depth); 
	prs_align(ps);

	prs_uint32("des_access", ps, depth, &(q_u->des_access));
	prs_align(ps);
}

/*******************************************************************
 make_svc_r_open_service
 ********************************************************************/
void make_svc_r_open_service(SVC_R_OPEN_SERVICE *r_u, POLICY_HND *hnd,
				uint32 status)  
{
	DEBUG(5,("make_svc_r_unknown_0: %d\n", __LINE__));

	memcpy(&(r_u->pol), hnd, sizeof(r_u->pol));
	r_u->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_r_open_service(char *desc,  SVC_R_OPEN_SERVICE *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_r_open_service");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(r_u->pol), ps, depth);

	prs_uint32("status      ", ps, depth, &(r_u->status));
}

/*******************************************************************
reads or writes a SVC_Q_START_SERVICE structure.
********************************************************************/
void svc_io_q_start_service(char *desc, SVC_Q_START_SERVICE *q_s, prs_struct *ps, int depth)
{
	if (q_s == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_q_start_service");
	depth++;

	prs_align(ps);
	smb_io_pol_hnd("", &(q_s->pol), ps, depth);

	prs_align(ps);
	prs_uint32("argc    ", ps, depth, &(q_s->argc    ));
	prs_uint32("ptr_argv", ps, depth, &(q_s->ptr_argv));

	if (q_s->ptr_argv != 0)
	{
		int i;

		prs_uint32("argc2   ", ps, depth, &(q_s->argc2));

		if (q_s->argc2 > MAX_SVC_ARGS)
		{
			q_s->argc = q_s->argc2 = MAX_SVC_ARGS;
		}

		for (i = 0; i < q_s->argc2; i++)
		{
			smb_io_unistr2("", &(q_s->argv[i]), 1, ps, depth); 
		}
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_r_start_service(char *desc,  SVC_R_START_SERVICE *r_s, prs_struct *ps, int depth)
{
	if (r_s == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_r_start_service");
	depth++;

	prs_uint32("status", ps, depth, &(r_s->status));
}

/*******************************************************************
 make_svc_query_svc_cfg
 ********************************************************************/
void make_svc_query_svc_cfg(QUERY_SERVICE_CONFIG *q_u,
				uint32 service_type, uint32 start_type,
				uint32 error_control,
				char* bin_path_name, char* load_order_grp, 
				uint32 tag_id,
				char* dependencies, char* service_start_name,
				char* disp_name)
{
	DEBUG(5,("make_svc_query_svc_cfg\n"));

	q_u->service_type = service_type;
	q_u->start_type = start_type;
	q_u->error_control = error_control;
	make_buf_unistr2(&(q_u->uni_bin_path_name     ), &(q_u->ptr_bin_path_name     ), bin_path_name     );
	make_buf_unistr2(&(q_u->uni_load_order_grp    ), &(q_u->ptr_load_order_grp    ), load_order_grp    );
	q_u->tag_id = tag_id;
	make_buf_unistr2(&(q_u->uni_dependencies      ), &(q_u->ptr_dependencies      ), dependencies      );
	make_buf_unistr2(&(q_u->uni_service_start_name), &(q_u->ptr_service_start_name), service_start_name);
	make_buf_unistr2(&(q_u->uni_display_name      ), &(q_u->ptr_display_name      ), disp_name         );
}

/*******************************************************************
reads or writes a QUERY_SERVICE_CONFIG structure.
********************************************************************/
void svc_io_query_svc_cfg(char *desc, QUERY_SERVICE_CONFIG *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_query_svc_cfg");
	depth++;

	prs_align(ps);

	prs_uint32("service_type          ", ps, depth, &(q_u->service_type          ));
	prs_uint32("start_type            ", ps, depth, &(q_u->start_type            ));
	prs_uint32("error_control         ", ps, depth, &(q_u->error_control         ));
	prs_uint32("ptr_bin_path_name     ", ps, depth, &(q_u->ptr_bin_path_name     ));
	prs_uint32("ptr_load_order_grp    ", ps, depth, &(q_u->ptr_load_order_grp    ));
	prs_uint32("tag_id                ", ps, depth, &(q_u->tag_id                ));
	prs_uint32("ptr_dependencies      ", ps, depth, &(q_u->ptr_dependencies      ));
	prs_uint32("ptr_service_start_name", ps, depth, &(q_u->ptr_service_start_name));
	prs_uint32("ptr_display_name      ", ps, depth, &(q_u->ptr_display_name      ));

	smb_io_unistr2("uni_bin_path_name     ", &(q_u->uni_bin_path_name     ), q_u->ptr_bin_path_name     , ps, depth); 
	prs_align(ps);
	smb_io_unistr2("uni_load_order_grp    ", &(q_u->uni_load_order_grp    ), q_u->ptr_load_order_grp    , ps, depth); 
	prs_align(ps);
	smb_io_unistr2("uni_dependencies      ", &(q_u->uni_dependencies      ), q_u->ptr_dependencies      , ps, depth); 
	prs_align(ps);
	smb_io_unistr2("uni_service_start_name", &(q_u->uni_service_start_name), q_u->ptr_service_start_name, ps, depth); 
	prs_align(ps);
	smb_io_unistr2("uni_display_name      ", &(q_u->uni_display_name      ), q_u->ptr_display_name      , ps, depth); 
	prs_align(ps);
}

/*******************************************************************
makes an SVC_Q_ENUM_SVCS_STATUS structure.
********************************************************************/
void make_svc_q_enum_svcs_status(SVC_Q_ENUM_SVCS_STATUS *q_c, POLICY_HND *hnd,
				uint32 service_type, uint32 service_state,
				uint32 buf_size, uint32 resume_hnd )
{
	if (q_c == NULL || hnd == NULL) return;

	DEBUG(5,("make_svc_q_enum_svcs_status\n"));

	memcpy(&(q_c->pol), hnd, sizeof(q_c->pol));
	q_c->service_type = service_type;
	q_c->service_state = service_state;
	q_c->buf_size = buf_size;
	make_enum_hnd(&q_c->resume_hnd, resume_hnd);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_q_enum_svcs_status(char *desc,  SVC_Q_ENUM_SVCS_STATUS *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_q_enum_svcs_status");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(q_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("service_type ", ps, depth, &(q_u->service_type ));
	prs_uint32("service_state", ps, depth, &(q_u->service_state));
	prs_uint32("buf_size     ", ps, depth, &(q_u->buf_size     ));
	smb_io_enum_hnd("resume_hnd", &(q_u->resume_hnd), ps, depth); 
}

/*******************************************************************
makes an SVC_R_ENUM_SVCS_STATUS structure.
********************************************************************/
void make_svc_r_enum_svcs_status(SVC_R_ENUM_SVCS_STATUS *r_c, 
				ENUM_SRVC_STATUS *svcs, uint32 more_buf_size,
				uint32 num_svcs, uint32 resume_hnd,
				uint32 dos_status)
{
	if (r_c == NULL) return;

	DEBUG(5,("make_svc_r_enum_svcs_status\n"));

	r_c->svcs          = svcs;
	r_c->more_buf_size = more_buf_size;
	r_c->num_svcs      = num_svcs;
	make_enum_hnd(&r_c->resume_hnd, resume_hnd);
	r_c->dos_status = dos_status;
}

/*******************************************************************
reads or writes a SVC_R_ENUM_SVCS_STATUS structure.

this is another wierd structure.  WHY oh WHY can the microsoft teams
not COMMUNICATE and get some CONSISTENCY TO THEIR DATA STRUCTURES!
ARGH!

********************************************************************/
void svc_io_r_enum_svcs_status(char *desc, SVC_R_ENUM_SVCS_STATUS *svc, prs_struct *ps, int depth)
{
	int i;
	if (svc == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_r_enum_svcs_status");
	depth++;

	prs_align(ps);
	
	/*
	 * format is actually as laid out in SVC_R_ENUM_SVCS_STATUS.
	 * the reason for all the jumping about, which is horrible
	 * and can be avoided, is due to the use of offsets instead
	 * of pointers.
	 *
	 * if i ever find out that these offsets are in fact non-zero
	 * tokens just like pointer-tokens, i am going to go MAD.
	 */

	if (ps->io)
	{
		/* reading */

		uint32 buf_offset;
		uint32 new_offset;

		prs_uint32("buf_size", ps, depth, &(svc->buf_size));

		buf_offset = ps->offset;
		ps->offset = buf_offset + svc->buf_size;

		prs_uint32("more_buf_size", ps, depth, &(svc->more_buf_size));
		prs_uint32("num_svcs", ps, depth, &(svc->num_svcs));
		smb_io_enum_hnd("resume_hnd", &(svc->resume_hnd), ps, depth); 
		prs_uint32("dos_status", ps, depth, &(svc->dos_status));

		new_offset = ps->offset;
		ps->offset = buf_offset;

		svc->svcs = Realloc(NULL, svc->num_svcs * sizeof(ENUM_SRVC_STATUS));

		if (svc->svcs == NULL)
		{
			DEBUG(0,("svc_io_r_enum_svcs_status: Realloc failed\n"));
			ps->offset = 0x7fffffff;
			return;
		}

		bzero(svc->svcs, svc->num_svcs * sizeof(ENUM_SRVC_STATUS));

		for (i = 0; i < svc->num_svcs; i++)
		{
			fstring name;
			uint32 old_offset;
			uint32 srvc_offset;
			uint32 disp_offset;

			prs_uint32("srvc_offset", ps, depth, &srvc_offset);
			prs_uint32("disp_offset", ps, depth, &disp_offset);
			svc_io_svc_status("status", &svc->svcs[i].status, ps, depth); 

			old_offset = ps->offset;

			ps->offset = buf_offset + srvc_offset;
			slprintf(name, sizeof(name)-1, "srvc[%02d]", i);
			smb_io_unistr(name, &svc->svcs[i].uni_srvc_name, ps, depth);

			ps->offset = buf_offset + disp_offset;
			slprintf(name, sizeof(name)-1, "disp[%02d]", i);
			smb_io_unistr(name, &svc->svcs[i].uni_disp_name, ps, depth);

			ps->offset = old_offset;
		}

		ps->offset = new_offset;
	}
	else
	{
		/* writing */

		uint32 buf_offset;
		uint32 old_buf_offset;
		uint32 srvc_offset = 9 * sizeof(uint32) * svc->num_svcs;

		prs_uint32_pre("buf_size", ps, depth, &svc->buf_size, &buf_offset);
		old_buf_offset = ps->offset;

		srvc_offset += old_buf_offset;

		if (svc->svcs == NULL)
		{
			return;
		}

		for (i = 0; i < svc->num_svcs; i++)
		{
			fstring name;
			uint32 old_offset;

			/*
			 * store unicode string offset and unicode string
			 */

			srvc_offset -= old_buf_offset;
			prs_uint32("srvc_offset", ps, depth, &srvc_offset);
			srvc_offset += old_buf_offset;

			slprintf(name, sizeof(name)-1, "srvc[%02d]", i);

			old_offset = ps->offset;
			ps->offset = srvc_offset;
			smb_io_unistr(name, &svc->svcs[i].uni_srvc_name, ps, depth);
			srvc_offset = ps->offset;
			ps->offset = old_offset;

			/*
			 * store unicode string offset and unicode string
			 */

			srvc_offset -= old_buf_offset;
			prs_uint32("disp_offset", ps, depth, &srvc_offset);
			srvc_offset += old_buf_offset;

			slprintf(name, sizeof(name)-1, "disp[%02d]", i);

			old_offset = ps->offset;
			ps->offset = srvc_offset;
			smb_io_unistr(name, &svc->svcs[i].uni_disp_name, ps, depth);
			srvc_offset = ps->offset;
			ps->offset = old_offset;

			/*
			 * store status info
			 */

			svc_io_svc_status("status", &svc->svcs[i].status, ps, depth); 
		}

		prs_uint32_post("buf_size", ps, depth, &svc->buf_size, buf_offset, srvc_offset - buf_offset - sizeof(uint32));

		ps->offset = srvc_offset;

		prs_uint32("more_buf_size", ps, depth, &(svc->more_buf_size));
		prs_uint32("num_svcs", ps, depth, &(svc->num_svcs));
		smb_io_enum_hnd("resume_hnd", &(svc->resume_hnd), ps, depth); 
		prs_uint32("dos_status", ps, depth, &(svc->dos_status));
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_svc_status(char *desc,  SVC_STATUS *svc, prs_struct *ps, int depth)
{
	if (svc == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_svc_status");
	depth++;

	prs_align(ps);

	prs_uint32("svc_type", ps, depth, &(svc->svc_type));
	prs_uint32("current_state", ps, depth, &(svc->current_state));
	prs_uint32("controls_accepted", ps, depth, &(svc->controls_accepted));
	prs_uint32("win32_exit_code", ps, depth, &(svc->win32_exit_code));
	prs_uint32("svc_specific_exit_code", ps, depth, &(svc->svc_specific_exit_code));
	prs_uint32("check_point", ps, depth, &(svc->check_point));
	prs_uint32("wait_hint", ps, depth, &(svc->wait_hint));
}

/*******************************************************************
makes an SVC_Q_QUERY_SVC_CONFIG structure.
********************************************************************/
void make_svc_q_query_svc_config(SVC_Q_QUERY_SVC_CONFIG *q_c, POLICY_HND *hnd,
				uint32 buf_size)
{
	if (q_c == NULL || hnd == NULL) return;

	DEBUG(5,("make_svc_q_query_svc_config\n"));

	memcpy(&(q_c->pol), hnd, sizeof(q_c->pol));
	q_c->buf_size = buf_size;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_q_query_svc_config(char *desc,  SVC_Q_QUERY_SVC_CONFIG *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_q_query_svc_config");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(q_u->pol), ps, depth); 
	prs_align(ps);
	prs_uint32("buf_size", ps, depth, &(q_u->buf_size));
}

/*******************************************************************
makes an SVC_R_QUERY_SVC_CONFIG structure.
********************************************************************/
void make_svc_r_query_svc_config(SVC_R_QUERY_SVC_CONFIG *r_c, 
				QUERY_SERVICE_CONFIG *cfg,
				uint32 buf_size)
{
	if (r_c == NULL) return;

	DEBUG(5,("make_svc_r_query_svc_config\n"));

	r_c->cfg      = cfg;
	r_c->buf_size = buf_size;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_r_query_svc_config(char *desc,  SVC_R_QUERY_SVC_CONFIG *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_r_query_svc_config");
	depth++;

	prs_align(ps);

	svc_io_query_svc_cfg("cfg", r_u->cfg, ps, depth); 
	prs_uint32("buf_size", ps, depth, &(r_u->buf_size));
	prs_uint32("status  ", ps, depth, &(r_u->status  ));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_q_query_disp_name(char *desc, SVC_Q_QUERY_DISP_NAME *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_q_query_disp_name");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(q_u->scman_pol), ps, depth); 
	prs_align(ps);

	smb_io_unistr2("uni_svc_name", &(q_u->uni_svc_name), 1, ps, depth); 
	prs_align(ps);

	prs_uint32("buf_size", ps, depth, &(q_u->buf_size));
}

/*******************************************************************
makes an SVC_R_QUERY_DISP_NAME structure.
********************************************************************/
void make_svc_r_query_disp_name(SVC_R_QUERY_DISP_NAME *r_d, 
				char *disp_name, uint32 status)
{
	uint32 len = strlen(disp_name);

	if (r_d == NULL) return;

	DEBUG(5,("make_svc_r_query_disp_name\n"));

	make_unistr2(&(r_d->uni_disp_name), disp_name, len+1);
	r_d->buf_size = len;

	r_d->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_r_query_disp_name(char *desc, SVC_R_QUERY_DISP_NAME *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_r_query_disp_name");
	depth++;

	prs_align(ps);

	smb_io_unistr2("uni_disp_name", &(r_u->uni_disp_name), 1, ps, depth); 
	prs_align(ps);

	prs_uint32("buf_size", ps, depth, &(r_u->buf_size));
	prs_uint32("status  ", ps, depth, &(r_u->status  ));
}

/*******************************************************************
makes an SVC_Q_CLOSE structure.
********************************************************************/
void make_svc_q_close(SVC_Q_CLOSE *q_c, POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL) return;

	DEBUG(5,("make_svc_q_close\n"));

	memcpy(&(q_c->pol), hnd, sizeof(q_c->pol));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_q_close(char *desc,  SVC_Q_CLOSE *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_q_close");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(q_u->pol), ps, depth); 
	prs_align(ps);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void svc_io_r_close(char *desc,  SVC_R_CLOSE *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "svc_io_r_close");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(r_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}

