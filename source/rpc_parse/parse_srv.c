
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Paul Ashton                  1997-2000,
 *  Copyright (C) Elrond                            2000
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
#include "nterr.h"
#include "rpc_parse.h"

extern int DEBUGLEVEL;


/*******************************************************************
 makes a SH_INFO_1_STR structure
********************************************************************/
BOOL make_srv_sh_info1_str(SH_INFO_1_STR * sh1,
			   const char *net_name, const char *remark)
{
	if (sh1 == NULL)
		return False;

	DEBUG(5, ("make_srv_sh_info1_str\n"));

	make_unistr2(&(sh1->uni_netname), net_name, strlen(net_name) + 1);
	make_unistr2(&(sh1->uni_remark), remark, strlen(remark) + 1);

	return True;
}

static void srv_free_sh_info1_str(SH_INFO_1_STR * sh1)
{
	safe_free(sh1);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_sh_info1_str(char *desc, SH_INFO_1_STR * sh1,
				prs_struct *ps, int depth)
{
	if (sh1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_sh_info1_str");
	depth++;

	prs_align(ps);

	smb_io_unistr2("", &(sh1->uni_netname), True, ps, depth);
	prs_align(ps);
	smb_io_unistr2("", &(sh1->uni_remark), True, ps, depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
 makes a SH_INFO_1 structure
********************************************************************/
BOOL make_srv_sh_info1(SH_INFO_1 * sh1,
		       const char *net_name, uint32 type, const char *remark)
{
	if (sh1 == NULL)
		return False;

	DEBUG(5, ("make_srv_sh_info1: %s %8x %s\n", net_name, type, remark));

	sh1->ptr_netname = net_name != NULL ? 1 : 0;
	sh1->type = type;
	sh1->ptr_remark = remark != NULL ? 1 : 0;

	return True;
}

static void srv_free_sh_info1(SH_INFO_1 * sh1)
{
	safe_free(sh1);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_sh_info1(char *desc, SH_INFO_1 * sh1,
			    prs_struct *ps, int depth)
{
	if (sh1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_sh_info1");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_netname", ps, depth, &(sh1->ptr_netname));
	prs_uint32("type       ", ps, depth, &(sh1->type));
	prs_uint32("ptr_remark ", ps, depth, &(sh1->ptr_remark));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static void srv_free_srv_share_info_1(SRV_SHARE_INFO_1 * ctr)
{
	void (*fn) (void *) = (void (*)(void *))&srv_free_sh_info1;
	void (*fnstr) (void *) = (void (*)(void *))&srv_free_sh_info1_str;

	if (!ctr)
		return;

	free_void_array(ctr->num_entries_read, (void **)ctr->info_1, *fn);
	ctr->info_1 = NULL;
	free_void_array(ctr->num_entries_read,
			(void **)ctr->info_1_str, *fnstr);
	ctr->info_1_str = NULL;

	ctr->num_entries_read = 0;
	ctr->ptr_share_info = 0;
	ctr->num_entries_read2 = 0;
}

static BOOL srv_io_srv_share_info_1(char *desc, SRV_SHARE_INFO_1 * ctr,
				    prs_struct *ps, int depth)
{
	if (ctr == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_share_1_ctr");
	depth++;

	if (ps->io)
	{
		ZERO_STRUCTP(ctr);
	}

	prs_align(ps);

	prs_uint32("num_entries_read", ps, depth, &(ctr->num_entries_read));
	prs_uint32("ptr_share_info", ps, depth, &(ctr->ptr_share_info));

	if (ctr->ptr_share_info != 0)
	{
		uint32 i;
		uint32 num_entries = ctr->num_entries_read;

		prs_uint32("num_entries_read2", ps, depth,
			   &(ctr->num_entries_read2));

		if (ps->io)
		{
			ctr->info_1 = g_new0(SH_INFO_1 *, num_entries);
			ctr->info_1_str =
				g_new0(SH_INFO_1_STR *, num_entries);
			if (!ctr->info_1 || !ctr->info_1_str)
			{
				srv_free_srv_share_info_1(ctr);
				return False;
			}
		}

		for (i = 0; i < num_entries; i++)
		{
			if (ps->io)
			{
				ctr->info_1[i] = g_new(SH_INFO_1, 1);
			}
			if (!srv_io_sh_info1("", ctr->info_1[i], ps, depth))
			{
				srv_free_srv_share_info_1(ctr);
				return False;
			}
		}

		for (i = 0; i < num_entries; i++)
		{
			if (ps->io)
			{
				ctr->info_1_str[i] = g_new(SH_INFO_1_STR, 1);
			}
			if (!srv_io_sh_info1_str("", ctr->info_1_str[i],
						 ps, depth))
			{
				srv_free_srv_share_info_1(ctr);
				return False;
			}
		}

		prs_align(ps);
	}

	return True;
}

/*******************************************************************
 makes a SH_INFO_2_STR structure
********************************************************************/
BOOL make_srv_sh_info2_str(SH_INFO_2_STR * sh2,
			   const char *net_name, const char *remark,
			   const char *path, const char *pass)
{
	if (sh2 == NULL)
		return False;

	DEBUG(5, ("make_srv_sh_info2_str\n"));

	make_unistr2(&(sh2->uni_netname), net_name, strlen(net_name) + 1);
	make_unistr2(&(sh2->uni_remark), remark, strlen(remark) + 1);
	make_unistr2(&(sh2->uni_path), path, strlen(path) + 1);
	make_unistr2(&(sh2->uni_passwd), pass, strlen(pass) + 1);

	return True;
}

static void srv_free_sh_info2_str(SH_INFO_2_STR * sh2)
{
	safe_free(sh2);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_sh_info2_str(char *desc,
				SH_INFO_2_STR * ss2, SH_INFO_2 * sh2,
				prs_struct *ps, int depth)
{
	if (ss2 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_sh_info2_str");
	depth++;

	prs_align(ps);

	smb_io_unistr2("netname", &(ss2->uni_netname), sh2->ptr_netname, ps,
		       depth);
	prs_align(ps);
	smb_io_unistr2("remark ", &(ss2->uni_remark), sh2->ptr_remark, ps,
		       depth);
	prs_align(ps);
	smb_io_unistr2("path   ", &(ss2->uni_path), sh2->ptr_path, ps, depth);
	prs_align(ps);
	smb_io_unistr2("passwd ", &(ss2->uni_passwd), sh2->ptr_passwd, ps,
		       depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
 makes a SH_INFO_2 structure
********************************************************************/
BOOL make_srv_sh_info2(SH_INFO_2 * sh2,
		       const char *net_name, uint32 type,
		       const char *remark,
		       uint32 perms, uint32 max_uses, uint32 num_uses,
		       const char *path, const char *pass)
{
	if (sh2 == NULL)
		return False;

	DEBUG(5, ("make_srv_sh_info2: %s %8x %s\n", net_name, type, remark));

	sh2->ptr_netname = net_name != NULL ? 1 : 0;
	sh2->type = type;
	sh2->ptr_remark = remark != NULL ? 1 : 0;
	sh2->perms = perms;
	sh2->max_uses = max_uses;
	sh2->num_uses = num_uses;
	sh2->type = type;
	sh2->ptr_path = path != NULL ? 1 : 0;
	sh2->ptr_passwd = pass != NULL ? 1 : 0;

	return True;
}

static void srv_free_sh_info2_hdr(SH_INFO_2 * sh2)
{
	safe_free(sh2);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_sh_info2_hdr(char *desc, SH_INFO_2 * sh2,
				prs_struct *ps, int depth)
{
	if (sh2 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_sh_info2_hdr");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_netname", ps, depth, &(sh2->ptr_netname));
	prs_uint32("type       ", ps, depth, &(sh2->type));
	prs_uint32("ptr_remark ", ps, depth, &(sh2->ptr_remark));
	prs_uint32("perms      ", ps, depth, &(sh2->perms));
	prs_uint32("max_uses   ", ps, depth, &(sh2->max_uses));
	prs_uint32("num_uses   ", ps, depth, &(sh2->num_uses));
	prs_uint32("ptr_path   ", ps, depth, &(sh2->ptr_path));
	prs_uint32("ptr_passwd ", ps, depth, &(sh2->ptr_passwd));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static void srv_free_sh_info502_hdr(SH_INFO_502_HDR * sh502)
{
}

static BOOL srv_io_sh_info502_hdr(char *desc, SH_INFO_502_HDR * sh502,
				  prs_struct *ps, int depth)
{
	if (sh502 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_sh_info502_hdr");
	depth++;

	prs_align(ps);

	srv_io_sh_info2_hdr("", &(sh502->info2_hdr), ps, depth);

	prs_uint32("sd_size", ps, depth, &(sh502->sd_size));
	prs_uint32("sd_ptr ", ps, depth, &(sh502->sd_ptr));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static void srv_free_sh_info502_data(SH_INFO_502_DATA * sh502)
{
	if (sh502 == NULL)
	{
		return;
	}
	free_sec_desc(&sh502->sd);
	ZERO_STRUCT(sh502->sd);
}

static BOOL srv_io_sh_info502_data(char *desc,
				   SH_INFO_502_DATA * sh502,
				   SH_INFO_502_HDR * si502,
				   prs_struct *ps, int depth)
{
	if (sh502 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_sh_info502_data");
	depth++;

	prs_align(ps);

	srv_io_sh_info2_str("", &(sh502->info2_str), &(si502->info2_hdr),
			    ps, depth);
	prs_align(ps);

	if (si502->sd_ptr)
	{
		prs_uint32("sd_size2", ps, depth, &(sh502->sd_size2));

		sec_io_desc("", &(sh502->sd), ps, depth);
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static void srv_free_share_info_2(SHARE_INFO_2 * sh2)
{
	if (sh2 == NULL)
		return;
}

static BOOL srv_io_share_info_2(char *desc, SHARE_INFO_2 * sh2, uint32 count,
				prs_struct *ps, int depth)
{
	if (sh2 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_share_info2");
	depth++;

	prs_align(ps);

	srv_io_sh_info2_hdr("", &sh2->info2_hdr, ps, depth);
	srv_io_sh_info2_str("", &sh2->info2_str, &sh2->info2_hdr, ps, depth);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static void srv_free_share_info_502(SHARE_INFO_502 * sh502)
{
	if (sh502 == NULL)
		return;
	srv_free_sh_info502_hdr(&sh502->info502_hdr);
	srv_free_sh_info502_data(&sh502->info502_data);
}

static BOOL srv_io_share_info_502(char *desc,
				  SHARE_INFO_502 * sh502, uint32 count,
				  prs_struct *ps, int depth)
{
	if (sh502 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_share_info502");
	depth++;

	prs_align(ps);

	srv_io_sh_info502_hdr("", &(sh502->info502_hdr), ps, depth);
	srv_io_sh_info502_data("", &(sh502->info502_data),
			       &(sh502->info502_hdr), ps, depth);

	return True;
}

/*******************************************************************
 reads or writes a structure.
 ********************************************************************/
static void srv_free_share_info_union(SHARE_INFO_UNION * info,
				      uint32 info_level, uint32 count)
{
	uint32 i;
	if (info == NULL)
		return;

	switch (info_level)
	{
		case 2:
		{
			for (i = 0; i < count; i++)
			{
				srv_free_share_info_2(&(info->id2[i]));
			}
			safe_free(info->id2);
			info->id2 = NULL;
			break;
		}
		case 502:
		{
			for (i = 0; i < count; i++)
			{
				srv_free_share_info_502(&(info->id502[i]));
			}
			safe_free(info->id502);
			info->id502 = NULL;
			break;
		}
		default:
		{
			DEBUG(1,
			      ("srv_free_share_info_union: Unsupported info level %d\n",
			       info_level));
			break;
		}
	}
}

static BOOL srv_io_share_info_union(const char *desc,
				    SHARE_INFO_UNION * info,
				    uint32 info_level, uint32 count,
				    prs_struct *ps, int depth)
{
	if (info == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_share_info_union");
	depth++;

	prs_align(ps);

	switch (info_level)
	{
		case 2:
		{
			if (UNMARSHALLING(ps))
			{
				info->id2 = g_new(SHARE_INFO_2, count);
				if (info->id2 == NULL)
				{
					DEBUG(1,
					      ("srv_io_share_info_ctr at level 2: malloc failed\n"));
					return False;
				}
			}
			return srv_io_share_info_2("", info->id2, count,
						   ps, depth);
		}
		case 502:
		{
			if (UNMARSHALLING(ps))
			{
				info->id502 = g_new(SHARE_INFO_502, count);
				if (info->id502 == NULL)
				{
					DEBUG(1,
					      ("srv_io_share_info_ctr at level 502: malloc failed\n"));
					return False;
				}
			}
			return srv_io_share_info_502("", info->id502, count,
						     ps, depth);
		}
		default:
		{
			DEBUG(1,
			      ("srv_io_share_info_ctr: Unsupported info level %d\n",
			       info_level));
			return False;
		}
	}
}

/*******************************************************************
 reads or writes a structure.
 ********************************************************************/
void srv_free_share_info_ctr(SHARE_INFO_CTR * info)
{
	if (info == NULL)
		return;

	srv_free_share_info_union(&info->info, info->info_level, 1);
}

static BOOL srv_io_share_info_ctr(const char *desc,
				  SHARE_INFO_CTR * info,
				  prs_struct *ps, int depth)
{
	if (info == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_share_info_ctr");
	depth++;

	prs_align(ps);

	prs_uint32("info_level", ps, depth, &info->info_level);
	prs_uint32("info_ptr  ", ps, depth, &info->info_ptr);

	if (info->info_ptr == 0)
	{
		return True;
	}

	return srv_io_share_info_union("", &info->info, info->info_level, 1,
				       ps, depth);
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
static void srv_free_srv_share_info_2(SRV_SHARE_INFO_2 * ctr)
{
	void (*fn) (void *) = (void (*)(void *))&srv_free_sh_info2_hdr;
	void (*fnstr) (void *) = (void (*)(void *))&srv_free_sh_info2_str;

	if (!ctr)
		return;

	free_void_array(ctr->num_entries_read, (void **)ctr->info_2, *fn);
	free_void_array(ctr->num_entries_read,
			(void **)ctr->info_2_str, *fnstr);

	ctr->num_entries_read = 0;
	ctr->ptr_share_info = 0;
}

static BOOL srv_io_srv_share_info_2(char *desc, SRV_SHARE_INFO_2 * ctr,
				    prs_struct *ps, int depth)
{
	if (ctr == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_share_2_ctr");
	depth++;

	if (ps->io)
	{
		ZERO_STRUCTP(ctr);
	}

	prs_align(ps);

	prs_uint32("num_entries_read", ps, depth, &(ctr->num_entries_read));
	prs_uint32("ptr_share_info", ps, depth, &(ctr->ptr_share_info));

	if (ctr->ptr_share_info != 0)
	{
		uint32 i;
		uint32 num_entries = ctr->num_entries_read;

		prs_uint32("num_entries_read2", ps, depth,
			   &(ctr->num_entries_read2));

		if (ps->io)
		{
			ctr->info_2 = g_new0(SH_INFO_2 *, num_entries);
			ctr->info_2_str =
				g_new0(SH_INFO_2_STR *, num_entries);
			if (!ctr->info_2 || !ctr->info_2_str)
			{
				srv_free_srv_share_info_2(ctr);
				return False;
			}
		}

		for (i = 0; i < num_entries; i++)
		{
			if (ps->io)
			{
				ctr->info_2[i] = g_new(SH_INFO_2, 1);
			}
			if (!srv_io_sh_info2_hdr("",
						 ctr->info_2[i], ps, depth))
			{
				srv_free_srv_share_info_2(ctr);
				return False;
			}
		}

		for (i = 0; i < num_entries; i++)
		{
			if (ps->io)
			{
				ctr->info_2_str[i] = g_new(SH_INFO_2_STR, 1);
			}
			if (!srv_io_sh_info2_str("",
						 ctr->info_2_str[i],
						 ctr->info_2[i], ps, depth))
			{
				srv_free_srv_share_info_2(ctr);
				return False;
			}
		}

		prs_align(ps);
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void srv_free_srv_share_ctr(SRV_SHARE_INFO_CTR * ctr)
{
	if (!ctr)
		return;
	switch (ctr->switch_value)
	{
		case 2:
		{
			srv_free_srv_share_info_2(&(ctr->share.info2));
			break;
		}
		case 1:
		{
			srv_free_srv_share_info_1(&(ctr->share.info1));
			break;
		}
	}
}

static BOOL srv_io_srv_share_ctr(char *desc, SRV_SHARE_INFO_CTR * ctr,
				 prs_struct *ps, int depth)
{
	if (ctr == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_share_ctr");
	depth++;

	prs_align(ps);

	prs_uint32("switch_value", ps, depth, &(ctr->switch_value));
	prs_uint32("ptr_share_ctr", ps, depth, &(ctr->ptr_share_ctr));

	if (ctr->ptr_share_ctr != 0)
	{
		switch (ctr->switch_value)
		{
			case 2:
			{
				srv_io_srv_share_info_2("",
							&(ctr->share.info2),
							ps, depth);
				break;
			}
			case 1:
			{
				srv_io_srv_share_info_1("",
							&(ctr->share.info1),
							ps, depth);
				break;
			}
			default:
			{
				DEBUG(5,
				      ("%s no share info at switch_value %d\n",
				       tab_depth(depth), ctr->switch_value));
				break;
			}
		}
	}

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_srv_q_net_share_enum(SRV_Q_NET_SHARE_ENUM * q_n,
			       const char *srv_name,
			       uint32 share_level, SRV_SHARE_INFO_CTR * ctr,
			       uint32 preferred_len, ENUM_HND * hnd)
{
	if (q_n == NULL || ctr == NULL || hnd == NULL)
		return False;

	q_n->ctr = ctr;

	DEBUG(5, ("make_q_net_share_enum\n"));

	make_buf_unistr2(&(q_n->uni_srv_name), &(q_n->ptr_srv_name),
			 srv_name);

	q_n->share_level = share_level;
	q_n->preferred_len = preferred_len;

	memcpy(&(q_n->enum_hnd), hnd, sizeof(*hnd));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_q_net_share_enum(char *desc, SRV_Q_NET_SHARE_ENUM * q_n,
			     prs_struct *ps, int depth)
{
	if (q_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_q_net_share_enum");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_n->ptr_srv_name));
	smb_io_unistr2("", &(q_n->uni_srv_name), True, ps, depth);

	prs_align(ps);

	prs_uint32("share_level", ps, depth, &(q_n->share_level));

	if (((int)q_n->share_level) != -1)
	{
		srv_io_srv_share_ctr("share_ctr", q_n->ctr, ps, depth);
	}

	prs_uint32("preferred_len", ps, depth, &(q_n->preferred_len));

	smb_io_enum_hnd("enum_hnd", &(q_n->enum_hnd), ps, depth);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_r_net_share_enum(char *desc, SRV_R_NET_SHARE_ENUM * r_n,
			     prs_struct *ps, int depth)
{
	if (r_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_r_net_share_enum");
	depth++;

	prs_align(ps);

	prs_uint32("share_level", ps, depth, &(r_n->share_level));

	if (r_n->share_level != 0)
	{
		srv_io_srv_share_ctr("share_ctr", r_n->ctr, ps, depth);
	}

	prs_uint32("total_entries", ps, depth, &(r_n->total_entries));
	smb_io_enum_hnd("enum_hnd", &(r_n->enum_hnd), ps, depth);
	prs_uint32("status     ", ps, depth, &(r_n->status));

	return True;
}


/*******************************************************************
 makes a structure
********************************************************************/
BOOL make_srv_q_net_share_get_info(SRV_Q_NET_SHARE_GET_INFO * q_n,
				   const UNISTR2 *srv_name,
				   const UNISTR2 *share_name,
				   uint32 info_level)
{
	if (q_n == NULL)
		return False;

	q_n->ptr_srv_name = (srv_name != NULL);
	copy_unistr2(&(q_n->uni_srv_name), srv_name);
	copy_unistr2(&(q_n->share_name), share_name);
	q_n->info_level = info_level;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_q_net_share_get_info(char *desc, SRV_Q_NET_SHARE_GET_INFO * q_n,
				 prs_struct *ps, int depth)
{
	if (q_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_q_net_share_get_info");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_n->ptr_srv_name));
	smb_io_unistr2("uni_srv_name", &(q_n->uni_srv_name), True, ps, depth);
	prs_align(ps);

	smb_io_unistr2("share_name", &(q_n->share_name), True, ps, depth);
	prs_align(ps);

	prs_uint32("info_level", ps, depth, &(q_n->info_level));

	return True;
}

/*******************************************************************
 makes a structure
********************************************************************/
BOOL make_srv_r_net_share_get_info(SRV_R_NET_SHARE_GET_INFO * r_n,
				   uint32 info_level,
				   SHARE_INFO_CTR * ctr, uint32 status)
{
	if (r_n == NULL)
		return False;

	ctr->info_level = info_level;

	if (status == NT_STATUS_NOPROBLEMO)
	{
		if (ctr != NULL)
		{
			ctr->info_ptr = 1;
			r_n->ctr = ctr;
		}
		else
		{
			ctr->info_ptr = 0;
			r_n->ctr = NULL;
		}
	}
	else
	{
		ctr->info_ptr = 0;
	}

	r_n->status = status;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_r_net_share_get_info(char *desc, SRV_R_NET_SHARE_GET_INFO * r_n,
				 prs_struct *ps, int depth)
{
	if (r_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_r_net_share_get_info");
	depth++;

	prs_align(ps);

	if (!srv_io_share_info_ctr("info_ctr", r_n->ctr, ps, depth))
	{
		return False;
	}

	prs_uint32("status    ", ps, depth, &r_n->status);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_q_net_share_add(char *desc, SRV_Q_NET_SHARE_ADD * q_n,
			    prs_struct *ps, int depth)
{
	if (q_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_q_net_share_add");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_n->ptr_srv_name));
	smb_io_unistr2("uni_srv_name", &(q_n->uni_srv_name), True, ps, depth);
	prs_align(ps);

	prs_uint32("info_level", ps, depth, &q_n->info_level);

	if (!srv_io_share_info_ctr("info_ctr", &q_n->ctr, ps, depth))
	{
		return False;
	}

	prs_uint32("parm_error", ps, depth, &q_n->parm_error);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_r_net_share_add(char *desc, SRV_R_NET_SHARE_ADD * r_n,
			    prs_struct *ps, int depth)
{
	if (r_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_r_net_share_add");
	depth++;

	prs_align(ps);

	prs_uint32("parm_error", ps, depth, &r_n->parm_error);
	prs_uint32("status    ", ps, depth, &r_n->status);

	return True;
}


/*******************************************************************
 makes a SESS_INFO_0_STR structure
********************************************************************/
BOOL make_srv_sess_info0_str(SESS_INFO_0_STR * ss0, char *name)
{
	if (ss0 == NULL)
		return False;

	DEBUG(5, ("make_srv_sess_info0_str\n"));

	make_unistr2(&(ss0->uni_name), name, strlen(name) + 1);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_sess_info0_str(char *desc, SESS_INFO_0_STR * ss0,
				  const SESS_INFO_0 * si0,
				  prs_struct *ps, int depth)
{
	if (ss0 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_sess_info0_str");
	depth++;

	prs_align(ps);

	smb_io_unistr2("", &(ss0->uni_name), si0->ptr_name, ps, depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
 makes a SESS_INFO_0 structure
********************************************************************/
BOOL make_srv_sess_info0(SESS_INFO_0 * ss0, char *name)
{
	if (ss0 == NULL)
		return False;

	DEBUG(5, ("make_srv_sess_info0: %s\n", name));

	ss0->ptr_name = name != NULL ? 1 : 0;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_sess_info0(char *desc, SESS_INFO_0 * ss0,
			      prs_struct *ps, int depth)
{
	if (ss0 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_sess_info0");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_name", ps, depth, &(ss0->ptr_name));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_srv_sess_info_0(char *desc, SRV_SESS_INFO_0 * ss0,
				   prs_struct *ps, int depth)
{
	if (ss0 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_sess_info_0");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries_read", ps, depth, &(ss0->num_entries_read));
	prs_uint32("ptr_sess_info", ps, depth, &(ss0->ptr_sess_info));

	if (ss0->ptr_sess_info != 0)
	{
		uint32 i;
		uint32 num_entries = ss0->num_entries_read;
		if (num_entries > MAX_SESS_ENTRIES)
		{
			num_entries = MAX_SESS_ENTRIES;	/* report this! */
		}

		prs_uint32("num_entries_read2", ps, depth,
			   &(ss0->num_entries_read2));

		SMB_ASSERT_ARRAY(ss0->info_0, num_entries);

		for (i = 0; i < num_entries; i++)
		{
			srv_io_sess_info0("", &(ss0->info_0[i]), ps, depth);
		}

		for (i = 0; i < num_entries; i++)
		{
			srv_io_sess_info0_str("", &(ss0->info_0_str[i]),
					      &(ss0->info_0[i]), ps, depth);
		}

		prs_align(ps);
	}

	return True;
}

/*******************************************************************
 makes a SESS_INFO_1_STR structure
********************************************************************/
BOOL make_srv_sess_info1_str(SESS_INFO_1_STR * ss1, char *name, char *user)
{
	if (ss1 == NULL)
		return False;

	DEBUG(5, ("make_srv_sess_info1_str\n"));

	make_unistr2(&(ss1->uni_name), name, strlen(name) + 1);
	make_unistr2(&(ss1->uni_user), name, strlen(user) + 1);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_sess_info1_str(char *desc, SESS_INFO_1_STR * ss1,
				  SESS_INFO_1 * si1,
				  prs_struct *ps, int depth)
{
	if (ss1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_sess_info1_str");
	depth++;

	prs_align(ps);

	smb_io_unistr2("", &(ss1->uni_name), si1->ptr_name, ps, depth);
	prs_align(ps);
	smb_io_unistr2("", &(ss1->uni_user), si1->ptr_user, ps, depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
 makes a SESS_INFO_1 structure
********************************************************************/
BOOL make_srv_sess_info1(SESS_INFO_1 * ss1,
			 char *name, char *user,
			 uint32 num_opens, uint32 open_time, uint32 idle_time,
			 uint32 user_flags)
{
	if (ss1 == NULL)
		return False;

	DEBUG(5, ("make_srv_sess_info1: %s\n", name));

	ss1->ptr_name = name != NULL ? 1 : 0;
	ss1->ptr_user = user != NULL ? 1 : 0;

	ss1->num_opens = num_opens;
	ss1->open_time = open_time;
	ss1->idle_time = idle_time;
	ss1->user_flags = user_flags;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_sess_info1(char *desc, SESS_INFO_1 * ss1,
			      prs_struct *ps, int depth)
{
	if (ss1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_sess_info1");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_name  ", ps, depth, &(ss1->ptr_name));
	prs_uint32("ptr_user  ", ps, depth, &(ss1->ptr_user));

	prs_uint32("num_opens ", ps, depth, &(ss1->num_opens));
	prs_uint32("open_time ", ps, depth, &(ss1->open_time));
	prs_uint32("idle_time ", ps, depth, &(ss1->idle_time));
	prs_uint32("user_flags", ps, depth, &(ss1->user_flags));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_srv_sess_info_1(char *desc, SRV_SESS_INFO_1 * ss1,
				   prs_struct *ps, int depth)
{
	if (ss1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_sess_info_1");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries_read", ps, depth, &(ss1->num_entries_read));
	prs_uint32("ptr_sess_info", ps, depth, &(ss1->ptr_sess_info));

	if (ss1->ptr_sess_info != 0)
	{
		uint32 i;
		uint32 num_entries = ss1->num_entries_read;
		if (num_entries > MAX_SESS_ENTRIES)
		{
			num_entries = MAX_SESS_ENTRIES;	/* report this! */
		}

		prs_uint32("num_entries_read2", ps, depth,
			   &(ss1->num_entries_read2));

		SMB_ASSERT_ARRAY(ss1->info_1, num_entries);

		for (i = 0; i < num_entries; i++)
		{
			srv_io_sess_info1("", &(ss1->info_1[i]), ps, depth);
		}

		for (i = 0; i < num_entries; i++)
		{
			srv_io_sess_info1_str("", &(ss1->info_1_str[i]),
					      &(ss1->info_1[i]), ps, depth);
		}

		prs_align(ps);
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_srv_sess_ctr(char *desc, SRV_SESS_INFO_CTR * ctr,
				prs_struct *ps, int depth)
{
	if (ctr == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_sess_ctr");
	depth++;

	prs_align(ps);

	prs_uint32("switch_value", ps, depth, &(ctr->switch_value));
	prs_uint32("ptr_sess_ctr", ps, depth, &(ctr->ptr_sess_ctr));

	if (ctr->ptr_sess_ctr != 0)
	{
		switch (ctr->switch_value)
		{
			case 0:
			{
				srv_io_srv_sess_info_0("", &(ctr->sess.info0),
						       ps, depth);
				break;
			}
			case 1:
			{
				srv_io_srv_sess_info_1("", &(ctr->sess.info1),
						       ps, depth);
				break;
			}
			default:
			{
				DEBUG(5,
				      ("%s no session info at switch_value %d\n",
				       tab_depth(depth), ctr->switch_value));
				break;
			}
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_srv_q_net_sess_enum(SRV_Q_NET_SESS_ENUM * q_n,
			      const char *srv_name, const char *qual_name,
			      char *user_name,
			      uint32 sess_level, SRV_SESS_INFO_CTR * ctr,
			      uint32 preferred_len, ENUM_HND * hnd)
{
	if (q_n == NULL || ctr == NULL || hnd == NULL)
		return False;

	q_n->ctr = ctr;

	DEBUG(5, ("make_q_net_sess_enum\n"));

	make_buf_unistr2(&(q_n->uni_srv_name), &(q_n->ptr_srv_name),
			 srv_name);
	make_buf_unistr2(&(q_n->uni_qual_name), &(q_n->ptr_qual_name),
			 qual_name);
	make_buf_unistr2(&(q_n->uni_user_name), &(q_n->ptr_user_name),
			 user_name);

	q_n->sess_level = sess_level;
	q_n->preferred_len = preferred_len;

	memcpy(&(q_n->enum_hnd), hnd, sizeof(*hnd));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_q_net_sess_enum(char *desc, SRV_Q_NET_SESS_ENUM * q_n,
			    prs_struct *ps, int depth)
{
	if (q_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_q_net_sess_enum");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_n->ptr_srv_name));
	smb_io_unistr2("", &(q_n->uni_srv_name), True, ps, depth);
	prs_align(ps);

	prs_uint32("ptr_qual_name", ps, depth, &(q_n->ptr_qual_name));
	smb_io_unistr2("", &(q_n->uni_qual_name), q_n->ptr_qual_name, ps,
		       depth);
	prs_align(ps);

	prs_uint32("ptr_user_name", ps, depth, &(q_n->ptr_user_name));
	smb_io_unistr2("", &(q_n->uni_user_name), q_n->ptr_user_name, ps,
		       depth);
	prs_align(ps);

	prs_uint32("sess_level", ps, depth, &(q_n->sess_level));

	if (((int)q_n->sess_level) != -1)
	{
		srv_io_srv_sess_ctr("sess_ctr", q_n->ctr, ps, depth);
	}

	prs_uint32("preferred_len", ps, depth, &(q_n->preferred_len));

	smb_io_enum_hnd("enum_hnd", &(q_n->enum_hnd), ps, depth);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_r_net_sess_enum(char *desc, SRV_R_NET_SESS_ENUM * r_n,
			    prs_struct *ps, int depth)
{
	if (r_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_r_net_sess_enum");
	depth++;

	prs_align(ps);

	prs_uint32("sess_level", ps, depth, &(r_n->sess_level));

	if (((int)r_n->sess_level) != -1)
	{
		srv_io_srv_sess_ctr("sess_ctr", r_n->ctr, ps, depth);
	}

	prs_uint32("total_entries", ps, depth, &(r_n->total_entries));
	smb_io_enum_hnd("enum_hnd", &(r_n->enum_hnd), ps, depth);
	prs_uint32("status     ", ps, depth, &(r_n->status));

	return True;
}

/*******************************************************************
 makes a CONN_INFO_0 structure
********************************************************************/
BOOL make_srv_conn_info0(CONN_INFO_0 * ss0, uint32 id)
{
	if (ss0 == NULL)
		return False;

	DEBUG(5, ("make_srv_conn_info0\n"));

	ss0->id = id;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_conn_info0(char *desc, CONN_INFO_0 * ss0,
			      prs_struct *ps, int depth)
{
	if (ss0 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_conn_info0");
	depth++;

	prs_align(ps);

	prs_uint32("id", ps, depth, &(ss0->id));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_srv_conn_info_0(char *desc, SRV_CONN_INFO_0 * ss0,
				   prs_struct *ps, int depth)
{
	if (ss0 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_conn_info_0");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries_read", ps, depth, &(ss0->num_entries_read));
	prs_uint32("ptr_conn_info", ps, depth, &(ss0->ptr_conn_info));

	if (ss0->ptr_conn_info != 0)
	{
		uint32 i;
		uint32 num_entries = ss0->num_entries_read;
		if (num_entries > MAX_CONN_ENTRIES)
		{
			num_entries = MAX_CONN_ENTRIES;	/* report this! */
		}

		prs_uint32("num_entries_read2", ps, depth,
			   &(ss0->num_entries_read2));

		for (i = 0; i < num_entries; i++)
		{
			srv_io_conn_info0("", &(ss0->info_0[i]), ps, depth);
		}

		prs_align(ps);
	}

	return True;
}

/*******************************************************************
 makes a CONN_INFO_1_STR structure
********************************************************************/
BOOL make_srv_conn_info1_str(CONN_INFO_1_STR * ss1, char *usr_name,
			     char *net_name)
{
	if (ss1 == NULL)
		return False;

	DEBUG(5, ("make_srv_conn_info1_str\n"));

	make_unistr2(&(ss1->uni_usr_name), usr_name, strlen(usr_name) + 1);
	make_unistr2(&(ss1->uni_net_name), net_name, strlen(net_name) + 1);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_conn_info1_str(char *desc, CONN_INFO_1_STR * ss1,
				  CONN_INFO_1 * ci1,
				  prs_struct *ps, int depth)
{
	if (ss1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_conn_info1_str");
	depth++;

	prs_align(ps);

	smb_io_unistr2("", &(ss1->uni_usr_name), ci1->ptr_usr_name, ps,
		       depth);
	prs_align(ps);
	smb_io_unistr2("", &(ss1->uni_net_name), ci1->ptr_net_name, ps,
		       depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
 makes a CONN_INFO_1 structure
********************************************************************/
BOOL make_srv_conn_info1(CONN_INFO_1 * ss1,
			 uint32 id, uint32 type,
			 uint32 num_opens, uint32 num_users, uint32 open_time,
			 char *usr_name, char *net_name)
{
	if (ss1 == NULL)
		return False;

	DEBUG(5, ("make_srv_conn_info1: %s %s\n", usr_name, net_name));

	ss1->id = id;
	ss1->type = type;
	ss1->num_opens = num_opens;
	ss1->num_users = num_users;
	ss1->open_time = open_time;

	ss1->ptr_usr_name = usr_name != NULL ? 1 : 0;
	ss1->ptr_net_name = net_name != NULL ? 1 : 0;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_conn_info1(char *desc, CONN_INFO_1 * ss1,
			      prs_struct *ps, int depth)
{
	if (ss1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_conn_info1");
	depth++;

	prs_align(ps);

	prs_uint32("id          ", ps, depth, &(ss1->id));
	prs_uint32("type        ", ps, depth, &(ss1->type));
	prs_uint32("num_opens   ", ps, depth, &(ss1->num_opens));
	prs_uint32("num_users   ", ps, depth, &(ss1->num_users));
	prs_uint32("open_time   ", ps, depth, &(ss1->open_time));

	prs_uint32("ptr_usr_name", ps, depth, &(ss1->ptr_usr_name));
	prs_uint32("ptr_net_name", ps, depth, &(ss1->ptr_net_name));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_srv_conn_info_1(char *desc, SRV_CONN_INFO_1 * ss1,
				   prs_struct *ps, int depth)
{
	if (ss1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_conn_info_1");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries_read", ps, depth, &(ss1->num_entries_read));
	prs_uint32("ptr_conn_info", ps, depth, &(ss1->ptr_conn_info));

	if (ss1->ptr_conn_info != 0)
	{
		uint32 i;
		uint32 num_entries = ss1->num_entries_read;
		if (num_entries > MAX_CONN_ENTRIES)
		{
			num_entries = MAX_CONN_ENTRIES;	/* report this! */
		}

		prs_uint32("num_entries_read2", ps, depth,
			   &(ss1->num_entries_read2));

		for (i = 0; i < num_entries; i++)
		{
			srv_io_conn_info1("", &(ss1->info_1[i]), ps, depth);
		}

		for (i = 0; i < num_entries; i++)
		{
			srv_io_conn_info1_str("", &(ss1->info_1_str[i]),
					      &(ss1->info_1[i]), ps, depth);
		}

		prs_align(ps);
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_srv_conn_ctr(char *desc, SRV_CONN_INFO_CTR * ctr,
				prs_struct *ps, int depth)
{
	if (ctr == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_conn_ctr");
	depth++;

	prs_align(ps);

	prs_uint32("switch_value", ps, depth, &(ctr->switch_value));
	prs_uint32("ptr_conn_ctr", ps, depth, &(ctr->ptr_conn_ctr));

	if (ctr->ptr_conn_ctr != 0)
	{
		switch (ctr->switch_value)
		{
			case 0:
			{
				srv_io_srv_conn_info_0("", &(ctr->conn.info0),
						       ps, depth);
				break;
			}
			case 1:
			{
				srv_io_srv_conn_info_1("", &(ctr->conn.info1),
						       ps, depth);
				break;
			}
			default:
			{
				DEBUG(5,
				      ("%s no connection info at switch_value %d\n",
				       tab_depth(depth), ctr->switch_value));
				break;
			}
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_srv_q_net_conn_enum(SRV_Q_NET_CONN_ENUM * q_n,
			      const char *srv_name, const char *qual_name,
			      uint32 conn_level, SRV_CONN_INFO_CTR * ctr,
			      uint32 preferred_len, ENUM_HND * hnd)
{
	if (q_n == NULL || ctr == NULL || hnd == NULL)
		return False;

	q_n->ctr = ctr;

	DEBUG(5, ("make_q_net_conn_enum\n"));

	make_buf_unistr2(&(q_n->uni_srv_name), &(q_n->ptr_srv_name),
			 srv_name);
	make_buf_unistr2(&(q_n->uni_qual_name), &(q_n->ptr_qual_name),
			 qual_name);

	q_n->conn_level = conn_level;
	q_n->preferred_len = preferred_len;

	memcpy(&(q_n->enum_hnd), hnd, sizeof(*hnd));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_q_net_conn_enum(char *desc, SRV_Q_NET_CONN_ENUM * q_n,
			    prs_struct *ps, int depth)
{
	if (q_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_q_net_conn_enum");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name ", ps, depth, &(q_n->ptr_srv_name));
	smb_io_unistr2("", &(q_n->uni_srv_name), q_n->ptr_srv_name, ps,
		       depth);
	prs_align(ps);

	prs_uint32("ptr_qual_name", ps, depth, &(q_n->ptr_qual_name));
	smb_io_unistr2("", &(q_n->uni_qual_name), q_n->ptr_qual_name, ps,
		       depth);
	prs_align(ps);

	prs_uint32("conn_level", ps, depth, &(q_n->conn_level));

	if (((int)q_n->conn_level) != -1)
	{
		srv_io_srv_conn_ctr("conn_ctr", q_n->ctr, ps, depth);
	}

	prs_uint32("preferred_len", ps, depth, &(q_n->preferred_len));

	smb_io_enum_hnd("enum_hnd", &(q_n->enum_hnd), ps, depth);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_r_net_conn_enum(char *desc, SRV_R_NET_CONN_ENUM * r_n,
			    prs_struct *ps, int depth)
{
	if (r_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_r_net_conn_enum");
	depth++;

	prs_align(ps);

	prs_uint32("conn_level", ps, depth, &(r_n->conn_level));

	if (((int)r_n->conn_level) != -1)
	{
		srv_io_srv_conn_ctr("conn_ctr", r_n->ctr, ps, depth);
	}

	prs_uint32("total_entries", ps, depth, &(r_n->total_entries));
	smb_io_enum_hnd("enum_hnd", &(r_n->enum_hnd), ps, depth);
	prs_uint32("status     ", ps, depth, &(r_n->status));

	return True;
}

/*******************************************************************
 makes a TPRT_INFO_0_STR structure
********************************************************************/
BOOL make_srv_tprt_info0_str(TPRT_INFO_0_STR * tp0,
			     char *trans_name,
			     char *trans_addr, uint32 trans_addr_len,
			     char *addr_name)
{
	if (tp0 == NULL)
		return False;

	DEBUG(5, ("make_srv_tprt_info0_str\n"));

	make_unistr2(&(tp0->uni_trans_name), trans_name,
		     strlen(trans_name) + 1);
	make_buffer4_str(&(tp0->buf_trans_addr), trans_addr, trans_addr_len);
	make_unistr2(&(tp0->uni_addr_name), addr_name, strlen(addr_name) + 1);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_tprt_info0_str(char *desc, TPRT_INFO_0_STR * tp0,
				  TPRT_INFO_0 * ti0,
				  prs_struct *ps, int depth)
{
	if (tp0 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_tprt_info0_str");
	depth++;

	prs_align(ps);

	smb_io_unistr2("", &(tp0->uni_trans_name), ti0->ptr_trans_name, ps,
		       depth);
	prs_align(ps);
	smb_io_buffer4("", &(tp0->buf_trans_addr), ti0->ptr_trans_addr, ps,
		       depth);
	prs_align(ps);
	smb_io_unistr2("", &(tp0->uni_addr_name), ti0->ptr_addr_name, ps,
		       depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
 makes a TPRT_INFO_0 structure
********************************************************************/
BOOL make_srv_tprt_info0(TPRT_INFO_0 * tp0,
			 uint32 num_vcs, uint32 trans_addr_len,
			 char *trans_name, char *trans_addr, char *addr_name)
{
	if (tp0 == NULL)
		return False;

	DEBUG(5, ("make_srv_tprt_info0: %s %s\n", trans_name, addr_name));

	tp0->num_vcs = num_vcs;
	tp0->ptr_trans_name = trans_name != NULL ? 1 : 0;
	tp0->ptr_trans_addr = trans_addr != NULL ? 1 : 0;
	tp0->trans_addr_len = trans_addr_len;
	tp0->ptr_addr_name = addr_name != NULL ? 1 : 0;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_tprt_info0(char *desc, TPRT_INFO_0 * tp0,
			      prs_struct *ps, int depth)
{
	if (tp0 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_tprt_info0");
	depth++;

	prs_align(ps);

	prs_uint32("num_vcs       ", ps, depth, &(tp0->num_vcs));
	prs_uint32("ptr_trans_name", ps, depth, &(tp0->ptr_trans_name));
	prs_uint32("ptr_trans_addr", ps, depth, &(tp0->ptr_trans_addr));
	prs_uint32("trans_addr_len", ps, depth, &(tp0->trans_addr_len));
	prs_uint32("ptr_addr_name ", ps, depth, &(tp0->ptr_addr_name));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_srv_tprt_info_0(char *desc, SRV_TPRT_INFO_0 * tp0,
				   prs_struct *ps, int depth)
{
	if (tp0 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_tprt_info_0");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries_read", ps, depth, &(tp0->num_entries_read));
	prs_uint32("ptr_tprt_info", ps, depth, &(tp0->ptr_tprt_info));

	if (tp0->ptr_tprt_info != 0)
	{
		uint32 i;
		uint32 num_entries = tp0->num_entries_read;

		prs_uint32("num_entries_read2", ps, depth,
			   &(tp0->num_entries_read2));

		if (ps->io)
		{
			/* reading */
			tp0->info_0 = g_new(TPRT_INFO_0, num_entries);

			tp0->info_0_str = g_new(TPRT_INFO_0_STR, num_entries);

			if (tp0->info_0 == NULL || tp0->info_0_str == NULL)
			{
				free_srv_tprt_info_0(tp0);
				return False;
			}
		}

		for (i = 0; i < num_entries; i++)
		{
			srv_io_tprt_info0("", &(tp0->info_0[i]), ps, depth);
		}

		for (i = 0; i < num_entries; i++)
		{
			srv_io_tprt_info0_str("", &(tp0->info_0_str[i]),
					      &(tp0->info_0[i]), ps, depth);
		}

		prs_align(ps);
	}

	if (!ps->io)
	{
		/* writing */
		free_srv_tprt_info_0(tp0);
	}

	return True;
}

/*******************************************************************
frees a structure.
********************************************************************/
void free_srv_tprt_info_0(SRV_TPRT_INFO_0 * tp0)
{
	if (tp0->info_0 != NULL)
	{
		free(tp0->info_0);
		tp0->info_0 = NULL;
	}
	if (tp0->info_0_str != NULL)
	{
		free(tp0->info_0_str);
		tp0->info_0_str = NULL;
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_srv_tprt_ctr(char *desc, SRV_TPRT_INFO_CTR * ctr,
				prs_struct *ps, int depth)
{
	if (ctr == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_tprt_ctr");
	depth++;

	prs_align(ps);

	prs_uint32("switch_value", ps, depth, &(ctr->switch_value));
	prs_uint32("ptr_tprt_ctr", ps, depth, &(ctr->ptr_tprt_ctr));

	if (ctr->ptr_tprt_ctr != 0)
	{
		switch (ctr->switch_value)
		{
			case 0:
			{
				srv_io_srv_tprt_info_0("", &(ctr->tprt.info0),
						       ps, depth);
				break;
			}
			default:
			{
				DEBUG(5,
				      ("%s no transport info at switch_value %d\n",
				       tab_depth(depth), ctr->switch_value));
				break;
			}
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void free_srv_tprt_ctr(SRV_TPRT_INFO_CTR * ctr)
{
	switch (ctr->switch_value)
	{
		case 0:
		{
			free_srv_tprt_info_0(&(ctr->tprt.info0));
			break;
		}
		default:
		{
			DEBUG(5, ("no transport info at switch_value %d\n",
				  ctr->switch_value));
			break;
		}
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_srv_q_net_tprt_enum(SRV_Q_NET_TPRT_ENUM * q_n,
			      const char *srv_name,
			      uint32 tprt_level, SRV_TPRT_INFO_CTR * ctr,
			      uint32 preferred_len, ENUM_HND * hnd)
{
	if (q_n == NULL || ctr == NULL || hnd == NULL)
		return False;

	q_n->ctr = ctr;

	DEBUG(5, ("make_q_net_tprt_enum\n"));

	make_buf_unistr2(&(q_n->uni_srv_name), &(q_n->ptr_srv_name),
			 srv_name);

	q_n->tprt_level = tprt_level;
	q_n->preferred_len = preferred_len;

	memcpy(&(q_n->enum_hnd), hnd, sizeof(*hnd));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_q_net_tprt_enum(char *desc, SRV_Q_NET_TPRT_ENUM * q_n,
			    prs_struct *ps, int depth)
{
	if (q_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_q_net_tprt_enum");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name ", ps, depth, &(q_n->ptr_srv_name));
	smb_io_unistr2("", &(q_n->uni_srv_name), q_n->ptr_srv_name, ps,
		       depth);
	prs_align(ps);

	prs_uint32("tprt_level", ps, depth, &(q_n->tprt_level));

	if (((int)q_n->tprt_level) != -1)
	{
		srv_io_srv_tprt_ctr("tprt_ctr", q_n->ctr, ps, depth);
	}

	prs_uint32("preferred_len", ps, depth, &(q_n->preferred_len));

	smb_io_enum_hnd("enum_hnd", &(q_n->enum_hnd), ps, depth);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_r_net_tprt_enum(char *desc, SRV_R_NET_TPRT_ENUM * r_n,
			    prs_struct *ps, int depth)
{
	if (r_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_r_net_tprt_enum");
	depth++;

	prs_align(ps);

	prs_uint32("tprt_level", ps, depth, &(r_n->tprt_level));

	if (((int)r_n->tprt_level) != -1)
	{
		srv_io_srv_tprt_ctr("tprt_ctr", r_n->ctr, ps, depth);
	}

	prs_uint32("total_entries", ps, depth, &(r_n->total_entries));
	smb_io_enum_hnd("enum_hnd", &(r_n->enum_hnd), ps, depth);
	prs_uint32("status     ", ps, depth, &(r_n->status));

	return True;
}

/*******************************************************************
 makes a FILE_INFO_3_STR structure
********************************************************************/
BOOL make_srv_file_info3_str(FILE_INFO_3_STR * fi3,
			     const char *path_name, const char *user_name)
{
	if (fi3 == NULL)
		return False;

	DEBUG(5, ("make_srv_file_info3_str\n"));

	make_unistr2(&(fi3->uni_path_name), path_name, strlen(path_name) + 1);
	make_unistr2(&(fi3->uni_user_name), user_name, strlen(user_name) + 1);

	return True;
}

static void srv_free_file_info3_str(FILE_INFO_3_STR * fs3)
{
	safe_free(fs3);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_file_info3_str(char *desc, FILE_INFO_3_STR * sh1,
				  prs_struct *ps, int depth)
{
	if (sh1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_file_info3_str");
	depth++;

	prs_align(ps);

	smb_io_unistr2("path", &(sh1->uni_path_name), True, ps, depth);
	prs_align(ps);
	smb_io_unistr2("user", &(sh1->uni_user_name), True, ps, depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
 makes a FILE_INFO_3 structure
********************************************************************/
BOOL make_srv_file_info3(FILE_INFO_3 * fl3,
			 uint32 id, uint32 perms, uint32 num_locks,
			 const char *path_name, const char *user_name)
{
	if (fl3 == NULL)
		return False;

	DEBUG(5, ("make_srv_file_info3: %s %s\n", path_name, user_name));

	fl3->id = id;
	fl3->perms = perms;
	fl3->num_locks = num_locks;

	fl3->ptr_path_name = path_name != NULL ? 1 : 0;
	fl3->ptr_user_name = user_name != NULL ? 1 : 0;

	return True;
}

static void srv_free_file_info3(FILE_INFO_3 * fi3)
{
	safe_free(fi3);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL srv_io_file_info3(char *desc, FILE_INFO_3 * fl3,
			      prs_struct *ps, int depth)
{
	if (fl3 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_file_info3");
	depth++;

	prs_align(ps);

	prs_uint32("id           ", ps, depth, &(fl3->id));
	prs_uint32("perms        ", ps, depth, &(fl3->perms));
	prs_uint32("num_locks    ", ps, depth, &(fl3->num_locks));
	prs_uint32("ptr_path_name", ps, depth, &(fl3->ptr_path_name));
	prs_uint32("ptr_user_name", ps, depth, &(fl3->ptr_user_name));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static void srv_free_srv_file_info_3(SRV_FILE_INFO_3 * ctr)
{
	void (*fn) (void *) = (void (*)(void *))srv_free_file_info3;
	void (*fnstr) (void *) = (void (*)(void *))srv_free_file_info3_str;

	if (!ctr)
		return;

	free_void_array(ctr->num_entries_read, (void **)ctr->info_3, fn);
	free_void_array(ctr->num_entries_read,
			(void **)ctr->info_3_str, fnstr);

	ctr->num_entries_read = 0;
	ctr->ptr_file_info = 0;
	ctr->num_entries_read2 = 0;
}

static BOOL srv_io_srv_file_info_3(char *desc, SRV_FILE_INFO_3 * fl3,
				   prs_struct *ps, int depth)
{
	if (fl3 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_file_3_fl3");
	depth++;

	if (ps->io)
	{
		ZERO_STRUCTP(fl3);
	}

	prs_align(ps);

	prs_uint32("num_entries_read", ps, depth, &(fl3->num_entries_read));
	prs_uint32("ptr_file_fl3", ps, depth, &(fl3->ptr_file_info));
	if (fl3->ptr_file_info != 0)
	{
		uint32 i;
		uint32 num_entries;

		prs_uint32("num_entries_read2", ps, depth,
			   &(fl3->num_entries_read2));
		num_entries = fl3->num_entries_read2;

		if (ps->io)
		{
			fl3->info_3 = g_new0(FILE_INFO_3 *, num_entries);
			fl3->info_3_str =
				g_new0(FILE_INFO_3_STR *, num_entries);
			if (!fl3->info_3 || !fl3->info_3_str)
			{
				srv_free_srv_file_info_3(fl3);
				return False;
			}
		}

		for (i = 0; i < num_entries; i++)
		{
			if (ps->io)
			{
				fl3->info_3[i] = g_new(FILE_INFO_3, 1);
			}
			if (!srv_io_file_info3("", fl3->info_3[i], ps, depth))
			{
				srv_free_srv_file_info_3(fl3);
				return False;
			}
		}

		for (i = 0; i < num_entries; i++)
		{
			if (ps->io)
			{
				fl3->info_3_str[i] =
					g_new(FILE_INFO_3_STR, 1);
			}
			if (!srv_io_file_info3_str("", fl3->info_3_str[i],
						   ps, depth))
			{
				srv_free_srv_file_info_3(fl3);
				return False;
			}
		}

		prs_align(ps);
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void srv_free_srv_file_ctr(SRV_FILE_INFO_CTR * ctr)
{
	switch (ctr->switch_value)
	{
		case 3:
			srv_free_srv_file_info_3(&(ctr->file.info3));
			break;
		default:
			DEBUG(5, ("no file info at switch_value %d\n",
				  ctr->switch_value));
			break;
	}
}

static BOOL srv_io_srv_file_ctr(char *desc, SRV_FILE_INFO_CTR * ctr,
				prs_struct *ps, int depth)
{
	if (ctr == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_file_ctr");
	depth++;

	prs_align(ps);

	prs_uint32("switch_value", ps, depth, &(ctr->switch_value));
	prs_uint32("ptr_file_ctr", ps, depth, &(ctr->ptr_file_ctr));

	if (ctr->ptr_file_ctr != 0)
	{
		switch (ctr->switch_value)
		{
			case 3:
			{
				srv_io_srv_file_info_3("", &(ctr->file.info3),
						       ps, depth);
				break;
			}
			default:
			{
				DEBUG(5,
				      ("%s no file info at switch_value %d\n",
				       tab_depth(depth), ctr->switch_value));
				break;
			}
		}
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL make_srv_q_net_file_enum(SRV_Q_NET_FILE_ENUM * q_n,
			      const char *srv_name, const char *qual_name,
			      uint32 file_id,
			      uint32 file_level, SRV_FILE_INFO_CTR * ctr,
			      uint32 preferred_len, ENUM_HND * hnd)
{
	if (q_n == NULL || ctr == NULL || hnd == NULL)
		return False;

	q_n->ctr = ctr;

	DEBUG(5, ("make_q_net_file_enum\n"));

	make_buf_unistr2(&(q_n->uni_srv_name), &(q_n->ptr_srv_name),
			 srv_name);
	make_buf_unistr2(&(q_n->uni_qual_name), &(q_n->ptr_qual_name),
			 qual_name);

	q_n->file_id = file_id;
	q_n->file_level = file_level;
	q_n->preferred_len = preferred_len;

	memcpy(&(q_n->enum_hnd), hnd, sizeof(*hnd));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_q_net_file_enum(char *desc, SRV_Q_NET_FILE_ENUM * q_n,
			    prs_struct *ps, int depth)
{
	if (q_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_q_net_file_enum");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_n->ptr_srv_name));
	smb_io_unistr2("", &(q_n->uni_srv_name), True, ps, depth);
	prs_align(ps);

	prs_uint32("ptr_qual_name", ps, depth, &(q_n->ptr_qual_name));
	smb_io_unistr2("", &(q_n->uni_qual_name), q_n->ptr_qual_name, ps,
		       depth);
	prs_align(ps);

	prs_uint32("file_id   ", ps, depth, &(q_n->file_id));
	prs_uint32("file_level", ps, depth, &(q_n->file_level));

	if (((int)q_n->file_level) != -1)
	{
		srv_io_srv_file_ctr("file_ctr", q_n->ctr, ps, depth);
	}

	prs_uint32("preferred_len", ps, depth, &(q_n->preferred_len));

	smb_io_enum_hnd("enum_hnd", &(q_n->enum_hnd), ps, depth);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_r_net_file_enum(char *desc, SRV_R_NET_FILE_ENUM * r_n,
			    prs_struct *ps, int depth)
{
	if (r_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_r_net_file_enum");
	depth++;

	prs_align(ps);

	prs_uint32("file_level", ps, depth, &(r_n->file_level));

	if (r_n->file_level != 0)
	{
		srv_io_srv_file_ctr("file_ctr", r_n->ctr, ps, depth);
	}

	prs_uint32("total_entries", ps, depth, &(r_n->total_entries));
	smb_io_enum_hnd("enum_hnd", &(r_n->enum_hnd), ps, depth);
	prs_uint32("status     ", ps, depth, &(r_n->status));

	return True;
}

/*******************************************************************
 reads or writes a SRV_INFO_101 structure.
 ********************************************************************/
static BOOL srv_io_info_101(char *desc, SRV_INFO_101 * sv101,
			    prs_struct *ps, int depth)
{
	if (sv101 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_info_101");
	depth++;

	prs_align(ps);

	prs_uint32("platform_id ", ps, depth, &(sv101->platform_id));
	prs_uint32("ptr_name    ", ps, depth, &(sv101->ptr_name));
	prs_uint32("ver_major   ", ps, depth, &(sv101->ver_major));
	prs_uint32("ver_minor   ", ps, depth, &(sv101->ver_minor));
	prs_uint32("srv_type    ", ps, depth, &(sv101->srv_type));
	prs_uint32("ptr_comment ", ps, depth, &(sv101->ptr_comment));

	prs_align(ps);

	smb_io_unistr2("uni_name    ", &(sv101->uni_name), True, ps, depth);
	prs_align(ps);
	smb_io_unistr2("uni_comment ", &(sv101->uni_comment), True, ps,
		       depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
 reads or writes a SRV_INFO_102 structure.
 ********************************************************************/
static BOOL srv_io_info_102(char *desc, SRV_INFO_102 * sv102,
			    prs_struct *ps, int depth)
{
	if (sv102 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_info102");
	depth++;

	prs_align(ps);

	prs_uint32("platform_id ", ps, depth, &(sv102->platform_id));
	prs_uint32("ptr_name    ", ps, depth, &(sv102->ptr_name));
	prs_uint32("ver_major   ", ps, depth, &(sv102->ver_major));
	prs_uint32("ver_minor   ", ps, depth, &(sv102->ver_minor));
	prs_uint32("srv_type    ", ps, depth, &(sv102->srv_type));
	prs_uint32("ptr_comment ", ps, depth, &(sv102->ptr_comment));

	/* same as 101 up to here */

	prs_uint32("users       ", ps, depth, &(sv102->users));
	prs_uint32("disc        ", ps, depth, &(sv102->disc));
	prs_uint32("hidden      ", ps, depth, &(sv102->hidden));
	prs_uint32("announce    ", ps, depth, &(sv102->announce));
	prs_uint32("ann_delta   ", ps, depth, &(sv102->ann_delta));
	prs_uint32("licenses    ", ps, depth, &(sv102->licenses));
	prs_uint32("ptr_usr_path", ps, depth, &(sv102->ptr_usr_path));

	smb_io_unistr2("uni_name    ", &(sv102->uni_name), True, ps, depth);
	prs_align(ps);
	smb_io_unistr2("uni_comment ", &(sv102->uni_comment), True, ps,
		       depth);
	prs_align(ps);
	smb_io_unistr2("uni_usr_path", &(sv102->uni_usr_path), True, ps,
		       depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
 reads or writes a SRV_INFO_102 structure.
 ********************************************************************/
static BOOL srv_io_info_ctr(char *desc, SRV_INFO_CTR * ctr,
			    prs_struct *ps, int depth)
{
	if (ctr == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_info_ctr");
	depth++;

	prs_align(ps);

	prs_uint32("switch_value", ps, depth, &(ctr->switch_value));
	prs_uint32("ptr_srv_ctr ", ps, depth, &(ctr->ptr_srv_ctr));

	if (ctr->ptr_srv_ctr != 0 && ctr->switch_value != 0 && ctr != NULL)
	{
		switch (ctr->switch_value)
		{
			case 101:
			{
				srv_io_info_101("sv101", &(ctr->srv.sv101),
						ps, depth);
				break;
			}
			case 102:
			{
				srv_io_info_102("sv102", &(ctr->srv.sv102),
						ps, depth);
				break;
			}
			default:
			{
				DEBUG(5,
				      ("%s no server info at switch_value %d\n",
				       tab_depth(depth), ctr->switch_value));
				break;
			}
		}
		prs_align(ps);
	}

	return True;
}

/*******************************************************************
 makes a SRV_Q_NET_SRV_GET_INFO structure.
 ********************************************************************/
BOOL make_srv_q_net_srv_get_info(SRV_Q_NET_SRV_GET_INFO * srv,
				 char *server_name, uint32 switch_value)
{
	if (srv == NULL)
		return False;

	DEBUG(5, ("make_srv_q_net_srv_get_info\n"));

	make_buf_unistr2(&(srv->uni_srv_name), &(srv->ptr_srv_name),
			 server_name);

	srv->switch_value = switch_value;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL srv_io_q_net_srv_get_info(char *desc, SRV_Q_NET_SRV_GET_INFO * q_n,
			       prs_struct *ps, int depth)
{
	if (q_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_q_net_srv_get_info");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name  ", ps, depth, &(q_n->ptr_srv_name));
	smb_io_unistr2("", &(q_n->uni_srv_name), True, ps, depth);
	prs_align(ps);

	prs_uint32("switch_value  ", ps, depth, &(q_n->switch_value));

	return True;
}

/*******************************************************************
 makes a SRV_R_NET_SRV_GET_INFO structure.
 ********************************************************************/
BOOL make_srv_r_net_srv_get_info(SRV_R_NET_SRV_GET_INFO * srv,
				 uint32 switch_value, SRV_INFO_CTR * ctr,
				 uint32 status)
{
	if (srv == NULL)
		return False;

	DEBUG(5, ("make_srv_r_net_srv_get_info\n"));

	srv->ctr = ctr;

	if (status == 0x0)
	{
		srv->ctr->switch_value = switch_value;
		srv->ctr->ptr_srv_ctr = 1;
	}
	else
	{
		srv->ctr->switch_value = 0;
		srv->ctr->ptr_srv_ctr = 0;
	}

	srv->status = status;

	return True;
}

/*******************************************************************
 reads or writes a structure.
 ********************************************************************/
BOOL srv_io_r_net_srv_get_info(char *desc, SRV_R_NET_SRV_GET_INFO * r_n,
			       prs_struct *ps, int depth)
{
	if (r_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_r_net_srv_get_info");
	depth++;

	prs_align(ps);

	srv_io_info_ctr("ctr", r_n->ctr, ps, depth);

	prs_uint32("status      ", ps, depth, &(r_n->status));

	return True;
}

/*******************************************************************
 makes a SRV_Q_NET_REMOTE_TOD structure.
 ********************************************************************/
BOOL make_srv_q_net_remote_tod(SRV_Q_NET_REMOTE_TOD * q_t, char *server_name)
{
	if (q_t == NULL)
		return False;

	DEBUG(5, ("make_srv_q_net_remote_tod\n"));

	make_buf_unistr2(&(q_t->uni_srv_name), &(q_t->ptr_srv_name),
			 server_name);

	return True;
}

/*******************************************************************
 reads or writes a structure.
 ********************************************************************/
BOOL srv_io_q_net_remote_tod(char *desc, SRV_Q_NET_REMOTE_TOD * q_n,
			     prs_struct *ps, int depth)
{
	if (q_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_q_net_remote_tod");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name  ", ps, depth, &(q_n->ptr_srv_name));
	smb_io_unistr2("", &(q_n->uni_srv_name), True, ps, depth);
	prs_align(ps);

	return True;
}

/*******************************************************************
 reads or writes a TIME_OF_DAY_INFO structure.
 ********************************************************************/
static BOOL srv_io_time_of_day_info(char *desc, TIME_OF_DAY_INFO * tod,
				    prs_struct *ps, int depth)
{
	if (tod == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_time_of_day_info");
	depth++;

	prs_align(ps);

	prs_uint32("elapsedt   ", ps, depth, &(tod->elapsedt));
	prs_uint32("msecs      ", ps, depth, &(tod->msecs));
	prs_uint32("hours      ", ps, depth, &(tod->hours));
	prs_uint32("mins       ", ps, depth, &(tod->mins));
	prs_uint32("secs       ", ps, depth, &(tod->secs));
	prs_uint32("hunds      ", ps, depth, &(tod->hunds));
	prs_uint32("timezone   ", ps, depth, &(tod->zone));
	prs_uint32("tintervals ", ps, depth, &(tod->tintervals));
	prs_uint32("day        ", ps, depth, &(tod->day));
	prs_uint32("month      ", ps, depth, &(tod->month));
	prs_uint32("year       ", ps, depth, &(tod->year));
	prs_uint32("weekday    ", ps, depth, &(tod->weekday));

	return True;
}

/*******************************************************************
 makes a TIME_OF_DAY_INFO structure.
 ********************************************************************/
BOOL make_time_of_day_info(TIME_OF_DAY_INFO * tod, uint32 elapsedt,
			   uint32 msecs, uint32 hours, uint32 mins,
			   uint32 secs, uint32 hunds, uint32 zone,
			   uint32 tintervals, uint32 day, uint32 month,
			   uint32 year, uint32 weekday)
{
	if (tod == NULL)
		return False;

	DEBUG(5, ("make_time_of_day_info\n"));

	tod->elapsedt = elapsedt;
	tod->msecs = msecs;
	tod->hours = hours;
	tod->mins = mins;
	tod->secs = secs;
	tod->hunds = hunds;
	tod->zone = zone;
	tod->tintervals = tintervals;
	tod->day = day;
	tod->month = month;
	tod->year = year;
	tod->weekday = weekday;

	return True;
}


/*******************************************************************
 reads or writes a structure.
 ********************************************************************/
BOOL srv_io_r_net_remote_tod(char *desc, SRV_R_NET_REMOTE_TOD * r_n,
			     prs_struct *ps, int depth)
{
	if (r_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_r_net_remote_tod");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_tod ", ps, depth, &(r_n->ptr_srv_tod));

	srv_io_time_of_day_info("tod", r_n->tod, ps, depth);

	prs_uint32("status      ", ps, depth, &(r_n->status));

	return True;
}
