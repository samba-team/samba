/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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



#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "rpc_parse.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern FILE* out_hnd;


/****************************************************************************
server get info query
****************************************************************************/
BOOL net_srv_get_info(struct client_info *info,
		uint32 info_level,
		SRV_INFO_CTR *ctr)
{
	fstring dest_srv;

	BOOL res = True;

	fstrcpy(dest_srv, "\\\\");
	fstrcat(dest_srv, info->dest_host);
	strupper(dest_srv);

	DEBUG(4,("net_srv_get_info: server:%s info level: %d\n",
				dest_srv, (int)info_level));

	/* send info level: receive requested info.  hopefully. */
	res = res ? srv_net_srv_get_info(dest_srv, info_level, ctr) : False;

	return res;
}

/****************************************************************************
server get info query
****************************************************************************/
void cmd_srv_query_info(struct client_info *info, int argc, char *argv[])
{
	uint32 info_level = 101;
	SRV_INFO_CTR ctr;

	bzero(&ctr, sizeof(ctr));

	if (argc > 1)
	{
		info_level = (uint32)strtol(argv[1], (char**)NULL, 10);
	}

	if (net_srv_get_info(info, info_level, &ctr))
	{
		DEBUG(5,("cmd_srv_query_info: query succeeded\n"));

		display_srv_info_ctr(out_hnd, ACTION_HEADER   , &ctr);
		display_srv_info_ctr(out_hnd, ACTION_ENUMERATE, &ctr);
		display_srv_info_ctr(out_hnd, ACTION_FOOTER   , &ctr);
	}
	else
	{
		DEBUG(5,("cmd_srv_query_info: query failed\n"));
	}
}

/****************************************************************************
server enum transports
****************************************************************************/
BOOL msrpc_srv_enum_tprt( const char* dest_srv,
				uint32 info_level,
				SRV_TPRT_INFO_CTR *ctr,
				TPRT_INFO_FN(tprt_fn))
{
	BOOL res = True;
	BOOL res1 = True;

	ENUM_HND hnd;

	hnd.ptr_hnd = 1;
	hnd.handle = 0;

	/* enumerate transports on server */
	res1 = res ? srv_net_srv_tprt_enum(dest_srv, 
	            info_level, ctr, 0xffffffff, &hnd) : False;

	tprt_fn(ctr);

	free_srv_tprt_ctr(ctr);

	return res1;
}

static void srv_display_tprt_ctr(const SRV_TPRT_INFO_CTR *ctr)
{
	display_srv_tprt_info_ctr(out_hnd, ACTION_HEADER   , ctr);
	display_srv_tprt_info_ctr(out_hnd, ACTION_ENUMERATE, ctr);
	display_srv_tprt_info_ctr(out_hnd, ACTION_FOOTER   , ctr);
}

/****************************************************************************
server enum transports
****************************************************************************/
void cmd_srv_enum_tprt(struct client_info *info, int argc, char *argv[])
{
	fstring dest_srv;
	SRV_TPRT_INFO_CTR ctr;
	uint32 info_level = 0;

	bzero(&ctr, sizeof(ctr));

	fstrcpy(dest_srv, "\\\\");
	fstrcat(dest_srv, info->dest_host);
	strupper(dest_srv);

	if (argc > 1)
	{
		info_level = (uint32)strtol(argv[1], (char**)NULL, 10);
	}

	DEBUG(4,("cmd_srv_enum_tprt: server:%s info level: %d\n",
				dest_srv, (int)info_level));

	/* enumerate transports on server */
	msrpc_srv_enum_tprt(dest_srv, 
	            info_level, &ctr, 
	            srv_display_tprt_ctr);
}

/****************************************************************************
server enum connections
****************************************************************************/
void cmd_srv_enum_conn(struct client_info *info, int argc, char *argv[])
{
	fstring dest_srv;
	fstring qual_srv;
	SRV_CONN_INFO_CTR ctr;
	ENUM_HND hnd;
	uint32 info_level = 0;

	BOOL res = True;

	bzero(&ctr, sizeof(ctr));

	fstrcpy(qual_srv, "\\\\");
	fstrcat(qual_srv, info->myhostname);
	strupper(qual_srv);

	fstrcpy(dest_srv, "\\\\");
	fstrcat(dest_srv, info->dest_host);
	strupper(dest_srv);

	if (argc > 1)
	{
		info_level = (uint32)strtol(argv[1], (char**)NULL, 10);
	}

	DEBUG(4,("cmd_srv_enum_conn: server:%s info level: %d\n",
				dest_srv, (int)info_level));

	hnd.ptr_hnd = 1;
	hnd.handle = 0;

	/* enumerate connections on server */
	res = res ? srv_net_srv_conn_enum(dest_srv, qual_srv,
	            info_level, &ctr, 0xffffffff, &hnd) : False;

	if (res)
	{
		display_srv_conn_info_ctr(out_hnd, ACTION_HEADER   , &ctr);
		display_srv_conn_info_ctr(out_hnd, ACTION_ENUMERATE, &ctr);
		display_srv_conn_info_ctr(out_hnd, ACTION_FOOTER   , &ctr);
	}

	if (res)
	{
		DEBUG(5,("cmd_srv_enum_conn: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_srv_enum_conn: query failed\n"));
	}
}

/****************************************************************************
server enum shares
****************************************************************************/
void cmd_srv_enum_shares(struct client_info *info, int argc, char *argv[])
{
	fstring dest_srv;
	SRV_SHARE_INFO_CTR ctr;
	ENUM_HND hnd;
	uint32 info_level = 1;

	BOOL res = True;

	bzero(&ctr, sizeof(ctr));

	fstrcpy(dest_srv, "\\\\");
	fstrcat(dest_srv, info->dest_host);
	strupper(dest_srv);

	if (argc > 1)
	{
		info_level = (uint32)strtol(argv[1], (char**)NULL, 10);
	}

	DEBUG(4,("cmd_srv_enum_shares: server:%s info level: %d\n",
				dest_srv, (int)info_level));

	hnd.ptr_hnd = 0;
	hnd.handle = 0;

	/* enumerate shares_files on server */
	res = res ? srv_net_srv_share_enum(dest_srv, 
	            info_level, &ctr, 0xffffffff, &hnd) : False;

	if (res)
	{
		display_srv_share_info_ctr(out_hnd, ACTION_HEADER   , &ctr);
		display_srv_share_info_ctr(out_hnd, ACTION_ENUMERATE, &ctr);
		display_srv_share_info_ctr(out_hnd, ACTION_FOOTER   , &ctr);
	}

	srv_free_srv_share_ctr(&ctr);

	if (res)
	{
		DEBUG(5,("cmd_srv_enum_shares: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_srv_enum_shares: query failed\n"));
	}
}

/****************************************************************************
server enum sessions
****************************************************************************/
void cmd_srv_enum_sess(struct client_info *info, int argc, char *argv[])
{
	fstring dest_srv;
	SRV_SESS_INFO_CTR ctr;
	ENUM_HND hnd;
	uint32 info_level = 0;

	BOOL res = True;

	bzero(&ctr, sizeof(ctr));

	fstrcpy(dest_srv, "\\\\");
	fstrcat(dest_srv, info->dest_host);
	strupper(dest_srv);

	if (argc > 1)
	{
		info_level = (uint32)strtol(argv[1], (char**)NULL, 10);
	}

	DEBUG(4,("cmd_srv_enum_sess: server:%s info level: %d\n",
				dest_srv, (int)info_level));

	hnd.ptr_hnd = 1;
	hnd.handle = 0;

	/* enumerate sessions on server */
	res = res ? srv_net_srv_sess_enum(dest_srv, NULL, NULL,
	                         info_level, &ctr, 0x1000, &hnd) : False;

	if (res)
	{
		display_srv_sess_info_ctr(out_hnd, ACTION_HEADER   , &ctr);
		display_srv_sess_info_ctr(out_hnd, ACTION_ENUMERATE, &ctr);
		display_srv_sess_info_ctr(out_hnd, ACTION_FOOTER   , &ctr);
	}

	if (res)
	{
		DEBUG(5,("cmd_srv_enum_sess: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_srv_enum_sess: query failed\n"));
	}
}

/****************************************************************************
server enum files
****************************************************************************/
void cmd_srv_enum_files(struct client_info *info, int argc, char *argv[])
{
	fstring dest_srv;
	SRV_FILE_INFO_CTR ctr;
	ENUM_HND hnd;
	uint32 info_level = 3;

	BOOL res = True;

	bzero(&ctr, sizeof(ctr));

	fstrcpy(dest_srv, "\\\\");
	fstrcat(dest_srv, info->dest_host);
	strupper(dest_srv);

	if (argc > 1)
	{
		info_level = (uint32)strtol(argv[1], (char**)NULL, 10);
	}

	DEBUG(4,("cmd_srv_enum_files: server:%s info level: %d\n",
				dest_srv, (int)info_level));

	hnd.ptr_hnd = 1;
	hnd.handle = 0;

	/* enumerate files on server */
	res = res ? srv_net_srv_file_enum(dest_srv, NULL, 0,
	                info_level, &ctr, 0x1000, &hnd) : False;

	if (res)
	{
		display_srv_file_info_ctr(out_hnd, ACTION_HEADER   , &ctr);
		display_srv_file_info_ctr(out_hnd, ACTION_ENUMERATE, &ctr);
		display_srv_file_info_ctr(out_hnd, ACTION_FOOTER   , &ctr);
	}

	if (res)
	{
		DEBUG(5,("cmd_srv_enum_files: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_srv_enum_files: query failed\n"));
	}
}

/****************************************************************************
display remote time
****************************************************************************/
void cmd_time(struct client_info *info, int argc, char *argv[])
{
	fstring dest_srv;
	TIME_OF_DAY_INFO tod;
	BOOL res = True;

	fstrcpy(dest_srv, "\\\\");
	fstrcat(dest_srv, info->dest_host);
	strupper(dest_srv);

	DEBUG(4,("cmd_time: server:%s\n", dest_srv));

	/* enumerate files on server */
	res = res ? srv_net_remote_tod(dest_srv, &tod) : False;

	if (res)
	{
		fprintf(out_hnd, "\tRemote Time:\t%s\n\n",
			http_timestring(tod.elapsedt));
	}

	if (res)
	{
		DEBUG(5,("cmd_srv_enum_files: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_srv_enum_files: query failed\n"));
	}
}
