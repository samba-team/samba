/* 
   Unix SMB/CIFS implementation.
   client connect/disconnect routines
   Copyright (C) Gerald (Jerry) Carter            2004
      
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

#define NO_SYSLOG

#include "includes.h"


/********************************************************************
 split a dfs path into the server and share name components
********************************************************************/

static void split_dfs_path( const char *nodepath, fstring server, fstring share )
{
	char *p;
	pstring path;

	pstrcpy( path, nodepath );

	if ( path[0] != '\\' )
		return;

	p = strrchr_m( path, '\\' );

	if ( !p )
		return;

	*p = '\0';
	p++;

	fstrcpy( share, p );
	fstrcpy( server, &path[1] );
}

/****************************************************************************
 return the original path truncated at the first wildcard character
 (also strips trailing \'s).  Trust the caller to provide a NULL 
 terminated string
****************************************************************************/

static void clean_path( pstring clean, const char *path )
{
	int len;
	char *p;
	pstring newpath;
		
	pstrcpy( newpath, path );
	p = newpath;
	
	while ( p ) {
		/* first check for '*' */
		
		p = strrchr_m( newpath, '*' );
		if ( p ) {
			*p = '\0';
			p = newpath;
			continue;
		}
	
		/* first check for '?' */
		
		p = strrchr_m( newpath, '?' );
		if ( p ) {
			*p = '\0';
			p = newpath;
		}
	}
	
	/* strip a trailing backslash */
	
	len = strlen( newpath );
	if ( newpath[len-1] == '\\' )
		newpath[len-1] = '\0';
		
	pstrcpy( clean, newpath );
}

/****************************************************************************
****************************************************************************/

static BOOL make_full_path( pstring path, const char *server, const char *share,
                            const char *dir )
{
	pstring servicename;
	char *sharename;
	const char *directory;

	
	/* make a copy so we don't modify the global string 'service' */
	
	pstrcpy(servicename, share);
	sharename = servicename;
	
	if (*sharename == '\\') {
	
		server = sharename+2;
		sharename = strchr_m(server,'\\');
		
		if (!sharename) 
			return False;
			
		*sharename = 0;
		sharename++;
	}

	directory = dir;
	if ( *directory == '\\' )
		directory++;
	
	pstr_sprintf( path, "\\%s\\%s\\%s", server, sharename, directory );

	return True;
}

/********************************************************************
 check for dfs referral
********************************************************************/

static BOOL cli_dfs_check_error( struct cli_state *cli )
{
	uint32 flgs2 = SVAL(cli->inbuf,smb_flg2);

	/* only deal with DS when we negotiated NT_STATUS codes and UNICODE */

	if ( !( (flgs2&FLAGS2_32_BIT_ERROR_CODES) && (flgs2&FLAGS2_UNICODE_STRINGS) ) )
		return False;

	if ( NT_STATUS_EQUAL( NT_STATUS_PATH_NOT_COVERED, NT_STATUS(IVAL(cli->inbuf,smb_rcls)) ) )
		return True;

	return False;
}

/********************************************************************
 get the dfs referral link
********************************************************************/

BOOL cli_dfs_get_referral( struct cli_state *cli, const char *path, 
                           CLIENT_DFS_REFERRAL**refs, size_t *num_refs,
			   uint16 *consumed)
{
	unsigned int data_len = 0;
	unsigned int param_len = 0;
	uint16 setup = TRANSACT2_GET_DFS_REFERRAL;
	char param[sizeof(pstring)+2];
	pstring data;
	char *rparam=NULL, *rdata=NULL;
	char *p;
	size_t pathlen = 2*(strlen(path)+1);
	uint16 num_referrals;
	CLIENT_DFS_REFERRAL *referrals;
	
	memset(param, 0, sizeof(param));
	SSVAL(param, 0, 0x03);	/* max referral level */
	p = &param[2];

	p += clistr_push(cli, p, path, MIN(pathlen, sizeof(param)-2), STR_TERMINATE);
	param_len = PTR_DIFF(p, param);

	if (!cli_send_trans(cli, SMBtrans2,
		NULL,                        /* name */
		-1, 0,                          /* fid, flags */
		&setup, 1, 0,                   /* setup, length, max */
		param, param_len, 2,            /* param, length, max */
		(char *)&data,  data_len, cli->max_xmit /* data, length, max */
		)) {
			return False;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
		&rparam, &param_len,
		&rdata, &data_len)) {
			return False;
	}
	
	*consumed     = SVAL( rdata, 0 );
	num_referrals = SVAL( rdata, 2 );
	
	if ( num_referrals != 0 ) {
		uint16 ref_version;
		uint16 ref_size;
		int i;
		uint16 node_offset;
		
		
		referrals = SMB_XMALLOC_ARRAY( CLIENT_DFS_REFERRAL, num_referrals );
	
		/* start at the referrals array */
	
		p = rdata+8;
		for ( i=0; i<num_referrals; i++ ) {
			ref_version = SVAL( p, 0 );
			ref_size    = SVAL( p, 2 );
			node_offset = SVAL( p, 16 );
			
			if ( ref_version != 3 ) {
				p += ref_size;
				continue;
			}
			
			referrals[i].proximity = SVAL( p, 8 );
			referrals[i].ttl       = SVAL( p, 10 );

			clistr_pull( cli, referrals[i].dfspath, p+node_offset, 
				sizeof(referrals[i].dfspath), -1, STR_TERMINATE|STR_UNICODE );

			p += ref_size;
		}
	
	}
	
	*num_refs = num_referrals;
	*refs = referrals;

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	return True;
}

/********************************************************************
********************************************************************/

BOOL cli_resolve_path( struct cli_state *rootcli, const char *path,
                       struct cli_state **targetcli, pstring targetpath )
{
	CLIENT_DFS_REFERRAL *refs = NULL;
	size_t num_refs;
	uint16 consumed;
	struct cli_state *cli_ipc;
	pstring fullpath, cleanpath;
	int pathlen;
	fstring server, share;
	struct cli_state *newcli;
	pstring newpath;
	
	SMB_STRUCT_STAT sbuf;
	uint32 attributes;
	
	*targetcli = NULL;
	
	if ( !rootcli || !path || !targetcli )
		return False;
		
	/* send a trans2_query_path_info to check for a referral */
	
	clean_path( cleanpath, 	path );
	make_full_path( fullpath, rootcli->desthost, rootcli->share, cleanpath );

	/* don't bother continuing if this is not a dfs root */
	
	if ( !rootcli->dfsroot || cli_qpathinfo_basic( rootcli, cleanpath, &sbuf, &attributes ) ) {
		*targetcli = rootcli;
		pstrcpy( targetpath, path );
		return True;
	}

	/* we got an error, check for DFS referral */
			
	if ( !cli_dfs_check_error(rootcli) )
		return False;

	/* check for the referral */

	if ( !(cli_ipc = cli_cm_open( rootcli->desthost, "IPC$", False )) )
		return False;
	
	if ( !cli_dfs_get_referral(cli_ipc, fullpath, &refs, &num_refs, &consumed) 
		|| !num_refs )
	{
		return False;
	}
	
	/* just store the first referral for now
	   Make sure to recreate the original string including any wildcards */
	
	make_full_path( fullpath, rootcli->desthost, rootcli->share, path );
	pathlen = strlen( fullpath )*2;
	consumed = MIN(pathlen, consumed );
	pstrcpy( targetpath, &fullpath[consumed/2] );

	split_dfs_path( refs[0].dfspath, server, share );
	SAFE_FREE( refs );
	
	/* open the connection to the target path */
	
	if ( (*targetcli = cli_cm_open(server, share, False)) == NULL ) {
		d_printf("Unable to follow dfs referral [//%s/%s]\n",
			server, share );
			
		return False;
	}

	/* check for another dfs refeerrali, note that we are not 
	   checking for loops here */

	if ( !strequal( targetpath, "\\" ) ) {
		if ( cli_resolve_path( *targetcli, targetpath, &newcli, newpath ) ) {
			*targetcli = newcli;
			pstrcpy( targetpath, newpath );
		}
	}
	
	return True;
}
