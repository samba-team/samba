/* 
   Unix SMB/CIFS implementation.
   client connect/disconnect routines
   Copyright (C) Gerald (Jerry) Carter
   
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
 check for dfs referral
********************************************************************/

BOOL check_for_dfs_referral( struct cli_state *cli )
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
 split a dfs path into the server and share name components
********************************************************************/

void split_dfs_path( const char *nodepath, fstring server, fstring share )
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

/********************************************************************
 get the dfs referral link
********************************************************************/

BOOL cli_dfs_get_referral( struct cli_state *cli, const char *path, 
                           struct referral **refs, size_t *num_refs)
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
	struct referral *referrals;
	
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
	
	num_referrals = SVAL( rdata, 2 );
	
	if ( num_referrals != 0 ) {
		uint16 ref_version;
		uint16 ref_size;
		int i;
		uint16 node_offset;
		
		
		referrals = SMB_XMALLOC_ARRAY( struct referral, num_referrals );
	
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
			
			referrals[0].proximity = SVAL( p, 8 );
			referrals[0].ttl       = SVAL( p, 10 );

			clistr_pull( cli, referrals[0].alternate_path, p+node_offset, 
				sizeof(referrals[0].alternate_path), -1, STR_TERMINATE|STR_UNICODE );

			p += ref_size;
		}
	
	}
	
	*num_refs = num_referrals;
	*refs = referrals;

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	return True;
}

