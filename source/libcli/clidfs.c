/* 
   Unix SMB/CIFS implementation.
   Dfs routines
   Copyright (C) James Myers 2003
   
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

BOOL smbcli_client_initialize(struct smbcli_client* context,
			   const char* sockops,
			   char* username, char* password, char* workgroup,
			   int flags)
{
	int i;
	for (i=0; i < DFS_MAX_CLUSTER_SIZE ; i++) {
		context->cli[i] = smbcli_raw_initialise();
	}
	context->sockops = sockops;
	context->username = username;
	context->password = password;
	context->workgroup = workgroup;
	context->connection_flags = flags;
	if (flags & SMBCLI_FULL_CONNECTION_USE_DFS)
		context->use_dfs = True;
	context->number_members = DFS_MAX_CLUSTER_SIZE;	
	return True;
}

/****************************************************************************
 Interpret a Dfs referral structure.
 The length of the structure is returned
 The structure of a Dfs referral depends on the info level.
****************************************************************************/

static int interpret_referral(struct smbcli_state *cli,
				   int level,char *p,referral_info *rinfo)
{
	char* q;
	int version, size;

	version = SVAL(p,0);
	size = SVAL(p,2);
	rinfo->server_type = SVAL(p,4);
	rinfo->referral_flags = SVAL(p,6);
	rinfo->proximity = SVAL(p,8);
	rinfo->ttl = SVAL(p,10);
	rinfo->pathOffset = SVAL(p,12);
	rinfo->altPathOffset = SVAL(p,14);
	rinfo->nodeOffset = SVAL(p,16);
	DEBUG(3,("referral version=%d, size=%d, server_type=%d, flags=0x%x, proximity=%d, ttl=%d, pathOffset=%d, altPathOffset=%d, nodeOffset=%d\n",
		version, size, rinfo->server_type, rinfo->referral_flags,
		rinfo->proximity, rinfo->ttl, rinfo->pathOffset,
		rinfo->altPathOffset, rinfo->nodeOffset));

	q = (char*)(p + (rinfo->pathOffset));
	//printf("p=%p, q=%p, offset=%d\n", p, q, rinfo->pathOffset);
	//printf("hex=0x%x, string=%s\n", q, q);
	clistr_pull(cli, rinfo->path, q,
		    sizeof(rinfo->path),
		    -1, STR_TERMINATE);
	DEBUG(4,("referral path=%s\n", rinfo->path));
	q = (char*)(p + (rinfo->altPathOffset)/sizeof(char));
	if (rinfo->altPathOffset > 0)
		clistr_pull(cli, rinfo->altPath, q,
		    sizeof(rinfo->altPath),
		    -1, STR_TERMINATE);
	DEBUG(4,("referral alt path=%s\n", rinfo->altPath));
	q = (char*)(p + (rinfo->nodeOffset)/sizeof(char));
	if (rinfo->nodeOffset > 0)
		clistr_pull(cli, rinfo->node, q,
		    sizeof(rinfo->node),
		    -1, STR_TERMINATE);
	DEBUG(4,("referral node=%s\n", rinfo->node));
	fstrcpy(rinfo->host, &rinfo->node[1]);
	p = strchr_m(&rinfo->host[1],'\\');
	if (!p) {
		printf("invalid referral node %s\n", rinfo->node);
		return -1;
	}
	*p = 0;
	rinfo->share = talloc_strdup(cli->mem_ctx, p+1);
	DEBUG(3,("referral host=%s share=%s\n",
		rinfo->host, rinfo->share));
	return size;
}

#if 0
int smbcli_select_dfs_referral(struct smbcli_state *cli, dfs_info* dinfo)
{
	return (int)sys_random()%dinfo->number_referrals;
}

int smbcli_get_dfs_referral(struct smbcli_state *cli,const char *Fname, dfs_info* dinfo)
{
	struct smb_trans2 parms;
	int info_level;
	char *p;
	pstring fname;
	int i;
	char *rparam=NULL, *rdata=NULL;
	int param_len, data_len;	
	uint16_t setup;
	pstring param;
	DATA_BLOB trans_param, trans_data;

	/* NT uses 260, OS/2 uses 2. Both accept 1. */
	info_level = (cli->capabilities&CAP_NT_SMBS)?260:1;

	pstrcpy(fname,Fname);

	setup = TRANSACT2_GET_DFS_REFERRAL ;
	SSVAL(param,0,SMBCLI_DFS_MAX_REFERRAL_LEVEL); /* attribute */
	p = param+2;
	p += clistr_push(cli, param+2, fname, -1, 
			 STR_TERMINATE);

	param_len = PTR_DIFF(p, param);
	DEBUG(3,("smbcli_get_dfs_referral: sending request\n"));
	
	trans_param.length = param_len;
	trans_param.data = param;
	trans_data.length = 0;
	trans_data.data = NULL;

	if (!smbcli_send_trans(cli, SMBtrans2, 
			    NULL,                   /* Name */
			    -1, 0,                  /* fid, flags */
			    &setup, 1, 0,           /* setup, length, max */
			    &trans_param, 10,   /* param, length, max */
			    &trans_data, 
			    cli->max_xmit /* data, length, max */
			    )) {
		return 0;
	}

	if (!smbcli_receive_trans(cli, SMBtrans2, 
			       &rparam, &param_len,
			       &rdata, &data_len) &&
                   smbcli_is_dos_error(cli)) {
           return 0;
	}
	//printf("smbcli_get_dfs_referral: received response, rdata=%p, rparam=%p\n",
	//	rdata, rparam);

    if (smbcli_is_error(cli) || !rdata) 
		return 0;

	/* parse out some important return info */
	//printf("smbcli_get_dfs_referral: valid response\n");
	p = rdata;
	dinfo->path_consumed = SVAL(p,0);
	dinfo->number_referrals = SVAL(p,2);
	dinfo->referral_flags = SVAL(p,4);
	DEBUG(3,("smbcli_get_dfs_referral: path_consumed=%d, # referrals=%d, flags=0x%x\n",
		dinfo->path_consumed, dinfo->number_referrals,
		dinfo->referral_flags));

	/* point to the referral bytes */
	p+=8;
	for (i=0; i < dinfo->number_referrals; i++) {
		p += interpret_referral(cli,info_level,p,&dinfo->referrals[i]);
	}

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	DEBUG(3,("received %d Dfs referrals\n",
			 dinfo->number_referrals));
			 
	dinfo->selected_referral = smbcli_select_dfs_referral(cli, dinfo);
	DEBUG(3, ("selected Dfs referral %d %s\n",
		dinfo->selected_referral, dinfo->referrals[dinfo->selected_referral].node));

	return(dinfo->number_referrals);
}
#endif

/* check if the server produced Dfs redirect */
BOOL smbcli_check_dfs_redirect(struct smbcli_state* c, char* fname,
		dfs_info* dinfo)
{
		//printf("check_dfs_redirect: error %s\n",
		//	smbcli_errstr(c));
        if (smbcli_is_dos_error(c)) {
        		printf("got dos error\n");
                return False;

        } else {
                NTSTATUS status;

                /* Check NT error */

                status = smbcli_nt_error(c);
                //printf("got nt error 0x%x\n", status);

				if (NT_STATUS_V(NT_STATUS_PATH_NOT_COVERED) != NT_STATUS_V(status)) {
                        return False;
                }
        }
    /* execute trans2 getdfsreferral */
    //printf("check_dfs_redirect: process referral\n");
    //smbcli_get_dfs_referral(c, fname, dinfo);
	return True;
}

int smbcli_dfs_open_connection(struct smbcli_client* cluster,
		char* host, char* share, int flags)
{
	int i;
	BOOL retry;
	struct smbcli_state* c;
	
	// check if already connected
	for (i=0; i < DFS_MAX_CLUSTER_SIZE; i++) {
		if (cluster->cli[i]->in_use && strequal(host, smbcli_state_get_host(cluster->cli[i]))
				&& strequal(share, smbcli_state_get_share(cluster->cli[i]))) {
			DEBUG(3,("smbcli_dfs_open_connection: already connected to \\\\%s\\%s\n", host, share));
			return i;
		}
	}
	// open connection
	DEBUG(3,("smbcli_dfs_open_connection: opening \\\\%s\\%s %s@%s\n",
		host, share, cluster->username, cluster->workgroup));
	for (i=0; i < DFS_MAX_CLUSTER_SIZE; i++) {
		if (!cluster->cli[i]->in_use) {
			break;
		}
	}
	if (i >= DFS_MAX_CLUSTER_SIZE)
		return -1;

	c = cluster->cli[i];
	if (NT_STATUS_IS_ERR(smbcli_full_connection(&c,
			     NULL, host, NULL, 0,
			     share, "?????",
			     cluster->username, cluster->workgroup, 
			     cluster->password, flags,
			     &retry)))
		return -1;
	smbcli_state_set_sockopt(cluster->cli[i], cluster->sockops);
	smbcli_state_set_host(cluster->cli[i], host);
	smbcli_state_set_share(cluster->cli[i], share);
	cluster->cli[i]->in_use = True;
	DEBUG(3,("smbcli_dfs_open_connection: connected \\\\%s\\%s (%d) %s@%s\n",
		smbcli_state_get_host(cluster->cli[i]), smbcli_state_get_share(cluster->cli[i]), i,
		cluster->username, cluster->workgroup));

	return i;
}

/**********************************************************************
  Parse the pathname  of the form \hostname\service\reqpath
  into the dfs_path structure 
 **********************************************************************/

BOOL smbcli_parse_dfs_path(char* pathname, struct dfs_path* pdp)
{
	pstring pathname_local;
	char* p,*temp;

	pstrcpy(pathname_local,pathname);
	p = temp = pathname_local;

	ZERO_STRUCTP(pdp);

	trim_string(temp,"\\","\\");
	DEBUG(10,("temp in smbcli_parse_dfs_path: .%s. after trimming \\'s\n",temp));

	/* now tokenize */
	/* parse out hostname */
	p = strchr(temp,'\\');
	if(p == NULL)
		return False;
	*p = '\0';
	pstrcpy(pdp->hostname,temp);
	DEBUG(10,("hostname: %s\n",pdp->hostname));

	/* parse out servicename */
	temp = p+1;
	p = strchr(temp,'\\');
	if(p == NULL) {
		pstrcpy(pdp->servicename,temp);
		pdp->reqpath[0] = '\0';
		return True;
	}
	*p = '\0';
	pstrcpy(pdp->servicename,temp);
	DEBUG(10,("servicename: %s\n",pdp->servicename));

	/* rest is reqpath */
	pstrcpy(pdp->reqpath, p+1);

	DEBUG(10,("rest of the path: %s\n",pdp->reqpath));
	return True;
}

char* rebuild_filename(char *referral_fname, struct smbcli_state* c,
		char* fname, int path_consumed)
{
	const char *template = "\\\\%s\\%s\\%s";
	struct dfs_path dp;
	
	// TODO: handle consumed length
	DEBUG(3,("rebuild_filename: %s, %d consumed of %d\n",
		fname, path_consumed, strlen(fname)));
	if (smbcli_parse_dfs_path(fname, &dp)) {
		DEBUG(3,("rebuild_filename: reqpath=%s\n",
			dp.reqpath));
		asprintf(&referral_fname,
			template, smbcli_state_get_host(c),
			smbcli_state_get_share(c), dp.reqpath);
	}
	else
		return NULL;
	DEBUG(3,("rebuild_filename: %s -> %s\n", fname, referral_fname));
	return referral_fname;
}

/****************************************************************************
 Open a file (allowing for Dfs referral).
****************************************************************************/

int smbcli_dfs_open(struct smbcli_client* cluster, int *server,
	char *fname_src, int flags, int share_mode)
{
	int referral_number;
	dfs_info dinfo;
	char *referral_fname;
	int fnum;
	
	DEBUG(3,("smbcli_dfs_open: open %s on server %s(%d)\n",
			fname_src, smbcli_state_get_host(cluster->cli[*server]), *server));
	cluster->cli[*server]->dfs_referral = *server;
	if ((fnum = smbcli_open(cluster->cli[*server], fname_src, flags, share_mode)) < 0) {
		if (smbcli_check_dfs_redirect(cluster->cli[*server], fname_src, &dinfo)) {
			// choose referral, check if already connected, open if not
			referral_number = dinfo.selected_referral;
			DEBUG(3,("smbcli_dfs_open: redirecting to %s\n", dinfo.referrals[referral_number].node));
			cluster->cli[*server]->dfs_referral = smbcli_dfs_open_connection(cluster,
				dinfo.referrals[referral_number].host,
				dinfo.referrals[referral_number].share,
				cluster->connection_flags);
			*server = cluster->cli[*server]->dfs_referral;
			if (server < 0)
				return False;
			// rebuild file name and retry operation.
			if (rebuild_filename(referral_fname, cluster->cli[*server], fname_src, dinfo.path_consumed) == NULL)
				return False;
			fname_src = referral_fname;
			DEBUG(3,("smbcli_dfs_open: Dfs open %s on server %s(%d)\n",
				fname_src, smbcli_state_get_host(cluster->cli[*server]), *server));
			fnum = smbcli_open(cluster->cli[*server], fname_src, flags, share_mode);
		}
		if (smbcli_is_error(cluster->cli[*server])) {
			printf("smbcli_dfs_open: open of %s failed (%s)\n",
				fname_src, smbcli_errstr(cluster->cli[*server]));
			return -1;
		}
	}
	DEBUG(3,("smbcli_dfs_open: open %s fnum=%d\n",
			fname_src, fnum));
	return fnum;
}

/****************************************************************************
 Delete a file (allowing for Dfs referral).
****************************************************************************/

NTSTATUS smbcli_nt_unlink(struct smbcli_client* cluster, int *server,
	char *fname_src, uint16_t FileAttributes)
{
	int referral_number;
	dfs_info dinfo;
	char *referral_fname;
	struct smb_unlink parms;
	
	DEBUG(3,("smbcli_nt_unlink: delete %s on server %s(%d), attributes=0x%x\n",
			fname_src, smbcli_state_get_host(cluster->cli[*server]), *server,
			FileAttributes));
	cluster->cli[*server]->dfs_referral = *server;
	parms.in.pattern = fname_src;
	parms.in.dirtype = FileAttributes;			
	if (NT_STATUS_IS_ERR(smbcli_raw_unlink(cluster->cli[*server], &parms))) {
		printf("smbcli_nt_unlink: delete of %s failed (%s)\n",
				fname_src, smbcli_errstr(cluster->cli[*server]));
		if (smbcli_check_dfs_redirect(cluster->cli[*server], fname_src, &dinfo)) {
			// choose referral, check if already connected, open if not
			referral_number = dinfo.selected_referral;
			DEBUG(3,("smbcli_nt_unlink: redirecting to %s\n", dinfo.referrals[referral_number].node));
			cluster->cli[*server]->dfs_referral = smbcli_dfs_open_connection(cluster,
				dinfo.referrals[referral_number].host,
				dinfo.referrals[referral_number].share,
				cluster->connection_flags);
			*server = cluster->cli[*server]->dfs_referral;
			if (server < 0)
				return NT_STATUS_INTERNAL_ERROR;
			// rebuild file name and retry operation.
			if (rebuild_filename(referral_fname, cluster->cli[*server], fname_src, dinfo.path_consumed) == NULL)
				return NT_STATUS_INTERNAL_ERROR;
			fname_src = referral_fname;
			DEBUG(3,("smbcli_nt_unlink: Dfs delete %s on server %s(%d)\n",
				fname_src, smbcli_state_get_host(cluster->cli[*server]), *server));
			smbcli_raw_unlink(cluster->cli[*server], &parms);
		}
		if (smbcli_is_error(cluster->cli[*server])) {
			printf("smbcli_nt_unlink: delete of %s failed (%s)\n",
				fname_src, smbcli_errstr(cluster->cli[*server]));
		}
	}
	return smbcli_nt_error(cluster->cli[*server]);
}

/****************************************************************************
 Rename a file (allowing for Dfs referral).
****************************************************************************/

BOOL smbcli_dfs_rename(struct smbcli_client* cluster, int *server,
	char *fname_src, char *fname_dst)
{
	int referral_number;
	dfs_info dinfo;
	char *referral_fname;
	
	DEBUG(3,("smbcli_dfs_rename: rename %s to %s on server %s(%d)\n",
			fname_src, fname_dst, smbcli_state_get_host(cluster->cli[*server]), *server));
	cluster->cli[*server]->dfs_referral = *server;
	if (!smbcli_rename(cluster->cli[*server], fname_src, fname_dst)) {
		if (smbcli_check_dfs_redirect(cluster->cli[*server], fname_src, &dinfo)) {
			// choose referral, check if already connected, open if not
			referral_number = dinfo.selected_referral;
			DEBUG(3,("smbcli_dfs_rename: redirecting to %s\n", dinfo.referrals[referral_number].node));
			cluster->cli[*server]->dfs_referral = smbcli_dfs_open_connection(cluster,
				dinfo.referrals[referral_number].host,
				dinfo.referrals[referral_number].share,
				cluster->connection_flags);
			*server = cluster->cli[*server]->dfs_referral;
			if (server < 0)
				return False;
			// rebuild file name and retry operation.
			if (rebuild_filename(referral_fname, cluster->cli[*server], fname_src, dinfo.path_consumed) == NULL)
				return False;
			fname_src = referral_fname;
			DEBUG(3,("smbcli_dfs_rename: Dfs rename %s to %s on server %s(%d)\n",
				fname_src, fname_dst, smbcli_state_get_host(cluster->cli[*server]), *server));
			smbcli_rename(cluster->cli[*server], fname_src, fname_dst);
		}
		if (smbcli_is_error(cluster->cli[*server])) {
			printf("smbcli_dfs_rename: rename of %s to %s failed (%s)\n",
				fname_src, fname_dst, smbcli_errstr(cluster->cli[*server]));
			return False;
		}
	}
	return True;
}

/****************************************************************************
 Make directory (allowing for Dfs referral).
****************************************************************************/

BOOL smbcli_dfs_mkdir(struct smbcli_client* cluster, int *server,
	char *fname_src)
{
	int referral_number;
	dfs_info dinfo;
	char *referral_fname;
	
	DEBUG(3,("smbcli_dfs_mkdir: mkdir %s on server %s(%d)\n",
			fname_src, smbcli_state_get_host(cluster->cli[*server]), *server));
	cluster->cli[*server]->dfs_referral = *server;			
	if (!smbcli_mkdir(cluster->cli[*server], fname_src)) {
		printf("smbcli_dfs_mkdir: mkdir of %s failed (%s)\n",
				fname_src, smbcli_errstr(cluster->cli[*server]));
		if (smbcli_check_dfs_redirect(cluster->cli[*server], fname_src, &dinfo)) {
			// choose referral, check if already connected, open if not
			referral_number = dinfo.selected_referral;
			DEBUG(3,("smbcli_dfs_mkdir: redirecting to %s\n", dinfo.referrals[referral_number].node));
			cluster->cli[*server]->dfs_referral = smbcli_dfs_open_connection(cluster,
				dinfo.referrals[referral_number].host,
				dinfo.referrals[referral_number].share,
				cluster->connection_flags);
			*server = cluster->cli[*server]->dfs_referral;
			if (server < 0)
				return False;
			// rebuild file name and retry operation.
			if (rebuild_filename(referral_fname, cluster->cli[*server], fname_src, dinfo.path_consumed) == NULL)
				return False;
			fname_src = referral_fname;
			DEBUG(3,("smbcli_dfs_mkdir: Dfs mkdir %s on server %s(%d)\n",
				fname_src, smbcli_state_get_host(cluster->cli[*server]), *server));
			smbcli_mkdir(cluster->cli[*server], fname_src);
		}
		if (smbcli_is_error(cluster->cli[*server])) {
			printf("smbcli_dfs_mkdir: mkdir of %s failed (%s)\n",
				fname_src, smbcli_errstr(cluster->cli[*server]));
			return False;
		}
	}
	return True;
}

/****************************************************************************
 Remove directory (allowing for Dfs referral).
****************************************************************************/

BOOL smbcli_dfs_rmdir(struct smbcli_client* cluster, int *server,
	char *fname_src)
{
	int referral_number;
	dfs_info dinfo;
	char *referral_fname;
	
	DEBUG(3,("smbcli_dfs_rmdir: rmdir %s on server %s(%d)\n",
			fname_src, smbcli_state_get_host(cluster->cli[*server]), *server));
	cluster->cli[*server]->dfs_referral = *server;			
	if (!smbcli_rmdir(cluster->cli[*server], fname_src)) {
		printf("smbcli_dfs_rmdir: rmdir of %s failed (%s)\n",
				fname_src, smbcli_errstr(cluster->cli[*server]));
		if (smbcli_check_dfs_redirect(cluster->cli[*server], fname_src, &dinfo)) {
			// choose referral, check if already connected, open if not
			referral_number = dinfo.selected_referral;
			DEBUG(3,("smbcli_dfs_rmdir: redirecting to %s\n", dinfo.referrals[referral_number].node));
			cluster->cli[*server]->dfs_referral = smbcli_dfs_open_connection(cluster,
				dinfo.referrals[referral_number].host,
				dinfo.referrals[referral_number].share,
				cluster->connection_flags);
			*server = cluster->cli[*server]->dfs_referral;
			if (server < 0)
				return False;
			// rebuild file name and retry operation.
			if (rebuild_filename(referral_fname, cluster->cli[*server], fname_src, dinfo.path_consumed) == NULL)
				return False;
			fname_src = referral_fname;
			DEBUG(3,("smbcli_dfs_rmdir: Dfs rmdir %s on server %s(%d)\n",
				fname_src, smbcli_state_get_host(cluster->cli[*server]), *server));
			smbcli_rmdir(cluster->cli[*server], fname_src);
		}
		if (smbcli_is_error(cluster->cli[*server])) {
			printf("smbcli_dfs_rmdir: rmdir of %s failed (%s)\n",
				fname_src, smbcli_errstr(cluster->cli[*server]));
			return False;
		}
	}
	return True;
}
