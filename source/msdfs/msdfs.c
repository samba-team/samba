/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   MSDfs services for Samba
   Copyright (C) Shirish Kalele 2000

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

extern fstring local_machine;
extern uint32 global_client_caps;

#ifdef WITH_MSDFS

/**********************************************************************
  Parse the pathname  of the form \hostname\service\reqpath
  into the dfs_path structure 
 **********************************************************************/

static BOOL parse_dfs_path(char* pathname, struct dfs_path* pdp)
{
	pstring pathname_local;
	char* p,*temp;

	pstrcpy(pathname_local,pathname);
	p = temp = pathname_local;

	ZERO_STRUCTP(pdp);

	trim_string(temp,"\\","\\");
	DEBUG(10,("temp in parse_dfs_path: .%s. after trimming \\'s\n",temp));

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
	p = pdp->reqpath;
	while (*p) {
		if (*p == '\\') *p = '/';
		p++;
	}

	DEBUG(10,("rest of the path: %s\n",pdp->reqpath));
	return True;
}

/********************************************************
 Fake up a connection struct for the VFS layer.
*********************************************************/

static BOOL create_conn_struct( connection_struct *conn, int snum)
{

	ZERO_STRUCTP(conn);
	conn->service = snum;
	conn->connectpath = lp_pathname(snum);
	pstring_sub(conn->connectpath, "%S", lp_servicename(snum));

	if (!smbd_vfs_init(conn)) {
		DEBUG(0,("create_conn_struct: smbd_vfs_init failed.\n"));
		return False;
	}
	return True;
}


/**********************************************************************
 Parse the contents of a symlink to verify if it is an msdfs referral
 A valid referral is of the form: msdfs:server1\share1,server2\share2
 **********************************************************************/
static BOOL parse_symlink(char* buf,struct referral** preflist, 
				 int* refcount)
{
	pstring temp;
	char* prot;
	char* alt_path[MAX_REFERRAL_COUNT];
	int count=0, i;
	struct referral* reflist;

	pstrcpy(temp,buf);
  
	prot = strtok(temp,":");

	if (!strequal(prot, "msdfs"))
		return False;

	/* No referral list requested. Just yes/no. */
	if (!preflist) 
		return True;

	/* parse out the alternate paths */
	while(((alt_path[count] = strtok(NULL,",")) != NULL) && count<MAX_REFERRAL_COUNT)
		count++;

	DEBUG(10,("parse_symlink: count=%d\n", count));

	reflist = *preflist = (struct referral*) malloc(count * sizeof(struct referral));
	if(reflist == NULL) {
		DEBUG(0,("parse_symlink: Malloc failed!\n"));
		return False;
	}
	
	for(i=0;i<count;i++) {
		/* replace / in the alternate path by a \ */
		char* p = strchr(alt_path[i],'/');
		if(p)
			*p = '\\'; 

		pstrcpy(reflist[i].alternate_path, "\\");
		pstrcat(reflist[i].alternate_path, alt_path[i]);
		reflist[i].proximity = 0;
		reflist[i].ttl = REFERRAL_TTL;
		DEBUG(10, ("parse_symlink: Created alt path: %s\n", reflist[i].alternate_path));
	}

	if(refcount)
		*refcount = count;

	return True;
}
 
/**********************************************************************
 Returns true if the unix path is a valid msdfs symlink
 **********************************************************************/
BOOL is_msdfs_link(connection_struct* conn, char* path,
		   struct referral** reflistp, int* refcnt,
		   SMB_STRUCT_STAT *sbufp)
{
	SMB_STRUCT_STAT st;
	pstring referral;
	int referral_len = 0;

	if (!path || !conn)
		return False;

	strlower(path);

	if (sbufp == NULL)
		sbufp = &st;

	if (conn->vfs_ops.lstat(conn,dos_to_unix_static(path), sbufp) != 0) {
		DEBUG(5,("is_msdfs_link: %s does not exist.\n",path));
		return False;
	}
  
	if (S_ISLNK(sbufp->st_mode)) {
		/* open the link and read it */
		referral_len = conn->vfs_ops.readlink(conn, path, referral, 
						      sizeof(pstring));
		if (referral_len == -1) {
			DEBUG(0,("is_msdfs_link: Error reading msdfs link %s: %s\n", path, strerror(errno)));
			return False;
		}

		referral[referral_len] = '\0';
		DEBUG(5,("is_msdfs_link: %s -> %s\n",path,referral));
		if (parse_symlink(referral, reflistp, refcnt))
			return True;
	}
	return False;
}

/*****************************************************************
 Used by other functions to decide if a dfs path is remote,
and to get the list of referred locations for that remote path.
 
findfirst_flag: For findfirsts, dfs links themselves are not
redirected, but paths beyond the links are. For normal smb calls,
even dfs links need to be redirected.

self_referralp: clients expect a dfs referral for the same share when
they request referrals for dfs roots on a server. 

consumedcntp: how much of the dfs path is being redirected. the client
should try the remaining path on the redirected server.
*****************************************************************/
static BOOL resolve_dfs_path(char* dfspath, struct dfs_path* dp, 
		      connection_struct* conn,
		      BOOL findfirst_flag,
		      struct referral** reflistpp, int* refcntp,
		      BOOL* self_referralp, int* consumedcntp)
{
	fstring localpath;

	char *p;
	fstring reqpath;

	if (!dp || !conn) {
		DEBUG(1,("resolve_dfs_path: NULL dfs_path* or NULL connection_struct*!\n"));
		return False;
	}

	if (dp->reqpath[0] == '\0') {
		if (self_referralp) {
			DEBUG(6,("resolve_dfs_path: self-referral. returning False\n"));
			*self_referralp = True;
		}
		return False;
	}

	/* check if need to redirect */
	fstrcpy(localpath, conn->connectpath);
	fstrcat(localpath, "/");
	fstrcat(localpath, dp->reqpath);
	if (is_msdfs_link(conn, localpath, reflistpp, refcntp, NULL)) {
		if (findfirst_flag) {
			DEBUG(6,("resolve_dfs_path (FindFirst) No redirection "
				 "for dfs link %s.\n", dfspath));
			return False;
		} else {		
			DEBUG(6,("resolve_dfs_path: %s resolves to a valid Dfs link.\n",
				 dfspath));
			if (consumedcntp) 
				*consumedcntp = strlen(dfspath);
			return True;
		}
	} 

	/* also redirect if the parent directory is a dfs link */
	fstrcpy(reqpath, dp->reqpath);
	p = strrchr(reqpath, '/');
	if (p) {
		*p = '\0';
		fstrcpy(localpath, conn->connectpath);
		fstrcat(localpath, "/");
		fstrcat(localpath, reqpath);
		if (is_msdfs_link(conn, localpath, reflistpp, refcntp, NULL)) {
			DEBUG(4, ("resolve_dfs_path: Redirecting %s because parent %s is dfs link\n", dfspath, localpath));

			/* To find the path consumed, we truncate the original
			   DFS pathname passed to use to remove the last
			   component. The length of the resulting string is
			   the path consumed 
			*/
			if (consumedcntp) {
				char *q;
				pstring buf;
				pstrcpy(buf, dfspath);
				trim_string(buf, NULL, "\\");
				q = strrchr(buf, '\\');
				if (q) 
					*q = '\0';
				*consumedcntp = strlen(buf);
				DEBUG(10, ("resolve_dfs_path: Path consumed: %d\n", *consumedcntp));
			}
			
			return True;
		}
	}
	
	return False;
}

/*****************************************************************
  Decides if a dfs pathname should be redirected or not.
  If not, the pathname is converted to a tcon-relative local unix path
*****************************************************************/
BOOL dfs_redirect(char* pathname, connection_struct* conn,
		  BOOL findfirst_flag)
{
	struct dfs_path dp;
	
	if (!conn || !pathname)
		return False;

	parse_dfs_path(pathname, &dp);

	/* if dfs pathname for a non-dfs share, convert to tcon-relative
	   path and return false */
	if (!lp_msdfs_root(SNUM(conn))) {
		fstrcpy(pathname, dp.reqpath);
		return False;
	}
	
	if (strcasecmp(dp.servicename, lp_servicename(SNUM(conn)) ) != 0) 
		return False;

	if (resolve_dfs_path(pathname, &dp, conn, findfirst_flag,
			     NULL, NULL, NULL, NULL)) {
		DEBUG(3,("dfs_redirect: Redirecting %s\n", pathname));
		return True;
	} else {
		DEBUG(3,("dfs_redirect: Not redirecting %s.\n", pathname));
		
		/* Form non-dfs tcon-relative path */
		fstrcpy(pathname, dp.reqpath);
		DEBUG(3,("dfs_redirect: Path converted to non-dfs path %s\n",
			 pathname));
		return False;
	}
	/* never reached */
	return False;
}

/**********************************************************************
 Gets valid referrals for a dfs path and fills up the
 junction_map structure
 **********************************************************************/
BOOL get_referred_path(char *pathname, struct junction_map* jn,
		       int* consumedcntp, BOOL* self_referralp)
{
	struct dfs_path dp;

	struct connection_struct conns;
	struct connection_struct* conn = &conns;
	int snum;

	BOOL self_referral = False;

	if (!pathname || !jn)
		return False;

	if (self_referralp)
		*self_referralp = False;
	else
		self_referralp = &self_referral;

	parse_dfs_path(pathname, &dp);

	/* Verify hostname in path */
	if (local_machine && (strcasecmp(local_machine, dp.hostname) != 0)) {

	   /* Hostname mismatch, check if one of our IP addresses */
	   if (!ismyip(*interpret_addr2(dp.hostname))) {
		
		DEBUG(3, ("get_referred_path: Invalid hostname %s in path %s\n",
		  	  dp.hostname, pathname));
		return False;
	   }
	}

	pstrcpy(jn->service_name, dp.servicename);
	pstrcpy(jn->volume_name, dp.reqpath);

	/* Verify the share is a dfs root */
	snum = lp_servicenumber(jn->service_name);
	if(snum < 0) {
		if ((snum = find_service(jn->service_name)) < 0)
			return False;
	}
	
	if (!create_conn_struct(conn, snum))
		return False;
	
	if (!lp_msdfs_root(SNUM(conn))) {
		DEBUG(3,("get_referred_path: .%s. in dfs path %s is not a dfs root.\n",
			 dp.servicename, pathname));
		return False;
	}

	/* If not remote & not a self referral, return False */
	if (!resolve_dfs_path(pathname, &dp, conn, False, 
			      &jn->referral_list, &jn->referral_count,
			      self_referralp, consumedcntp)) {
		if (!*self_referralp) {
			DEBUG(3,("get_referred_path: No valid referrals for path %s\n", pathname));
			return False;
		}
	}
	
	/* if self_referral, fill up the junction map */
	if (*self_referralp) {
		struct referral* ref;
		jn->referral_count = 1;
		if((ref = (struct referral*) malloc(sizeof(struct referral)))
		   == NULL) {
			DEBUG(0,("malloc failed for referral\n"));
			return False;
		}
      
		pstrcpy(ref->alternate_path,pathname);
		ref->proximity = 0;
		ref->ttl = REFERRAL_TTL;
		jn->referral_list = ref;
		if (consumedcntp)
			*consumedcntp = strlen(pathname);
	}

	return True;
}

static int setup_ver2_dfs_referral(char* pathname, char** ppdata, 
				   struct junction_map* junction,
				   int consumedcnt,
				   BOOL self_referral)
{
	char* pdata = *ppdata;

	unsigned char uni_requestedpath[1024];
	int uni_reqpathoffset1,uni_reqpathoffset2;
	int uni_curroffset;
	int requestedpathlen=0;
	int offset;
	int reply_size = 0;
	int i=0;

	DEBUG(10,("setting up version2 referral\nRequested path:\n"));

	requestedpathlen = (dos_struni2((char *)uni_requestedpath,pathname,sizeof(uni_requestedpath)) + 1) * 2;

	dump_data(10, (char *) uni_requestedpath,requestedpathlen);

	DEBUG(10,("ref count = %u\n",junction->referral_count));

	uni_reqpathoffset1 = REFERRAL_HEADER_SIZE + 
			VERSION2_REFERRAL_SIZE * junction->referral_count;

	uni_reqpathoffset2 = uni_reqpathoffset1 + requestedpathlen;

	uni_curroffset = uni_reqpathoffset2 + requestedpathlen;

	reply_size = REFERRAL_HEADER_SIZE + VERSION2_REFERRAL_SIZE*junction->referral_count +
					2 * requestedpathlen;
	DEBUG(10,("reply_size: %u\n",reply_size));

	/* add up the unicode lengths of all the referral paths */
	for(i=0;i<junction->referral_count;i++) {
		DEBUG(10,("referral %u : %s\n",i,junction->referral_list[i].alternate_path));
		reply_size += (strlen(junction->referral_list[i].alternate_path)+1)*2;
	}

	DEBUG(10,("reply_size = %u\n",reply_size));
	/* add the unexplained 0x16 bytes */
	reply_size += 0x16;

	pdata = Realloc(pdata,reply_size);
	if(pdata == NULL) {
		DEBUG(0,("malloc failed for Realloc!\n"));
		return -1;
	} else
		*ppdata = pdata;

	/* copy in the dfs requested paths.. required for offset calculations */
	memcpy(pdata+uni_reqpathoffset1,uni_requestedpath,requestedpathlen);
	memcpy(pdata+uni_reqpathoffset2,uni_requestedpath,requestedpathlen);

	/* create the header */
	SSVAL(pdata,0,consumedcnt * 2); /* path consumed */
	SSVAL(pdata,2,junction->referral_count); /* number of referral in this pkt */
	if(self_referral)
		SIVAL(pdata,4,DFSREF_REFERRAL_SERVER | DFSREF_STORAGE_SERVER); 
	else
		SIVAL(pdata,4,DFSREF_STORAGE_SERVER);

	offset = 8;
	/* add the referral elements */
	for(i=0;i<junction->referral_count;i++) {
		struct referral* ref = &(junction->referral_list[i]);
		int unilen;

		SSVAL(pdata,offset,2); /* version 2 */
		SSVAL(pdata,offset+2,VERSION2_REFERRAL_SIZE);
		if(self_referral)
			SSVAL(pdata,offset+4,1);
		else
			SSVAL(pdata,offset+4,0);
		SSVAL(pdata,offset+6,0); /* ref_flags :use path_consumed bytes? */
		SIVAL(pdata,offset+8,ref->proximity);
		SIVAL(pdata,offset+12,ref->ttl);

		SSVAL(pdata,offset+16,uni_reqpathoffset1-offset);
		SSVAL(pdata,offset+18,uni_reqpathoffset2-offset);
		/* copy referred path into current offset */
		unilen = (dos_struni2(pdata+uni_curroffset,ref->alternate_path,sizeof(uni_requestedpath)) +1)*2;
		SSVAL(pdata,offset+20,uni_curroffset-offset);

		uni_curroffset += unilen;
		offset += VERSION2_REFERRAL_SIZE;
	}
	/* add in the unexplained 22 (0x16) bytes at the end */
	memset(pdata+uni_curroffset,'\0',0x16);
	return reply_size;
}

static int setup_ver3_dfs_referral(char* pathname, char** ppdata, 
				   struct junction_map* junction,
				   int consumedcnt,
				   BOOL self_referral)
{
	char* pdata = *ppdata;

	unsigned char uni_reqpath[1024];
	int uni_reqpathoffset1, uni_reqpathoffset2;
	int uni_curroffset;
	int reply_size = 0;

	int reqpathlen = 0;
	int offset,i=0;
	
	DEBUG(10,("setting up version3 referral\n"));

	reqpathlen = (dos_struni2((char *) uni_reqpath,pathname,sizeof(uni_reqpath))+1)*2;
	
	dump_data(10, (char *) uni_reqpath,reqpathlen);

	uni_reqpathoffset1 = REFERRAL_HEADER_SIZE + VERSION3_REFERRAL_SIZE * junction->referral_count;
	uni_reqpathoffset2 = uni_reqpathoffset1 + reqpathlen;
	reply_size = uni_curroffset = uni_reqpathoffset2 + reqpathlen;

	for(i=0;i<junction->referral_count;i++) {
		DEBUG(10,("referral %u : %s\n",i,junction->referral_list[i].alternate_path));
		reply_size += (strlen(junction->referral_list[i].alternate_path)+1)*2;
	}

	pdata = Realloc(pdata,reply_size);
	if(pdata == NULL) {
		DEBUG(0,("version3 referral setup: malloc failed for Realloc!\n"));
		return -1;
	} else
		*ppdata = pdata;

	/* create the header */
	SSVAL(pdata,0,consumedcnt * 2); /* path consumed */
	SSVAL(pdata,2,junction->referral_count); /* number of referral */
	if(self_referral)
		SIVAL(pdata,4,DFSREF_REFERRAL_SERVER | DFSREF_STORAGE_SERVER); 
	else
		SIVAL(pdata,4,DFSREF_STORAGE_SERVER);
	
	/* copy in the reqpaths */
	memcpy(pdata+uni_reqpathoffset1,uni_reqpath,reqpathlen);
	memcpy(pdata+uni_reqpathoffset2,uni_reqpath,reqpathlen);
	
	offset = 8;
	for(i=0;i<junction->referral_count;i++) {
		struct referral* ref = &(junction->referral_list[i]);
		int unilen;

		SSVAL(pdata,offset,3); /* version 3 */
		SSVAL(pdata,offset+2,VERSION3_REFERRAL_SIZE);
		if(self_referral)
			SSVAL(pdata,offset+4,1);
		else
			SSVAL(pdata,offset+4,0);

		SSVAL(pdata,offset+6,0); /* ref_flags :use path_consumed bytes? */
		SIVAL(pdata,offset+8,ref->ttl);
	    
		SSVAL(pdata,offset+12,uni_reqpathoffset1-offset);
		SSVAL(pdata,offset+14,uni_reqpathoffset2-offset);
		/* copy referred path into current offset */
		unilen = (dos_struni2(pdata+uni_curroffset,ref->alternate_path,sizeof(uni_reqpath)) +1)*2;
		SSVAL(pdata,offset+16,uni_curroffset-offset);
		/* copy 0x10 bytes of 00's in the ServiceSite GUID */
		memset(pdata+offset+18,'\0',16);

		uni_curroffset += unilen;
		offset += VERSION3_REFERRAL_SIZE;
	}
	return reply_size;
}

/******************************************************************
 * Set up the Dfs referral for the dfs pathname
 ******************************************************************/

int setup_dfs_referral(char* pathname, int max_referral_level, char** ppdata)
{
	struct junction_map junction;
	int consumedcnt;
	BOOL self_referral = False;
	pstring buf;
	int reply_size = 0;
	char *pathnamep = pathname;

	ZERO_STRUCT(junction);

	/* get the junction entry */
	if (!pathnamep)
		return -1;

	/* Trim pathname sent by client so it begins with only one backslash.
	   Two backslashes confuse some dfs clients
	 */
	while (strlen(pathnamep) > 1 && pathnamep[0] == '\\'
	       && pathnamep[1] == '\\')
		pathnamep++;

	pstrcpy(buf, pathnamep);
	if (!get_referred_path(buf, &junction, &consumedcnt,
			       &self_referral))
		return -1;
	
	if (!self_referral)
	{
		pathnamep[consumedcnt] = '\0';

		if( DEBUGLVL( 3 ) ) {
			int i=0;
			dbgtext("setup_dfs_referral: Path %s to alternate path(s):",pathnamep);
			for(i=0;i<junction.referral_count;i++)
				dbgtext(" %s",junction.referral_list[i].alternate_path);
			dbgtext(".\n");
		}
	}
	
	/* create the referral depeding on version */
	DEBUG(10,("max_referral_level :%d\n",max_referral_level));
	if(max_referral_level<2 || max_referral_level>3)
		max_referral_level = 2;

	switch(max_referral_level) {
	case 2:
		{
		reply_size = setup_ver2_dfs_referral(pathnamep, ppdata, &junction, 
						     consumedcnt, self_referral);
		SAFE_FREE(junction.referral_list);
		break;
		}
	case 3:
		{
		reply_size = setup_ver3_dfs_referral(pathnamep, ppdata, &junction, 
						     consumedcnt, self_referral);
		SAFE_FREE(junction.referral_list);
		break;
		}
	default:
		{
		DEBUG(0,("setup_dfs_referral: Invalid dfs referral version: %d\n", max_referral_level));
		return -1;
		}
	}
      
	DEBUG(10,("DFS Referral pdata:\n"));
	dump_data(10,*ppdata,reply_size);
	return reply_size;
}

int dfs_path_error(char* inbuf, char* outbuf)
{
	return ERROR_BOTH(NT_STATUS_PATH_NOT_COVERED, ERRSRV, ERRbadpath);
}

/**********************************************************************
 The following functions are called by the NETDFS RPC pipe functions
 **********************************************************************/

/**********************************************************************
 Creates a junction structure from a Dfs pathname
 **********************************************************************/
BOOL create_junction(char* pathname, struct junction_map* jn)
{
        struct dfs_path dp;
 
        parse_dfs_path(pathname,&dp);

        /* check if path is dfs : validate first token */
        if (local_machine && (strcasecmp(local_machine,dp.hostname)!=0)) {
	    
	   /* Hostname mismatch, check if one of our IP addresses */
	   if (!ismyip(*interpret_addr2(dp.hostname))) {
                DEBUG(4,("create_junction: Invalid hostname %s in dfs path %s\n",
			 dp.hostname, pathname));
                return False;
	   }
        }

        /* Check for a non-DFS share */
        if(!lp_msdfs_root(lp_servicenumber(dp.servicename))) {
                DEBUG(4,("create_junction: %s is not an msdfs root.\n", 
			 dp.servicename));
                return False;
        }

        pstrcpy(jn->service_name,dp.servicename);
        pstrcpy(jn->volume_name,dp.reqpath);
        return True;
}

/**********************************************************************
 Forms a valid Unix pathname from the junction 
 **********************************************************************/
static BOOL junction_to_local_path(struct junction_map* jn, char* path,
				   int max_pathlen, connection_struct *conn)
{
	int snum;

	if(!path || !jn)
		return False;

	snum = lp_servicenumber(jn->service_name);
	if(snum < 0)
		return False;

	safe_strcpy(path, lp_pathname(snum), max_pathlen-1);
	safe_strcat(path, "/", max_pathlen-1);
	strlower(jn->volume_name);
	safe_strcat(path, jn->volume_name, max_pathlen-1);

	if (!create_conn_struct(conn, snum))
		return False;

	return True;
}

BOOL create_msdfs_link(struct junction_map* jn, BOOL exists)
{
	pstring path;
	pstring msdfs_link;
	connection_struct conns;
 	connection_struct *conn = &conns;
	int i=0;
	BOOL insert_comma = False;

	if(!junction_to_local_path(jn, path, sizeof(path), conn))
		return False;
  
	/* form the msdfs_link contents */
	pstrcpy(msdfs_link, "msdfs:");
	for(i=0; i<jn->referral_count; i++) {
		char* refpath = jn->referral_list[i].alternate_path;
      
		trim_string(refpath, "\\", "\\");
		if(*refpath == '\0') {
			if (i == 0)
				insert_comma = False;
			continue;
		}
		if (i > 0 && insert_comma)
			pstrcat(msdfs_link, ",");

		pstrcat(msdfs_link, refpath);
		if (!insert_comma)
			insert_comma = True;
		
	}

	DEBUG(5,("create_msdfs_link: Creating new msdfs link: %s -> %s\n", path, msdfs_link));

	if(exists)
		if(conn->vfs_ops.unlink(conn,path)!=0)
			return False;

	if(conn->vfs_ops.symlink(conn, msdfs_link, path) < 0) {
		DEBUG(1,("create_msdfs_link: symlink failed %s -> %s\nError: %s\n", 
				path, msdfs_link, strerror(errno)));
		return False;
	}
	return True;
}

BOOL remove_msdfs_link(struct junction_map* jn)
{
	pstring path;
	connection_struct conns;
 	connection_struct *conn = &conns;

	if(!junction_to_local_path(jn, path, sizeof(path), conn))
		return False;
     
	if(conn->vfs_ops.unlink(conn, path)!=0)
		return False;
  
	return True;
}

static BOOL form_junctions(int snum, struct junction_map* jn, int* jn_count)
{
	int cnt = *jn_count;
	DIR *dirp;
	char* dname;
	pstring connect_path;
	char* service_name = lp_servicename(snum);
	connection_struct conns;
	connection_struct *conn = &conns;
 
	pstrcpy(connect_path,lp_pathname(snum));

	if(*connect_path == '\0')
		return False;

	/*
	 * Fake up a connection struct for the VFS layer.
	 */

	if (!create_conn_struct(conn, snum))
		return False;

	{ 
		/* form a junction for the msdfs root - convention 
		   DO NOT REMOVE THIS: NT clients will not work with us
		   if this is not present
		*/ 
		struct referral *ref = NULL;
		pstring alt_path;
		pstrcpy(jn[cnt].service_name, service_name);
		jn[cnt].volume_name[0] = '\0';
		jn[cnt].referral_count = 1;
	
		slprintf(alt_path,sizeof(alt_path)-1,"\\\\%s\\%s", 
			 local_machine, service_name);
		ref = jn[cnt].referral_list = (struct referral*) malloc(sizeof(struct referral));
		if (jn[cnt].referral_list == NULL) {
			DEBUG(0, ("Malloc failed!\n"));
			return False;
		}

		pstrcpy(ref->alternate_path, alt_path);
		ref->proximity = 0;
		ref->ttl = REFERRAL_TTL;
		cnt++;
	}

	dirp = conn->vfs_ops.opendir(conn, dos_to_unix_static(connect_path));
	if(!dirp)
		return False;

	while((dname = vfs_readdirname(conn, dirp)) != NULL) {
		pstring pathreal;

		pstrcpy(pathreal, connect_path);
		pstrcat(pathreal, "/");
		pstrcat(pathreal, dname);
 
		if (is_msdfs_link(conn, pathreal, &(jn[cnt].referral_list),
				  &(jn[cnt].referral_count), NULL)) {
			pstrcpy(jn[cnt].service_name, service_name);
			pstrcpy(jn[cnt].volume_name, dname);
			cnt++;
		}
	}
	
	conn->vfs_ops.closedir(conn,dirp);
	*jn_count = cnt;
	return True;
}

int enum_msdfs_links(struct junction_map* jn)
{
	int i=0;
	int jn_count = 0;

	if(!lp_host_msdfs())
		return -1;

	for(i=0;*lp_servicename(i);i++) {
		if(lp_msdfs_root(i)) 
			form_junctions(i,jn,&jn_count);
	}
	return jn_count;
}


#else
/* Stub functions if WITH_MSDFS not defined */
 int setup_dfs_referral(char* pathname, int max_referral_level, char** ppdata)
{
	return -1;
}

 BOOL is_msdfs_link(connection_struct* conn, char* path,
		    struct referral** reflistpp, int* refcntp,
		    SMB_STRUCT_STAT *sbufp)
{
	return False;
}

#endif
