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

extern int DEBUGLEVEL;
extern pstring global_myname;
extern uint32 global_client_caps;

#ifdef MS_DFS

static void create_nondfs_path(char* pathname, struct dfs_path* pdp)
{
  pstrcpy(pathname,pdp->volumename); 
  pstrcat(pathname,"\\"); 
  pstrcat(pathname,pdp->restofthepath); 
}

/* Parse the pathname  of the form \hostname\service\volume\restofthepath
   into the dfs_path structure */
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
  if(p == NULL)
    {
      pstrcpy(pdp->servicename,temp);
      return True;
    }
  *p = '\0';
  pstrcpy(pdp->servicename,temp);
  DEBUG(10,("servicename: %s\n",pdp->servicename));

  /* parse out volumename */
  temp = p+1;
  p = strchr(temp,'\\');
  if(p == NULL)
    {
      pstrcpy(pdp->volumename,temp);
      return True;
    }
  *p = '\0';
  pstrcpy(pdp->volumename,temp);
  DEBUG(10,("volumename: %s\n",pdp->volumename));

  /* remaining path .. */
  pstrcpy(pdp->restofthepath,p+1);
  DEBUG(10,("rest of the path: %s\n",pdp->restofthepath));
  return True;
}

/**********************************************************************
 Parse the contents of a symlink to verify if it is an msdfs referral
 A valid referral is of the form: msdfs:server1\share1,server2\share2
 **********************************************************************/
static BOOL parse_symlink(char* buf,struct referral** preflist, int* refcount)
{
  pstring temp;
  char* prot;
  char* alt_path[MAX_REFERRAL_COUNT];
  int count=0, i;
  struct referral* reflist;

  pstrcpy(temp,buf);
  
  prot = strtok(temp,":");

  if(!strequal(prot, "msdfs"))
    return False;

  /* It's an msdfs referral */
  if(!preflist) 
    return True;

  /* parse out the alternate paths */
  while(((alt_path[count] = strtok(NULL,",")) != NULL) 
	&& count<MAX_REFERRAL_COUNT)
    count++;

  DEBUG(10,("parse_symlink: count=%d\n", count));
  reflist = *preflist = (struct referral*) malloc(count * 
						  sizeof(struct referral));
  if(reflist == NULL)
    {
      DEBUG(0,("parse_symlink: Malloc failed!\n"));
      return False;
    }
  
  for(i=0;i<count;i++)
    {
      pstrcpy(reflist[i].alternate_path, "\\");
      pstrcat(reflist[i].alternate_path, alt_path[i]);
      reflist[i].proximity = 0;
      reflist[i].ttl = REFERRAL_TTL;
      DEBUG(10, ("parse_symlink: Created alt path: %s\n",
		reflist[i].alternate_path));
    }

  if(refcount)
    *refcount = count;

  return True;
}
 
BOOL is_msdfs_volume(connection_struct* conn, char* path)
{
  SMB_STRUCT_STAT st;
  pstring referral;

  if(!path || !conn)
    return False;

  strlower(path);

  if(conn->vfs_ops.lstat(dos_to_unix(path,False),&st) != 0)
    {
      DEBUG(5,("is_msdfs_volume: %s does not exist.\n",path));
      return False;
    }
  
  if(st.st_mode & S_IFLNK)
    {
      /* open the link and read it */
      readlink(path, referral, sizeof(pstring));
      DEBUG(5,("is_msdfs_volume: %s -> %s\n",path,referral));
      if(parse_symlink(referral, NULL, NULL))
	return True;
    }
  return False;
}

static BOOL get_referred_path(struct junction_map* junction)
{
  fstring path;
  pstring buf;
  SMB_STRUCT_STAT st;
  int snum = lp_servicenumber(junction->service_name);

  /* form the path */
  fstrcpy(path, lp_pathname(snum));
  fstrcat(path, "/");

  strlower(junction->volume_name);

  fstrcat(path, junction->volume_name);

  DEBUG(5,("get_referred_path: lstat target: %s\n", path));
  
  if(lstat(dos_to_unix(path, False),&st) != 0)
    {
      DEBUG(5,("get_referred_path: %s does not exist.\n",path));
      return False;
    }
  
  if(st.st_mode & S_IFLNK)
    {
      /* open the link and read it to get the dfs referral */
      readlink(path, buf, sizeof(buf));
      DEBUG(5,("get_referred_path: Referral: %s\n",buf));
      if(parse_symlink(buf, &junction->referral_list, 
		       &junction->referral_count))
      return True;
    }
  return False;
}

/**************************************************************
Decides if given pathname is Dfs and if it should be redirected
Converts pathname to non-dfs format if Dfs redirection not required 
**************************************************************/
BOOL dfs_redirect(char* pathname, connection_struct* conn)
{
  struct dfs_path dp;
  pstring temp;
  fstring path;

  pstrcpy(temp,pathname);

  if(!lp_msdfs_root(SNUM(conn)) )
    return False;

  parse_dfs_path(pathname,&dp);

  if(global_myname && (strcasecmp(global_myname,dp.hostname)!=0))
     return False;

  /* check if need to redirect */
  fstrcpy(path, conn->connectpath);
  fstrcat(path, "/");
  fstrcat(path, dp.volumename);
  if(is_msdfs_volume(conn, path))
    {
      DEBUG(4,("dfs_redirect: Redirecting %s\n",temp));
      return True;
    }
  else
    {
      create_nondfs_path(pathname,&dp);
      DEBUG(4,("dfs_redirect: Not redirecting %s. Converted to non-dfs pathname \'%s\'\n",
	       temp,pathname));
      return False;
    }
}

/*
  Special DFS redirect call for findfirst's. 
  If the findfirst is for the dfs junction, then no redirection,
  if it is for the underlying directory contents, redirect.
  */
BOOL dfs_findfirst_redirect(char* pathname, connection_struct* conn)
{
  struct dfs_path dp;
  
  pstring temp;

  pstrcpy(temp,pathname);

  /* Is the path Dfs-redirectable? */
  if(!dfs_redirect(temp,conn))
    {
      pstrcpy(pathname,temp);
      return False;
    }

  parse_dfs_path(pathname,&dp);
  DEBUG(8,("dfs_findfirst_redirect: path %s is in Dfs. dp.restofthepath=.%s.\n",pathname,dp.restofthepath));
  if(*(dp.restofthepath))
    return True;
  else
    {
      create_nondfs_path(pathname,&dp);
      return False;
    }
}

static int setup_ver2_dfs_referral(char* pathname, char** ppdata, 
				   struct junction_map* junction,
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

  requestedpathlen = (dos_struni2(uni_requestedpath,pathname,512)+1)*2;

  dump_data(10,uni_requestedpath,requestedpathlen);

  DEBUG(10,("ref count = %u\n",junction->referral_count));

  uni_reqpathoffset1 = REFERRAL_HEADER_SIZE + 
    VERSION2_REFERRAL_SIZE * junction->referral_count;

  uni_reqpathoffset2 = uni_reqpathoffset1 + requestedpathlen;

  uni_curroffset = uni_reqpathoffset2 + requestedpathlen;

  reply_size = REFERRAL_HEADER_SIZE + VERSION2_REFERRAL_SIZE*junction->referral_count +
    2 * requestedpathlen;
  DEBUG(10,("reply_size: %u\n",reply_size));

  /* add up the unicode lengths of all the referral paths */
  for(i=0;i<junction->referral_count;i++)
    {
      DEBUG(10,("referral %u : %s\n",i,junction->referral_list[i].alternate_path));
      reply_size += (strlen(junction->referral_list[i].alternate_path)+1)*2;
    }

  DEBUG(10,("reply_size = %u\n",reply_size));
  /* add the unexplained 0x16 bytes */
  reply_size += 0x16;

  pdata = *ppdata = Realloc(pdata,reply_size);
  if(pdata == NULL)
    {
      DEBUG(0,("malloc failed for Realloc!\n"));
      return -1;
    }

  /* copy in the dfs requested paths.. required for offset calculations */
  memcpy(pdata+uni_reqpathoffset1,uni_requestedpath,requestedpathlen);
  memcpy(pdata+uni_reqpathoffset2,uni_requestedpath,requestedpathlen);


  /* create the header */
  SSVAL(pdata,0,requestedpathlen-2); /* path consumed */
  SSVAL(pdata,2,junction->referral_count); /* number of referral in this pkt */
  if(self_referral)
    SIVAL(pdata,4,DFSREF_REFERRAL_SERVER | DFSREF_STORAGE_SERVER); 
  else
    SIVAL(pdata,4,DFSREF_STORAGE_SERVER);

  offset = 8;
  /* add the referral elements */
  for(i=0;i<junction->referral_count;i++)
    {
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
      unilen = (dos_struni2(pdata+uni_curroffset,ref->alternate_path,512)
		+1)*2;
      SSVAL(pdata,offset+20,uni_curroffset-offset);
	    
      uni_curroffset += unilen;
      offset += VERSION2_REFERRAL_SIZE;
    }
  /* add in the unexplained 22 (0x16) bytes at the end */
  memset(pdata+uni_curroffset,'\0',0x16);
  free(junction->referral_list);
  return reply_size;
}

static int setup_ver3_dfs_referral(char* pathname, char** ppdata, 
				   struct junction_map* junction,
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

  reqpathlen = (dos_struni2(uni_reqpath,pathname,512)+1)*2;
	
  dump_data(10,uni_reqpath,reqpathlen);

  uni_reqpathoffset1 = REFERRAL_HEADER_SIZE + VERSION3_REFERRAL_SIZE *
    junction->referral_count;
  uni_reqpathoffset2 = uni_reqpathoffset1 + reqpathlen;
  reply_size = uni_curroffset = uni_reqpathoffset2 + reqpathlen;

  for(i=0;i<junction->referral_count;i++)
    {
      DEBUG(10,("referral %u : %s\n",i,junction->referral_list[i].alternate_path));
      reply_size += (strlen(junction->referral_list[i].alternate_path)+1)*2;
    }

  pdata = *ppdata = Realloc(pdata,reply_size);
  if(pdata == NULL)
    {
      DEBUG(0,("version3 referral setup: malloc failed for Realloc!\n"));
      return -1;
    }
	
  /* create the header */
  SSVAL(pdata,0,reqpathlen-2); /* path consumed */
  SSVAL(pdata,2,junction->referral_count); /* number of referral in this pkt */
  if(self_referral)
    SIVAL(pdata,4,DFSREF_REFERRAL_SERVER | DFSREF_STORAGE_SERVER); 
  else
    SIVAL(pdata,4,DFSREF_STORAGE_SERVER);
	
  /* copy in the reqpaths */
  memcpy(pdata+uni_reqpathoffset1,uni_reqpath,reqpathlen);
  memcpy(pdata+uni_reqpathoffset2,uni_reqpath,reqpathlen);
	
  offset = 8;
  for(i=0;i<junction->referral_count;i++)
    {
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
      unilen = (dos_struni2(pdata+uni_curroffset,ref->alternate_path,512)
		+1)*2;
      SSVAL(pdata,offset+16,uni_curroffset-offset);
      /* copy 0x10 bytes of 00's in the ServiceSite GUID */
      memset(pdata+offset+18,'\0',16);

      uni_curroffset += unilen;
      offset += VERSION3_REFERRAL_SIZE;
    }
  free(junction->referral_list);
  return reply_size;
}

/******************************************************************
 * Set up the Dfs referral for the dfs pathname
 ******************************************************************/
int setup_dfs_referral(char* pathname, int max_referral_level, 
			char** ppdata)
{
  struct dfs_path dp;
  
  struct junction_map junction;

  BOOL self_referral;

  int reply_size = 0;

  ZERO_STRUCT(junction);

  parse_dfs_path(pathname,&dp);

  /* check if path is dfs : check hostname is the first token */
  if(global_myname && (strcasecmp(global_myname,dp.hostname)!=0))
     {
       DEBUG(4,("setup_dfs_referral: Invalid DFS referral request for %s\n",
		pathname));
       return -1;
     }

  /* Check for a non-DFS share */
    if(!lp_msdfs_root(lp_servicenumber(dp.servicename)))
      {
	DEBUG(4,("setup_dfs_referral: %s is not an msdfs root.\n", 
		 dp.servicename));
	return -1;
      }

  pstrcpy(junction.service_name,dp.servicename);
  pstrcpy(junction.volume_name,dp.volumename);

  /* get the junction entry */
  if(!get_referred_path(&junction))
    {
      
      /* refer the same pathname, create a standard referral struct */
      struct referral* ref;
      self_referral = True;
      junction.referral_count = 1;
      if((ref = (struct referral*) malloc(sizeof(struct referral))) == NULL)
	{
	  DEBUG(0,("malloc failed for referral\n"));
	  return -1;
	}
      
      pstrcpy(ref->alternate_path,pathname);
      ref->proximity = 0;
      ref->ttl = REFERRAL_TTL;
      junction.referral_list = ref;
    }
  else
    {
      self_referral = False;
      if( DEBUGLVL( 3 ) )
	{
	  int i=0;
	  dbgtext("setup_dfs_referral: Path %s to alternate path(s):",pathname);
	  for(i=0;i<junction.referral_count;i++)
	    dbgtext(" %s",junction.referral_list[i].alternate_path);
	  dbgtext(".\n");
	}
    }
      
  /* create the referral depeding on version */
  DEBUG(10,("max_referral_level :%d\n",max_referral_level));
  if(max_referral_level<2 || max_referral_level>3) max_referral_level = 2;

  switch(max_referral_level)
    {
    case 2:
      {
	reply_size = setup_ver2_dfs_referral(pathname, ppdata, &junction,
					     self_referral);
	break;
      }
    case 3:
      {
	reply_size = setup_ver3_dfs_referral(pathname, ppdata, &junction,
					     self_referral);
	break;
      }
    default:
      {
	DEBUG(0,("setup_dfs_referral: Invalid dfs referral version: %d\n", 
		 max_referral_level));
	return -1;
      }
    }
      
  DEBUG(10,("DFS Referral pdata:\n"));
  dump_data(10,*ppdata,reply_size);
  return reply_size;
}


int dfs_path_error(char* inbuf, char* outbuf)
{
  enum remote_arch_types ra_type = get_remote_arch();
  BOOL NT_arch = ((ra_type==RA_WINNT) || (ra_type == RA_WIN2K));
  if(NT_arch && (global_client_caps & (CAP_NT_SMBS | CAP_STATUS32)) )
    {
      SSVAL(outbuf,smb_flg2,SVAL(outbuf,smb_flg2) | FLAGS2_32_BIT_ERROR_CODES);
      return(ERROR(0,0xc0000000|NT_STATUS_PATH_NOT_COVERED));
    }
  return(ERROR(ERRSRV,ERRbadpath)); 
}

#else
/* Stub functions if MS_DFS not defined */
int setup_dfs_referral(char* pathname, int max_referral_level, 
		       char** ppdata)
{
  return -1;
}

BOOL is_msdfs_volume(connection_struct* conn, char* path)
{
  return False;
}

#endif
