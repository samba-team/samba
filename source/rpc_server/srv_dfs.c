
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines for Dfs
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Shirish Kalele               2000.
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

#define MAX_MSDFS_JUNCTIONS 256

extern int DEBUGLEVEL;
extern pstring global_myname;

#ifdef WITH_MSDFS

/**********************************************************************
 api_dfs_exist
 **********************************************************************/
static BOOL api_dfs_exist( prs_struct *data,
			   prs_struct *rdata)
{
  DFS_R_DFS_EXIST r_d;

  if(lp_host_msdfs()) 
    r_d.dfs_exist_flag = 1;
  else
    r_d.dfs_exist_flag = 0; 

  return dfs_io_r_dfs_exist("", &r_d, rdata, 0);
}

static uint32 init_reply_dfs_add(DFS_Q_DFS_ADD* q_a)
{
  struct junction_map jn;
  struct referral* old_referral_list = NULL;
  BOOL exists = False;

  pstring dfspath, servername, sharename;
  pstring altpath;

  unistr2_to_ascii(dfspath, &(q_a->DfsEntryPath), sizeof(dfspath)-1);
  unistr2_to_ascii(servername, &(q_a->ServerName), sizeof(servername)-1);
  unistr2_to_ascii(sharename, &(q_a->ShareName), sizeof(sharename)-1);

  DEBUG(5,("init_reply_dfs_add: Request to add %s -> %s\\%s.\n",
	   dfspath, servername, sharename));

  pstrcpy(altpath, servername);
  pstrcat(altpath, "\\");
  pstrcat(altpath, sharename);

  if(!create_junction(dfspath, &jn))
    return NERR_DfsNoSuchServer;

  if(get_referred_path(&jn))
    {
      exists = True;
      jn.referral_count += 1;
      old_referral_list = jn.referral_list;
    }
  else
    jn.referral_count = 1;

  jn.referral_list = (struct referral*) malloc(jn.referral_count 
					       * sizeof(struct referral));

  if(jn.referral_list == NULL)
    {
      DEBUG(0,("init_reply_dfs_add: malloc failed for referral list!\n"));
      return NERR_DfsInternalError;
    }

  if(old_referral_list)
    {
      memcpy(jn.referral_list, old_referral_list, 
	     sizeof(struct referral)*jn.referral_count-1);
      free(old_referral_list);
    }
  
  jn.referral_list[jn.referral_count-1].proximity = 0;
  jn.referral_list[jn.referral_count-1].ttl = REFERRAL_TTL;

  pstrcpy(jn.referral_list[jn.referral_count-1].alternate_path, altpath);
  
  if(!create_msdfs_link(&jn, exists))
    return NERR_DfsCantCreateJunctionPoint;

  return 0;
}
/*****************************************************************
 api_dfs_add
 *****************************************************************/
static BOOL api_dfs_add(prs_struct* data, prs_struct* rdata)
{
  DFS_Q_DFS_ADD q_a;
  DFS_R_DFS_ADD r_a;

  if(!dfs_io_q_dfs_add("", &q_a, data, 0))
    return False;
  
  r_a.status = init_reply_dfs_add(&q_a);

  dfs_io_r_dfs_add("", &r_a, rdata, 0);

  return True;
}

static uint32 init_reply_dfs_remove(DFS_Q_DFS_REMOVE* q_r)
{
  struct junction_map jn;
  BOOL found = False;

  pstring dfspath, servername, sharename;
  pstring altpath;

  unistr2_to_ascii(dfspath, &(q_r->DfsEntryPath), sizeof(dfspath)-1);
  if(q_r->ptr_ServerName)
    unistr2_to_ascii(servername, &(q_r->ServerName), sizeof(servername)-1);

  if(q_r->ptr_ShareName)
    unistr2_to_ascii(sharename, &(q_r->ShareName), sizeof(sharename)-1);

  if(q_r->ptr_ServerName && q_r->ptr_ShareName)
    {
      pstrcpy(altpath, servername);
      pstrcat(altpath, "\\");
      pstrcat(altpath, sharename);
    }

  DEBUG(5,("init_reply_dfs_remove: Request to remove %s -> %s\\%s.\n",
	   dfspath, servername, sharename));

  if(!create_junction(dfspath, &jn))
    return NERR_DfsNoSuchServer;

  if(!get_referred_path(&jn))
    return NERR_DfsNoSuchVolume;

  /* if no server-share pair given, remove the msdfs link completely */
  if(!q_r->ptr_ServerName && !q_r->ptr_ShareName)
    {
      if(!remove_msdfs_link(&jn))
	return NERR_DfsNoSuchVolume;
    }
  else
    {
      int i=0;
      /* compare each referral in the list with the one to remove */
      for(i=0;i<jn.referral_count;i++)
	{
	  pstring refpath;
	  pstrcpy(refpath,jn.referral_list[i].alternate_path);
	  trim_string(refpath, "\\", "\\");
	  if(strequal(refpath, altpath))
	    {
	      *(jn.referral_list[i].alternate_path)='\0';
	      found = True;
	    }
	}
      if(!found)
	return NERR_DfsNoSuchShare;
      
      /* Only one referral, remove it */
      if(jn.referral_count == 1)
	{
	  if(!remove_msdfs_link(&jn))
	    return NERR_DfsNoSuchVolume;
	}
      else
	{
	  if(!create_msdfs_link(&jn, True))
	    return NERR_DfsCantCreateJunctionPoint;
	}
    }

  return 0;
}

/*****************************************************************
 api_dfs_remove
 *****************************************************************/
static BOOL api_dfs_remove(prs_struct* data, prs_struct* rdata)
{
  DFS_Q_DFS_REMOVE q_r;
  DFS_R_DFS_REMOVE r_r;

  if(!dfs_io_q_dfs_remove("", &q_r, data, 0))
    return False;

  r_r.status = init_reply_dfs_remove(&q_r);

  dfs_io_r_dfs_remove("", &r_r, rdata, 0);

  return True;
}

static BOOL init_reply_dfs_info_1(struct junction_map* j, DFS_INFO_1* dfs1, int num_j)
{
  int i=0;
  for(i=0;i<num_j;i++) 
    {
      pstring str;
      dfs1[i].ptr_entrypath = 1;
      slprintf(str, sizeof(pstring)-1, "\\\\%s\\%s\\%s", global_myname, 
	       j[i].service_name, j[i].volume_name);
      DEBUG(5,("init_reply_dfs_info_1: %d) initing entrypath: %s\n",i,str));
      init_unistr2(&dfs1[i].entrypath,str,strlen(str)+1);
    }
  return True;
}

static BOOL init_reply_dfs_info_2(struct junction_map* j, DFS_INFO_2* dfs2, int num_j)
{
  int i=0;
  for(i=0;i<num_j;i++)
    {
      pstring str;
      dfs2[i].ptr_entrypath = 1;
      slprintf(str, sizeof(pstring)-1, "\\\\%s\\%s\\%s", global_myname,
	       j[i].service_name, j[i].volume_name);
      init_unistr2(&dfs2[i].entrypath, str, strlen(str)+1);
      dfs2[i].ptr_comment = 0;
      dfs2[i].state = 1; /* set up state of dfs junction as OK */
      dfs2[i].num_storages = j[i].referral_count;
    }
  return True;
}

static BOOL init_reply_dfs_info_3(struct junction_map* j, DFS_INFO_3* dfs3, int num_j)
{
  int i=0,ii=0;
  for(i=0;i<num_j;i++)
    {
      pstring str;
      dfs3[i].ptr_entrypath = 1;
      slprintf(str, sizeof(pstring)-1, "\\\\%s\\%s\\%s", global_myname,
	       j[i].service_name, j[i].volume_name);
      init_unistr2(&dfs3[i].entrypath, str, strlen(str)+1);
      dfs3[i].ptr_comment = 1;
      init_unistr2(&dfs3[i].comment, "", 1); 
      dfs3[i].state = 1;
      dfs3[i].num_storages = dfs3[i].num_storage_infos = j[i].referral_count;
      dfs3[i].ptr_storages = 1;
     
      /* also enumerate the storages */
      dfs3[i].storages = (DFS_STORAGE_INFO*) malloc(j[i].referral_count * 
						    sizeof(DFS_STORAGE_INFO));
      for(ii=0;ii<j[i].referral_count;ii++)
	{
	  char* p; 
	  pstring path;
	  DFS_STORAGE_INFO* stor = &(dfs3[i].storages[ii]);
	  struct referral* ref = &(j[i].referral_list[ii]);
	  
	  pstrcpy(path, ref->alternate_path);
	  trim_string(path,"\\","");
	  p = strrchr(path,'\\');
	  if(p==NULL)
	    {
	      DEBUG(4,("init_reply_dfs_info_3: invalid path: no \\ found in %s\n",path));
	      continue;
	    }
	  *p = '\0';
	  DEBUG(5,("storage %d: %s.%s\n",ii,path,p+1));
	  stor->state = 2; /* set all storages as ONLINE */
	  init_unistr2(&stor->servername, path, strlen(path)+1);
	  init_unistr2(&stor->sharename,  p+1, strlen(p+1)+1);
	  stor->ptr_servername = stor->ptr_sharename = 1;
	}
    }
  return True;
}

static uint32 init_reply_dfs_ctr(uint32 level, DFS_INFO_CTR* ctr, 
			       struct junction_map* jn, int num_jn)
{
  /* do the levels */
  switch(level)
    {
    case 1:
      {
	DFS_INFO_1* dfs1;
	dfs1 = (DFS_INFO_1*) malloc(num_jn * sizeof(DFS_INFO_1));
	init_reply_dfs_info_1(jn, dfs1, num_jn);
	ctr->dfs.info1 = dfs1;
	break;
      }
    case 2:
      {
	DFS_INFO_2* dfs2;
	dfs2 = (DFS_INFO_2*) malloc(num_jn * sizeof(DFS_INFO_2));
	init_reply_dfs_info_2(jn, dfs2, num_jn);
	ctr->dfs.info2 = dfs2;
	break;
      }
    case 3:
      {
	DFS_INFO_3* dfs3;
	dfs3 = (DFS_INFO_3*) malloc(num_jn * sizeof(DFS_INFO_3));
	init_reply_dfs_info_3(jn, dfs3, num_jn);
	ctr->dfs.info3 = dfs3;
      }
    }
  return 0;
}
      
static uint32 init_reply_dfs_enum(uint32 level, DFS_R_DFS_ENUM *q_r)
{
  struct junction_map jn[MAX_MSDFS_JUNCTIONS];
  int num_jn = 0;
  int i=0;

  num_jn = enum_msdfs_links(jn);
  
  DEBUG(5,("make_reply_dfs_enum: %d junctions found in Dfs, doing level %d\n",
	   num_jn, level));

  q_r->ptr_buffer = level;
  q_r->level = q_r->level2 = level;
  q_r->ptr_num_entries = q_r->ptr_num_entries2 = 1;
  q_r->num_entries = q_r->num_entries2 = num_jn;
  q_r->reshnd.ptr_hnd = 1;
  q_r->reshnd.handle = num_jn;
  
  q_r->ctr = (DFS_INFO_CTR*) malloc(sizeof(DFS_INFO_CTR));
  q_r->ctr->switch_value = level;
  q_r->ctr->num_entries = num_jn;
  q_r->ctr->ptr_dfs_ctr = 1;
  
  init_reply_dfs_ctr(level, q_r->ctr, jn, num_jn);

  for(i=0;i<num_jn;i++)
    free(jn[i].referral_list);

  return 0;
}
      
static uint32 init_reply_dfs_get_info(UNISTR2* uni_path, uint32 level,  
				      DFS_R_DFS_GET_INFO* r_i)
{
  pstring path;
  struct junction_map jn;

  unistr2_to_ascii(path, uni_path, sizeof(path)-1);
  if(!create_junction(path, &jn))
     return NERR_DfsNoSuchServer;
  
  if(!get_referred_path(&jn))
    return NERR_DfsNoSuchVolume;

  r_i->level = level;
  r_i->ptr_ctr = 1;
  r_i->status = init_reply_dfs_ctr(level, &(r_i->ctr), &jn, 1);
  
  free(jn.referral_list);
  return 0;
}
/*******************************************************************
 api_dfs_get_info
 *******************************************************************/
static BOOL api_dfs_get_info(prs_struct* data, prs_struct* rdata)
{
  DFS_Q_DFS_GET_INFO q_i;
  DFS_R_DFS_GET_INFO r_i;

  ZERO_STRUCT(r_i);

  if(!dfs_io_q_dfs_get_info("", &q_i, data, 0))
    return False;

  r_i.status = init_reply_dfs_get_info(&q_i.uni_path, q_i.level, &r_i);

  if(!dfs_io_r_dfs_get_info("", &r_i, rdata, 0))
    return False;

  switch(r_i.level) {
  case 1: free(r_i.ctr.dfs.info1); break;
  case 2: free(r_i.ctr.dfs.info2); break;
  case 3: 
    {
      free(r_i.ctr.dfs.info3->storages);
      free(r_i.ctr.dfs.info3);
      break;
    }
  }
  return True;
}

/*******************************************************************
 api_dfs_enum
 *******************************************************************/
static BOOL api_dfs_enum(prs_struct* data, prs_struct* rdata)
{
  DFS_Q_DFS_ENUM q_e;
  DFS_R_DFS_ENUM q_r;

  if(!dfs_io_q_dfs_enum("", &q_e, data, 0))
    return False;

  q_r.status = init_reply_dfs_enum(q_e.level, &q_r);

  if(!dfs_io_r_dfs_enum("", &q_r, rdata, 0))
      return False;
  switch(q_e.level) {
  case 1: 
    free(q_r.ctr->dfs.info1); break;
  case 2:
    free(q_r.ctr->dfs.info2); break;
  case 3:
    free(q_r.ctr->dfs.info3->storages); free(q_r.ctr->dfs.info3); break;
  }
  free(q_r.ctr);
  return True;
}

/*******************************************************************
\pipe\netdfs commands
********************************************************************/
struct api_struct api_netdfs_cmds[] =
{
  {"DFS_EXIST",        DFS_EXIST,               api_dfs_exist    },
  {"DFS_ADD",          DFS_ADD,                 api_dfs_add      },
  {"DFS_REMOVE",       DFS_REMOVE,              api_dfs_remove   },
  {"DFS_GET_INFO",     DFS_GET_INFO,            api_dfs_get_info },
  {"DFS_ENUM",         DFS_ENUM,                api_dfs_enum     },
  {NULL,                      0,                NULL             }
};

/*******************************************************************
receives a netdfs pipe and responds.
********************************************************************/
BOOL api_netdfs_rpc(pipes_struct *p, prs_struct *data)
{
	return api_rpcTNP(p, "api_netdfs_rpc", api_netdfs_cmds, data); 
}

#endif
