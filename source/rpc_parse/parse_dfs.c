#include "includes.h"
#include "nterr.h"
#include "rpc_parse.h"   

extern int DEBUGLEVEL;

/*************************************************************
 Read/write a DFS_R_DFS_EXIST structure
 ************************************************************/
BOOL dfs_io_r_dfs_exist(char *desc, DFS_R_DFS_EXIST *q_d, prs_struct *ps,
			int depth)
{
  if(q_d == NULL) return False;
  
  prs_debug(ps, depth, desc, "dfs_io_r_dfs_exist");
  depth++;

  prs_align(ps);

  prs_uint32("exist flag", ps, 0, &(q_d->dfs_exist_flag));
  return True;
}
  
/******************************************************************* 
Make a DFS_Q_DFS_REMOVE structure
*******************************************************************/
BOOL make_dfs_q_dfs_remove(DFS_Q_DFS_REMOVE *q_d, char *entrypath, 
			   char *servername, char *sharename)
{
  DEBUG(5,("make_dfs_q_dfs_remove\n"));
  make_unistr2(&(q_d->DfsEntryPath), entrypath,  strlen(entrypath)+1);
  make_unistr2(&(q_d->ServerName),   servername, strlen(servername)+1);
  make_unistr2(&(q_d->ShareName),    sharename,  strlen(sharename)+1);
  q_d->ptr_ServerName = q_d->ptr_ShareName = 1;
  return True;
}

/******************************************************************* 
Read/write a DFS_Q_DFS_REMOVE structure
*******************************************************************/
BOOL dfs_io_q_dfs_remove(char *desc, DFS_Q_DFS_REMOVE *q_d, prs_struct *ps,
			 int depth)
{
  if(q_d == NULL) return False;

  prs_debug(ps, depth, desc, "dfs_io_q_dfs_remove");
  depth++;
  
  prs_align(ps);
  
  smb_io_unistr2("DfsEntryPath",&(q_d->DfsEntryPath), 1, ps, depth);
  prs_align(ps);

  prs_uint32("ptr_ServerName", ps, depth, &(q_d->ptr_ServerName));
  smb_io_unistr2("ServerName",&(q_d->ServerName), 1, ps, depth);
  prs_align(ps);

  prs_uint32("ptr_ShareName", ps, depth, &(q_d->ptr_ShareName));
  smb_io_unistr2("ShareName",&(q_d->ShareName),  1, ps, depth);
  prs_align(ps);

  return True;
}

/******************************************************************* 
Read/write a DFS_R_DFS_REMOVE structure
*******************************************************************/
BOOL dfs_io_r_dfs_remove(char *desc, DFS_R_DFS_REMOVE *r_d, prs_struct *ps,
		      int depth)
{
  if(r_d == NULL) return False;

  prs_debug(ps, depth, desc, "dfs_io_r_dfs_remove");
  depth++;

  prs_uint32("status", ps, depth, &(r_d->status));

  return True;
}

/******************************************************************* 
Make a DFS_Q_DFS_ADD structure
*******************************************************************/
BOOL make_dfs_q_dfs_add(DFS_Q_DFS_ADD *q_d, char *entrypath, char *servername,
			char *sharename, char *comment, uint32 flags)
{
  DEBUG(5,("make_dfs_q_dfs_add\n"));
  q_d->ptr_DfsEntryPath = q_d->ptr_ServerName = q_d->ptr_ShareName = 1;
  make_unistr2(&(q_d->DfsEntryPath), entrypath,  strlen(entrypath)+1);
  make_unistr2(&(q_d->ServerName),   servername, strlen(servername)+1);
  make_unistr2(&(q_d->ShareName),    sharename,  strlen(sharename)+1);
  if(comment != NULL)
    {
      make_unistr2(&(q_d->Comment),      comment,    strlen(comment)+1);
      q_d->ptr_Comment = 1;
    }
  else
    {
      q_d->ptr_Comment = 0;
    }

  q_d->Flags = flags;
  return True;
}

/************************************************************
 Read/write a DFS_Q_DFS_ADD structure
 ************************************************************/
BOOL dfs_io_q_dfs_add(char *desc, DFS_Q_DFS_ADD *q_d, prs_struct *ps,
		      int depth)
{
  if(q_d == NULL) return False;

  prs_debug(ps, depth, desc, "dfs_io_q_dfs_add");
  depth++;
  
  prs_align(ps);
  
  smb_io_unistr2("DfsEntryPath",&(q_d->DfsEntryPath), 1, ps, depth);
  prs_align(ps);

  smb_io_unistr2("ServerName",&(q_d->ServerName), 1, ps, depth);
  prs_align(ps);

  prs_uint32("ptr_ShareName", ps, depth, &(q_d->ptr_ShareName));
  smb_io_unistr2("ShareName",&(q_d->ShareName),  1, ps, depth);
  prs_align(ps);

  prs_uint32("ptr_Comment", ps, depth, &(q_d->ptr_Comment));
  smb_io_unistr2("",&(q_d->Comment), q_d->ptr_Comment , ps, depth);
  prs_align(ps);

  prs_uint32("Flags", ps, depth, &(q_d->Flags));
  return True;
}

/************************************************************
 Read/write a DFS_R_DFS_ADD structure 
 ************************************************************/
BOOL dfs_io_r_dfs_add(char *desc, DFS_R_DFS_ADD *r_d, prs_struct *ps,
		      int depth)
{
  if(r_d == NULL) return False;

  prs_debug(ps, depth, desc, "dfs_io_r_dfs_add");
  depth++;

  prs_uint32("status", ps, depth, &(r_d->status));

  return True;
}

/************************************************************
 Make a DFS_Q_DFS_ENUM structure
 ************************************************************/
BOOL make_dfs_q_dfs_enum(DFS_Q_DFS_ENUM *q_d, uint32 level, DFS_INFO_CTR *ctr)
{
  q_d->level = level;
  q_d->maxpreflen = -1;
  q_d->ptr_buffer = 1;
  q_d->level2 = level;
  
  q_d->ptr_num_entries = 1;
  q_d->num_entries = 0;
  q_d->num_entries2 = 0;
  q_d->reshnd.ptr_hnd = 1;
  q_d->reshnd.handle = 0;
  return True;
}
  
/************************************************************
 Read or write the DFS_Q_DFS_ENUM structure 
 ************************************************************/
BOOL dfs_io_q_dfs_enum(char *desc, DFS_Q_DFS_ENUM *q_d, prs_struct *ps,
		      int depth)
{
  if(q_d == NULL) return False;

  prs_debug(ps, depth, desc, "dfs_io_q_dfs_enum");
  depth++;
  
  prs_align(ps);
  
  prs_uint32("level", ps, depth, &(q_d->level));
  prs_uint32("maxpreflen", ps, depth, &(q_d->maxpreflen));
  prs_uint32("ptr_buffer", ps, depth, &(q_d->ptr_buffer));
  prs_uint32("level2", ps, depth, &(q_d->level2));
  prs_uint32("level3", ps, depth, &(q_d->level2));
  
  prs_uint32("ptr_num_entries", ps, depth, &(q_d->ptr_num_entries));
  prs_uint32("num_entries", ps, depth, &(q_d->num_entries));
  prs_uint32("num_entries2", ps, depth, &(q_d->num_entries2));
  smb_io_enum_hnd("resume_hnd",&(q_d->reshnd), ps, depth);
  return True;
}

/************************************************************
 Read/write a DFS_R_DFS_ENUM structure
 ************************************************************/
BOOL dfs_io_r_dfs_enum(char *desc, DFS_R_DFS_ENUM *q_d, prs_struct *ps, int depth)
{
  DFS_INFO_CTR *ctr;
  if(q_d == NULL) return False;
  ctr = q_d->ctr;
  if(ctr == NULL) return False;

  prs_debug(ps, depth, desc, "dfs_io_r_dfs_enum");
  depth++;

  prs_align(ps);

  prs_uint32("ptr_buffer", ps, depth, &(q_d->ptr_buffer));
  prs_uint32("level", ps, depth, &(q_d->level));
  prs_uint32("level2", ps, depth, &(ctr->switch_value));
  prs_uint32("ptr_num_entries", ps, depth, &(q_d->ptr_num_entries));
  if(q_d->ptr_num_entries)
    prs_uint32("num_entries", ps, depth, &(q_d->num_entries));
  prs_uint32("ptr_num_entries2", ps, depth, &(q_d->ptr_num_entries2));
  if(q_d->ptr_num_entries2)
    prs_uint32("num_entries2", ps, depth, &(ctr->num_entries));

  switch(q_d->level)
    {
    case 1:
      {
	int i=0;
	
	depth++;
	/* should depend on whether marshalling or unmarshalling! */
	if(UNMARSHALLING(ps))
	   ctr->dfs.info1 = g_new0(DFS_INFO_1, q_d->num_entries);

	for(i=0;i<q_d->num_entries;i++)
	  {
	    prs_uint32("ptr_entrypath",ps, depth, &(ctr->dfs.info1[i].ptr_entrypath));
	  }
	for(i=0;i<q_d->num_entries;i++)
	  {
	    smb_io_unistr2("", &(ctr->dfs.info1[i].entrypath), 
			   ctr->dfs.info1[i].ptr_entrypath,
			   ps, depth);
	    prs_align(ps);
	  }
	depth--;
	break;
      }
    case 2:
      {
	int i=0;
	depth++;
	if(UNMARSHALLING(ps))
	  ctr->dfs.info2 = g_new0(DFS_INFO_2, q_d->num_entries);

	for(i=0;i<q_d->num_entries;i++)
	  {
	    prs_uint32("ptr_entrypath", ps, depth, 
		       &(ctr->dfs.info2[i].ptr_entrypath));
	    prs_uint32("ptr_comment", ps, depth, 
		       &(ctr->dfs.info2[i].ptr_comment));
	    prs_uint32("state", ps, depth, &(ctr->dfs.info2[i].state));
	    prs_uint32("num_storages", ps, depth, 
		       &(ctr->dfs.info2[i].num_storages));
	  }
	for(i=0;i<q_d->num_entries;i++)
	  {
	    smb_io_unistr2("", &(ctr->dfs.info2[i].entrypath),
			   ctr->dfs.info2[i].ptr_entrypath, ps, depth);
	    smb_io_unistr2("",&(ctr->dfs.info2[i].comment),
			   ctr->dfs.info2[i].ptr_comment, ps, depth);
	  }
	depth--;
	break;
      }
    case 3:
      {
	int i=0;
	depth++;
	if(UNMARSHALLING(ps))
	  ctr->dfs.info3 = g_new0(DFS_INFO_3, q_d->num_entries);

	for(i=0;i<q_d->num_entries;i++)
	  {
	    prs_uint32("ptr_entrypath", ps, depth, 
		       &(ctr->dfs.info3[i].ptr_entrypath));
	    prs_uint32("ptr_comment", ps, depth,
		       &(ctr->dfs.info3[i].ptr_comment));
	    prs_uint32("state", ps, depth, &(ctr->dfs.info3[i].state));
	    prs_uint32("num_storages", ps, depth,
		       &(ctr->dfs.info3[i].num_storages));
	    prs_uint32("ptr_storages", ps, depth,
		       &(ctr->dfs.info3[i].ptr_storages));
	  }
	for(i=0;i<q_d->num_entries;i++)
	  {
	    smb_io_unistr2("", &(ctr->dfs.info3[i].entrypath),
			   ctr->dfs.info3[i].ptr_entrypath, ps, depth);
	    prs_align(ps);
	    smb_io_unistr2("", &(ctr->dfs.info3[i].comment),
			   ctr->dfs.info3[i].ptr_comment, ps, depth);
	    prs_align(ps);
	    prs_uint32("num_storage_infos", ps, depth, 
		   &(ctr->dfs.info3[i].num_storage_infos));
	    if(!smb_io_dfs_storage_info("storage_info",
				       &(ctr->dfs.info3[i]), 
				       ps, depth))
	      return False;
	  }
      }
    }

  smb_io_enum_hnd("resume_hnd", &(q_d->reshnd), ps, depth);
  prs_uint32("status", ps, depth, &(q_d->status));
  return True;
}

BOOL smb_io_dfs_storage_info(char *desc, DFS_INFO_3* info3,
			     prs_struct *ps, int depth)
{
  int i=0;
  if(info3 == NULL) return False;
  
  prs_debug(ps, depth, desc, "smb_io_dfs_storage_info");
  depth++;

  if(UNMARSHALLING(ps))
    info3->storages = g_new0(DFS_STORAGE_INFO, info3->num_storage_infos);

  for(i=0;i<info3->num_storage_infos;i++)
    {
      prs_uint32("storage_state", ps, depth, &(info3->storages[i].state));
      prs_uint32("ptr_servername", ps, depth, 
		 &(info3->storages[i].ptr_servername));
      prs_uint32("ptr_sharename", ps, depth,
		 &(info3->storages[i].ptr_sharename));
    }
  for(i=0;i<info3->num_storage_infos;i++)
    {
      smb_io_unistr2("servername", &(info3->storages[i].servername),
		     info3->storages[i].ptr_servername, ps, depth);
      prs_align(ps);
      smb_io_unistr2("sharename", &(info3->storages[i].sharename),
		     info3->storages[i].ptr_sharename, ps, depth);
      prs_align(ps);
    }
  return True;
}
      

  
