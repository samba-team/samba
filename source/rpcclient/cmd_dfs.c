#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "nterr.h"
#include "rpc_parse.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern FILE* out_hnd;

extern struct user_creds *usr_creds;

void cmd_dfs_add(struct client_info *info, int argc, char *argv[])
{
  fstring srv_name;
  char *entrypath, *servername, *sharename, *comment=NULL;

  /* parse out the args */
  if(argc < 4)
    {
      report(out_hnd, "dfsadd Dfspath storage_server share [\"comment\"]\n");
      return;
    }

  fstrcpy(srv_name,"\\\\");
  fstrcat(srv_name, info->dest_host);
  strupper(srv_name);

  entrypath = argv[1];
  servername = argv[2];
  sharename = argv[3];
  if(argc > 4)
    comment = argv[4];

  DEBUG(5,("Adding Dfs path: %s\n(physically located at \\\\%s\\%s\n",entrypath,
	   servername,sharename));
  
  if(!dfs_add(srv_name, entrypath, servername, sharename, comment))
    {
      report(out_hnd, "dfsadd: Unable to add dfs share\n");
      return;
    }
  else
    {
      report(out_hnd, "dfsadd: Successfully added dfs share\n");
      return;
    }
}

void cmd_dfs_remove(struct client_info *info, int argc, char *argv[])
{
  fstring srv_name;
  char *dfs_entrypath, *dfs_servername, *dfs_sharename;
  
  if(argc != 4)
    {
      report(out_hnd, "dfsremove Dfspath storage_server share\n");
      return;
    }

  fstrcpy(srv_name, "\\\\");
  fstrcat(srv_name, info->dest_host);
  strupper(srv_name);

  dfs_entrypath = argv[1];
  dfs_servername = argv[2];
  dfs_sharename = argv[3];

  DEBUG(5,("Removing Dfs path: %s\n[physically located at \\\\%s\\%s\n",
	 dfs_entrypath, dfs_servername, dfs_sharename));
  
  if(!dfs_remove(srv_name, dfs_entrypath, dfs_servername, dfs_sharename))
    {
      report(out_hnd, "dfsremove: Unsuccessful!\n");
      return;
    }
  else
    {
      report(out_hnd, "dfsremove: Removed.\n");
      return;
    }
}

void display_dfs_enum_1(FILE *hnd, DFS_INFO_CTR *ctr)
{
  int i=0;
  for(i=0;i<ctr->num_entries;i++)
    {
      fstring path;
      UNISTR2 *unipath = &(ctr->dfs.info1[i].entrypath);
      unistr2_to_ascii(path, unipath, sizeof(path)-1);
      report(hnd, "Path: %s\n",path);
    }
  free(ctr->dfs.info1);
}

void display_dfs_enum_2(FILE *hnd, DFS_INFO_CTR *ctr)
{
  int i=0;
  for(i=0;i<ctr->num_entries;i++)
    {
      fstring path, comment;
      fstring state;
      UNISTR2 *unipath = &(ctr->dfs.info2[i].entrypath);
      UNISTR2 *unicomment = &(ctr->dfs.info2[i].comment);
      unistr2_to_ascii(path, unipath, sizeof(path)-1);
      unistr2_to_ascii(comment, unicomment, sizeof(comment)-1);
      
      report(hnd, "Path: %s\n",path);
      if(*comment)
	report(hnd, "Comment: [%s]\n",comment);
	
      switch(ctr->dfs.info2[i].state)
	{
	case 1: fstrcpy(state, "OK"); break;
	case 2: fstrcpy(state, "INCONSISTENT"); break;
	case 3: fstrcpy(state, "OFFLINE"); break;
	case 4: fstrcpy(state, "ONLINE"); break;
	default: fstrcpy(state, "UNKNOWN"); break;
	}
      report(hnd, "State: %s Number of storages: %u\n\n",state,
	     ctr->dfs.info2[i].num_storages);
    }
  free(ctr->dfs.info2);
}

void display_dfs_enum_3_storages(FILE *hnd, DFS_INFO_3 *info3)
{
  int i=0;
  if((info3 == NULL) || (info3->storages==NULL))
    return;

  for(i=0;i<info3->num_storages;i++)
    {
      DFS_STORAGE_INFO *stor = &(info3->storages[i]);
      fstring servername, sharename,storagepath;
      unistr2_to_ascii(servername, &(stor->servername), sizeof(servername)-1);
      unistr2_to_ascii(sharename, &(stor->sharename), sizeof(sharename)-1);
      fstrcpy(storagepath,"\\\\");
      fstrcat(storagepath,servername);
      fstrcat(storagepath,"\\");
      fstrcat(storagepath,sharename);
      
      report(hnd, "     Storage %1u: %-33s[%s] \n",i+1, storagepath,
	     (stor->state==2?"ONLINE":"OFFLINE"));
    }
}
void display_dfs_enum_3(FILE *hnd, DFS_INFO_CTR *ctr)
{
  int i=0;

  for(i=0;i<ctr->num_entries;i++)
    {
      fstring path, comment;
      fstring state;
      UNISTR2 *unipath = &(ctr->dfs.info3[i].entrypath);
      UNISTR2 *unicomment = &(ctr->dfs.info3[i].comment);
      unistr2_to_ascii(path, unipath, sizeof(path)-1);
      unistr2_to_ascii(comment, unicomment, sizeof(comment)-1);

      switch(ctr->dfs.info3[i].state)
	{
	case 1: fstrcpy(state, "OK"); break;
	case 2: fstrcpy(state, "INCONSISTENT"); break;
	case 3: fstrcpy(state, "OFFLINE"); break;
	case 4: fstrcpy(state, "ONLINE"); break;
	default: fstrcpy(state, "UNKNOWN"); break;
	}

      report(hnd, "Dfs path:%-40sState: %s\n",path,state);
      if(*comment)
	report(hnd, "Comment: [%s]\n",comment);

      display_dfs_enum_3_storages(hnd, &(ctr->dfs.info3[i]));
      report(hnd,"\n");
    }
  free(ctr->dfs.info3);
}
void display_dfs_enum(FILE *hnd, char *srv_name, DFS_INFO_CTR *ctr)
{
  /* print header */
  report(hnd, "\tDfs Namespace at %s [Info level %u]\n\n",srv_name, 
	 ctr->switch_value);
  switch(ctr->switch_value)
    {
    case 1:
      display_dfs_enum_1(hnd, ctr);
      break;
    case 2:
      display_dfs_enum_2(hnd, ctr);
      break;
    case 3:
      display_dfs_enum_3(hnd, ctr);
      break;
    default:
      report(hnd, "\tUnknown info level [%u]\n",ctr->switch_value);
    }
  report(hnd, "\n");
}

/****************************************************************************
 DFS enum query
 ****************************************************************************/
void cmd_dfs_enum(struct client_info *info, int argc, char *argv[])
{
  fstring srv_name;
  DFS_INFO_CTR ctr;
  uint32 info_level = 3;
  uint32 res=0;
  fstrcpy(srv_name,"\\\\");
  fstrcat(srv_name, info->dest_host);
  strupper(srv_name);

  if(argc > 2)
    {
      report(out_hnd, "dfsenum [1,2,3]\n");
      return;
    }
  
  if(argc == 2)
    info_level = (uint32)strtol(argv[1], (char**)NULL, 10); 
  
  if(info_level<1 || info_level>3)
    {
      report(out_hnd, "dfsenum [1,2,3]\n");
      return;
    }
  DEBUG(5,("cmd_dfs_enum: info_level: %u query\n",info_level));

  res = dfs_enum(srv_name, info_level, &ctr);
  if(res==0)
    {
      DEBUG(5,("cmd_dfs_enum: query succeeded\n"));
      display_dfs_enum(out_hnd, srv_name, &ctr);
    }
  else
    report(out_hnd, "FAILED: %s\n",get_nt_error_msg(res)); 
}

    
