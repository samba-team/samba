#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;  

/* Called by all dfs operations to verify if a dfs_root exists at server */
static BOOL _dfs_exist(struct cli_connection *con)
{
  prs_struct buf;
  prs_struct rbuf;
  DFS_R_DFS_EXIST q_d;
  
  prs_init(&buf, 0, 4, False);
  prs_init(&rbuf, 0 ,4, True);
  
  /* make a null request */
  if(!rpc_con_pipe_req(con, DFS_EXIST, &buf, &rbuf))
    {
      DEBUG(5,("Null request unsuccessful!\n"));
      prs_free_data(&rbuf);
      cli_connection_unlink(con);
      return False;
    }
  if(!dfs_io_r_dfs_exist("", &q_d, &rbuf, 0))
    return False;

  prs_free_data(&rbuf);
  return q_d.dfs_exist_flag;
}

BOOL dfs_remove(char *srv_name, char *dfs_entrypath, char *dfs_servername, 
		char *dfs_sharename)
{
  prs_struct rbuf;
  prs_struct buf;
  BOOL valid_cfg= False;
  DFS_Q_DFS_REMOVE q_d;
  struct cli_connection *con=NULL;

  prs_init(&buf, 0, 4, False);
  prs_init(&rbuf, 0 ,4, True);
  if (!cli_connection_init(srv_name, PIPE_NETDFS, &con))
    return False;

  /* check if server is a dfs server */
  if(!_dfs_exist(con))
    {
      DEBUG(5,("dfs_remove: No Dfs root at \\\\%s\n",srv_name));
      return False;
    }

  /* store the parameters */
  make_dfs_q_dfs_remove(&q_d, dfs_entrypath, dfs_servername, dfs_sharename);

  /* turn parameters into data stream */
  if(dfs_io_q_dfs_remove("", &q_d, &buf, 0) &&
     rpc_con_pipe_req(con, DFS_REMOVE, &buf, &rbuf))
    {
      DFS_R_DFS_REMOVE r_d;
      BOOL p;
      ZERO_STRUCT(r_d);
      
      dfs_io_r_dfs_remove("", &r_d, &rbuf, 0);
      p = (rbuf.offset != 0);
      
      if(p && r_d.status!=0)
	{
	  DEBUG(1,("DFS_REMOVE: %s\n",get_nt_error_msg(r_d.status)));
	  p = False;
	}
      
      if(p)
	valid_cfg = True;
    }
  prs_free_data(&rbuf);
  prs_free_data(&buf);
  cli_connection_unlink(con);
  return valid_cfg;
}

BOOL dfs_add(char *srv_name, char* entrypath, char* servername, char* sharename, char* comment)
{
  prs_struct rbuf;
  prs_struct buf;
  BOOL valid_cfg= False;
  DFS_Q_DFS_ADD q_d;
  struct cli_connection *con=NULL;

  prs_init(&buf, 0, 4, False);
  prs_init(&rbuf, 0 ,4, True);
  if (!cli_connection_init(srv_name, PIPE_NETDFS, &con))
    return False;

  if(!_dfs_exist(con))
    {
      DEBUG(5,("dfs_add: No Dfs root at \\\\%s\n",srv_name));
     return False;
    }

  /* store the parameters */
  make_dfs_q_dfs_add(&q_d, entrypath, servername, sharename, comment, 
		     DFSFLAG_ADD_VOLUME);

  /* turn parameters into data stream */
  if(dfs_io_q_dfs_add("", &q_d, &buf, 0) &&
     rpc_con_pipe_req(con, DFS_ADD, &buf, &rbuf))
    {
      DFS_R_DFS_ADD r_d;
      BOOL p;
      ZERO_STRUCT(r_d);
      
      dfs_io_r_dfs_add("", &r_d, &rbuf, 0);
      p = (rbuf.offset != 0);
      
      if(p && r_d.status!=0)
	{
	  DEBUG(1,("DFS_ADD: %s\n",get_nt_error_msg(r_d.status)));
	  p = False;
	}
      
      if(p)
	valid_cfg = True;
    }
  prs_free_data(&rbuf);
  prs_free_data(&buf);
  cli_connection_unlink(con);
  return valid_cfg;
}
	    
uint32 dfs_enum(char *srv_name, uint32 level, DFS_INFO_CTR *ctr)
{
  prs_struct rbuf;
  prs_struct buf;
  BOOL valid_cfg= False;
  DFS_Q_DFS_ENUM q_d;
  uint32 res = NT_STATUS_UNSUCCESSFUL;

  struct cli_connection *con=NULL;

  prs_init(&buf, 0, 4, False);
  prs_init(&rbuf, 0 ,4, True);
  if (!cli_connection_init(srv_name, PIPE_NETDFS, &con))
    return NT_STATUS_PIPE_NOT_AVAILABLE;

  if(!_dfs_exist(con))
    {
      DEBUG(5,("dfs_add: No Dfs root at \\\\%s\n",srv_name));
     return NT_STATUS_OBJECT_PATH_NOT_FOUND;
    }

  /* store the parameters */
  make_dfs_q_dfs_enum(&q_d, level, ctr);
 
  /* turn parameters into data stream */
  if(dfs_io_q_dfs_enum("", &q_d, &buf, 0) &&
     rpc_con_pipe_req(con, DFS_ENUM, &buf, &rbuf))
    {
      DFS_R_DFS_ENUM r_d;
      BOOL p;
      ZERO_STRUCT(r_d);
      
      r_d.ctr = ctr;
      dfs_io_r_dfs_enum("", &r_d, &rbuf, 0);
      p = (rbuf.offset != 0);
      
      if(p && r_d.status!=0)
	{
	  DEBUG(1,("DFS_ENUM: %s\n",get_nt_error_msg(r_d.status)));
	  res = r_d.status;
	  p = False;
	}
      
      if(p)
	valid_cfg = True;
    }
  prs_free_data(&rbuf);
  prs_free_data(&buf);
  cli_connection_unlink(con);
  if(valid_cfg)
    return 0;
  else
    return res;
}

