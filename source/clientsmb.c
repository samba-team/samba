/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell 1994-1997
   
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


extern pstring debugf;
extern int DEBUGLEVEL;

extern file_info def_finfo;

static pstring cd_path="";

struct cli_state smb_cli;
int smb_tidx = -1;

#define CNV_LANG(s) dos2unix_format(s,False)
#define CNV_INPUT(s) unix2dos_format(s,True)


/***************************************************************************
 checks that the smb connection is still open
 ****************************************************************************/
void client_check_connection(void)
{
#ifdef CLIX
	static int delay = 0;
	delay++;
	if (delay > 100000)
	{
	  delay = 0;
	  cli_chkpath(&smb_cli, smb_tidx, "\\");
	}
#else
      cli_chkpath(&smb_cli, smb_tidx, "\\");
#endif
}

/***************************************************************************
 write a file
 ****************************************************************************/
static int write_trans_file(struct client_info *info,
				int f, char *b, int n)
{
	return writefile(info->translation, f, b, n);
}

/***************************************************************************
 read a file
 ****************************************************************************/
static int read_trans_file(struct client_info *info,
				char *b, int size, int n, FILE *f)
{
	return readfile(info->translation, b, size, n, f);
}


/****************************************************************************
 send a message
 ****************************************************************************/
void client_send_message(struct cli_state *cli, int t_idx,
				char *username, char *dest_host)
{
  int total_len;
  char message[2000];
  int l;
  char c;

  printf("Type your message, ending it with a Control-D\n");

      for (l=0; l < sizeof(message) && (c = fgetc(stdin)) != EOF; l++)
	{
	  if (c == '\n')
	    message[l++] = '\r';
	  message[l] = c;   
	}
    if (!cli_send_message(cli, t_idx, username, dest_host, message, &total_len))
    {
	  printf("send_message failed (%s)\n", cli_errstr(cli));
	  return;
	}      

  if (total_len >= 1600)
    printf("the message was truncated to 1600 bytes ");
  else
    printf("sent %d bytes ",total_len);

}



/****************************************************************************
send message
****************************************************************************/
void cmd_send_message(struct client_info *info)
{
	fstring username;

	if (!next_token(NULL,username,NULL))
	{
		DEBUG(0,("message <username/workgroup>\n"));
	}

	client_send_message(&smb_cli, smb_tidx, username, info->dest_host);
}


/****************************************************************************
check the space on a device
****************************************************************************/
static void do_dskattr(struct cli_state *cli, int t_idx)
{
	uint16 num_blocks;	
	uint32 block_size;
	uint16 free_blocks;

	if (!cli_dskattr(cli, t_idx, &num_blocks, &block_size, &free_blocks))
	{
    	DEBUG(0,("Error in dskattr: %s\n", cli_errstr(cli)));      
	}
	else
	{
  		DEBUG(0,("\n\t\t%d blocks of size %d. %d blocks available\n",
		          num_blocks, block_size, free_blocks));
	}
}


/****************************************************************************
change directory - inner section
****************************************************************************/
void do_cd(struct cli_state *cli, int t_idx, struct client_info*info, char *newdir)
{
  char *p = newdir;
  pstring saved_dir;
  pstring dname;
      
  /* Save the current directory in case the
     new directory is invalid */
  strcpy(saved_dir, info->cur_dir);
  if (*p == '\\')
    strcpy(info->cur_dir,p);
  else
    strcat(info->cur_dir,p);
  if (*(info->cur_dir+strlen(info->cur_dir)-1) != '\\') {
    strcat(info->cur_dir, "\\");
  }
  dos_clean_name(info->cur_dir);
  strcpy(dname,info->cur_dir);
  strcat(info->cur_dir,"\\");
  dos_clean_name(info->cur_dir);

  if (!strequal(info->cur_dir,"\\"))
    if (!cli_chkpath(cli, t_idx, dname))
    {
      DEBUG(2,("do_cd: cli_chkpath returned %s\n", cli_errstr(cli)));
      strcpy(info->cur_dir,saved_dir);
    }

  strcpy(cd_path, info->cur_dir);
}

/****************************************************************************
change directory
****************************************************************************/
void cmd_cd(struct client_info*info)
{
  fstring buf;

  if (next_token(NULL,buf,NULL))
    do_cd(&smb_cli, smb_tidx, info, buf);
  else
    DEBUG(0,("Current directory is %s\n", CNV_LANG(info->cur_dir)));
}



/****************************************************************************
  get a directory listing
  ****************************************************************************/
void cmd_dir(struct client_info*info)
{
  int attribute = aDIR | aSYSTEM | aHIDDEN;
  pstring mask;
  fstring buf;
  char *p=buf;

  info->dir_total = 0;
  strcpy(mask,info->cur_dir);
  if(mask[strlen(mask)-1]!='\\')
    strcat(mask,"\\");

  if (next_token(NULL,buf,NULL))
    {
      if (*p == '\\')
	strcpy(mask,p);
      else
	strcat(mask,p);
    }
  else {
    strcat(mask,"*");
  }

  cli_do_dir(&smb_cli, smb_tidx, info, mask, attribute, info->recurse_dir, NULL);

  do_dskattr(&smb_cli, smb_tidx);

  DEBUG(3, ("Total bytes listed: %d\n", info->dir_total));
}




/****************************************************************************
  get a file
  ****************************************************************************/
void cmd_get(struct client_info*info)
{
  pstring lname;
  pstring rname;
  BOOL newhandle = False;
  int handle = 0;

  char *p;

  strcpy(rname,info->cur_dir);
  strcat(rname,"\\");

  p = rname + strlen(rname);

  if (!next_token(NULL,p,NULL)) {
    DEBUG(0,("get <filename>\n"));
    return;
  }
  strcpy(lname,p);
  dos_clean_name(rname);
    
  next_token(NULL,lname,NULL);

  
  if(!strcmp(lname,"-"))
  {
    handle = fileno(stdout);
    newhandle = False;
  }
  else 
  {
      handle = creat(lname,0644);
      newhandle = True;
  }

  if (handle < 0)
  {
      DEBUG(0,("Error opening local file %s\n",lname));
      return;
  }

  cli_get(&smb_cli, smb_tidx, info, rname,lname, NULL, handle,
		NULL, write_trans_file, NULL);

  if(newhandle)
  {
    close(handle);
  }
}


/****************************************************************************
  do a mget operation on one file
  ****************************************************************************/
static void do_mget(struct cli_state *cli, int t_idx, struct client_info*info,
				file_info *finfo)
{
  pstring rname;
  pstring quest;

  if (strequal(finfo->name,".") || strequal(finfo->name,".."))
    return;

  if (info->abort_mget)
    {
      DEBUG(0,("mget aborted\n"));
      return;
    }

  if (finfo->mode & aDIR)
    sprintf(quest,"Get directory %s? ", CNV_LANG(finfo->name));
  else
    sprintf(quest,"Get file %s? ", CNV_LANG(finfo->name));

  if (info->prompt && !yesno(quest)) return;

  if (finfo->mode & aDIR)
    {
      pstring saved_curdir;
      pstring mget_mask;

      strcpy(saved_curdir,info->cur_dir);

      strcat(info->cur_dir,finfo->name);
      strcat(info->cur_dir,"\\");

      unix_format(finfo->name);
      {
	if (info->lowercase)
	  strlower(finfo->name);

	if (!directory_exist(finfo->name,NULL) && 
	    sys_mkdir(finfo->name,0777) != 0) 
	  {
	    DEBUG(0,("failed to create directory %s\n", CNV_LANG(finfo->name)));
	    strcpy(info->cur_dir,saved_curdir);
	    return;
	  }

	if (sys_chdir(finfo->name) != 0)
	  {
	    DEBUG(0,("failed to chdir to directory %s\n", CNV_LANG(finfo->name)));
	    strcpy(info->cur_dir,saved_curdir);
	    return;
	  }
      }       

      strcpy(mget_mask,info->cur_dir);
      strcat(mget_mask,"*");
      
      cli_dir(cli, t_idx, info, mget_mask, aSYSTEM | aHIDDEN | aDIR, info->recurse_dir, do_mget);
      chdir("..");
      strcpy(info->cur_dir,saved_curdir);
    }
  else
    {
      int handle;
      strcpy(rname,info->cur_dir);
      strcat(rname,finfo->name);
      handle = creat(rname,0644);

	  if (handle < 0)
	  {
		  DEBUG(0,("Error opening local file %s\n",rname));
		  return;
	  }

	  cli_get(cli, t_idx, info, rname,finfo->name, finfo, handle,
			NULL, write_trans_file, NULL);
    }
}

/****************************************************************************
view the file using the pager
****************************************************************************/
void cmd_more(struct client_info*info)
{
  fstring rname,lname,tmpname,pager_cmd;
  char *pager;
  int handle;

  strcpy(rname,info->cur_dir);
  strcat(rname,"\\");
  sprintf(tmpname,"%s/smbmore.%d",tmpdir(),(int)getpid());
  strcpy(lname,tmpname);

  if (!next_token(NULL,rname+strlen(rname),NULL)) {
    DEBUG(0,("more <filename>\n"));
    return;
  }
  dos_clean_name(rname);

  handle = creat(rname,0644);

  if (handle < 0)
  {
	  DEBUG(0,("Error opening local file %s\n",lname));
	  return;
  }

  cli_get(&smb_cli, smb_tidx, info, rname,lname, NULL, handle,
			NULL, write_trans_file, NULL);

  pager=getenv("PAGER");
  sprintf(pager_cmd,"%s %s",(pager? pager:PAGER), tmpname);
  system(pager_cmd);
  unlink(tmpname);
}



/****************************************************************************
do a mget command
****************************************************************************/
void cmd_mget(struct client_info*info)
{
  int attribute = aSYSTEM | aHIDDEN;
  pstring mget_mask;
  fstring buf;
  char *p=buf;

  *mget_mask = 0;

  if (info->recurse_dir)
    attribute |= aDIR;

  info->abort_mget = False;

  while (next_token(NULL,p,NULL))
    {
      strcpy(mget_mask,info->cur_dir);
      if(mget_mask[strlen(mget_mask)-1]!='\\')
	strcat(mget_mask,"\\");

      if (*p == '\\')
	strcpy(mget_mask,p);
      else
	strcat(mget_mask,p);
      cli_do_dir(&smb_cli, smb_tidx, info, mget_mask, attribute, False, do_mget);
    }

  if (! *mget_mask)
    {
      strcpy(mget_mask,info->cur_dir);
      if(mget_mask[strlen(mget_mask)-1]!='\\')
	strcat(mget_mask,"\\");
      strcat(mget_mask,"*");
      cli_do_dir(&smb_cli, smb_tidx, info, mget_mask, attribute, False, do_mget);
    }
}

/****************************************************************************
  make a directory
  ****************************************************************************/
void cmd_mkdir(struct client_info*info)
{
  pstring mask;
  fstring buf;
  char *p=buf;
  
  strcpy(mask,info->cur_dir);

  if (!next_token(NULL,p,NULL))
    {
      if (!info->recurse_dir)
	DEBUG(0,("mkdir <dirname>\n"));
      return;
    }
  strcat(mask,p);

  if (info->recurse_dir)
    {
      pstring ddir;
      pstring ddir2;
      *ddir2 = 0;

      strcpy(ddir,mask);
      trim_string(ddir,".",NULL);
      p = strtok(ddir,"/\\");
      while (p)
	{
	  strcat(ddir2,p);
	  if (!cli_chkpath(&smb_cli, smb_tidx, ddir2))
	    {		  
	      cli_mkdir(&smb_cli, smb_tidx, ddir2);
	    }
	  strcat(ddir2,"\\");
	  p = strtok(NULL,"/\\");
	}	 
    }
  else
    cli_mkdir(&smb_cli, smb_tidx, mask);
}


/****************************************************************************
  put a file
  ****************************************************************************/
void cmd_put(struct client_info*info)
{
  pstring lname;
  pstring rname;
  file_info finfo;
  int nread;
  pstring buf;
  char *p = buf;
  
    struct timeval tp_start;

  finfo = def_finfo;

  strcpy(rname,info->cur_dir);
  strcat(rname,"\\");
  
  if (!next_token(NULL,p,NULL))
    {
      DEBUG(0,("put <filename>\n"));
      return;
    }
  strcpy(lname,p);
  
  if (next_token(NULL,p,NULL))
    strcat(rname,p);      
  else
    strcat(rname,lname);

  dos_clean_name(rname);

  {
    struct stat st;
    if (!file_exist(lname,&st)) {
      DEBUG(0,("%s does not exist\n",lname));
      return;
    }
    finfo.mtime = st.st_mtime;
  }


    GetTimeOfDay(&tp_start);

  nread = cli_put(&smb_cli, smb_tidx, info, rname, lname, &finfo, read_trans_file);

  if (info->archive_level >= 2 && (finfo.mode & aARCH))
  {
    if (!cli_setatr(&smb_cli, smb_tidx, rname, finfo.mode & ~(aARCH), 0)) return;
  }

  {
    struct timeval tp_end;
    int this_time;

    GetTimeOfDay(&tp_end);
    this_time = (tp_end.tv_sec  - tp_start.tv_sec)*1000 +
                (tp_end.tv_usec - tp_start.tv_usec)/1000;

    info->get_total_time_ms += this_time;
    info->get_total_size += finfo.size;

    DEBUG(1,("(%g kb/s) (average %g kb/s)\n",
	     finfo.size           / (1.024*this_time + 1.0e-4),
	     info->get_total_size / (1.024*info->get_total_time_ms)));
  }
}

/****************************************************************************
  seek in a directory/file list until you get something that doesn't start with
  the specified name
  ****************************************************************************/
static BOOL seek_list(FILE *f,char *name)
{
  pstring s;
  while (!feof(f))
    {
      if (fscanf(f,"%s",s) != 1) return(False);
      trim_string(s,"./",NULL);
      if (strncmp(s,name,strlen(name)) != 0)
	{
	  strcpy(name,s);
	  return(True);
	}
    }
      
  return(False);
}


/****************************************************************************
  mput some files
  ****************************************************************************/
void cmd_mput(struct client_info*info)
{
  pstring lname;
  pstring rname;
  file_info finfo;
  fstring buf;
  char *p=buf;

  finfo = def_finfo;

  
  while (next_token(NULL,p,NULL))
    {
      struct stat st;
      pstring cmd;
      pstring tmpname;
      FILE *f;
      
      sprintf(tmpname,"%s/ls.smb.%d",tmpdir(),(int)getpid());
      if (info->recurse_dir)
	sprintf(cmd,"find . -name \"%s\" -print > %s",p,tmpname);
      else
	sprintf(cmd,"/bin/ls %s > %s",p,tmpname);
      system(cmd);

      f = fopen(tmpname,"r");
      if (!f) continue;

      while (!feof(f))
	{
	  pstring quest;

	  if (fscanf(f,"%s",lname) != 1) break;
	  trim_string(lname,"./",NULL);

	again1:

	  /* check if it's a directory */
	  if (directory_exist(lname,&st))
	    {
	      if (!info->recurse_dir) continue;
	      sprintf(quest,"Put directory %s? ",lname);
	      if (info->prompt && !yesno(quest)) 
		{
		  strcat(lname,"/");
		  if (!seek_list(f,lname))
		    break;
		  goto again1;		    
		}
	      
	      strcpy(rname,info->cur_dir);
	      strcat(rname,lname);
	      if (!cli_chkpath(&smb_cli, smb_tidx, rname) && !cli_mkdir(&smb_cli, smb_tidx, rname)) {
		strcat(lname,"/");
		if (!seek_list(f,lname))
		  break;
		goto again1;		    		  
	      }

	      continue;
	    }
	  else
	    {
	      sprintf(quest,"Put file %s? ",lname);
	      if (info->prompt && !yesno(quest)) continue;

	      strcpy(rname,info->cur_dir);
	      strcat(rname,lname);
	    }
	  dos_format(rname);

	  /* null size so cli_put knows to ignore it */
	  finfo.size = -1;

	  /* set the date on the file */
	  finfo.mtime = st.st_mtime;

	  cli_put(&smb_cli, smb_tidx, info, rname,lname,&finfo, read_trans_file);
	}
      fclose(f);
      unlink(tmpname);
    }
}

/****************************************************************************
  get info on a file
  ****************************************************************************/
void cmd_stat(struct client_info*info)
{
	fstring buf;
	fstring fname;

	if (!next_token(NULL,buf,NULL))
	{
		printf("stat <file>\n");
		return;
	}

	strcpy(fname, info->cur_dir);
	strcat(fname, buf);

	cli_stat(&smb_cli, smb_tidx, fname);
}


/****************************************************************************
delete some files
****************************************************************************/
static void do_del(struct cli_state *cli, int t_idx, struct client_info*info,
				file_info *finfo)
{
	pstring mask;

	strcpy(mask,info->cur_dir);
	strcat(mask,finfo->name);

	if (finfo->mode & aDIR) return;

    if (!cli_unlink(cli, t_idx, mask))
	{
    	DEBUG(0,("%s deleting remote file %s\n", cli_errstr(cli), CNV_LANG(mask)));
	}
}

/****************************************************************************
delete some files
****************************************************************************/
void cmd_del(struct client_info*info)
{
  pstring mask;
  fstring buf;
  int attribute = aSYSTEM | aHIDDEN;

  if (info->recurse_dir)
    attribute |= aDIR;
  
  strcpy(mask,info->cur_dir);
    
  if (!next_token(NULL,buf,NULL))
    {
      DEBUG(0,("del <filename>\n"));
      return;
    }
  strcat(mask,buf);

  cli_do_dir(&smb_cli, smb_tidx, info, mask, attribute, info->recurse_dir, do_del);
}


/****************************************************************************
remove a directory
****************************************************************************/
void cmd_rmdir(struct client_info*info)
{
	pstring mask;
	fstring buf;

	strcpy(mask,info->cur_dir);

	if (!next_token(NULL,buf,NULL))
	{
		DEBUG(0,("rmdir <dirname>\n"));
		return;
	}
	strcat(mask,buf);

	if (!cli_rmdir(&smb_cli, smb_tidx, mask))
    {
		DEBUG(0,("%s removing remote directory file %s\n", cli_errstr(&smb_cli), CNV_LANG(mask)));
		return;
    }
}

/****************************************************************************
rename some files
****************************************************************************/
void cmd_rename(struct client_info*info)
{
  pstring src,dest;
  fstring buf,buf2;
  
  strcpy(src , info->cur_dir);
  strcpy(dest, info->cur_dir);
  
  if (!next_token(NULL,buf,NULL) || !next_token(NULL,buf2,NULL))
    {
      DEBUG(0,("rename <src> <dest>\n"));
      return;
    }
  strcat(src,buf);
  strcat(dest,buf2);

	cli_move(&smb_cli, smb_tidx, src, dest);
}


/****************************************************************************
show cd/pwd
****************************************************************************/
void cmd_pwd(struct client_info *info)
{
  DEBUG(0,("Current directory for SMB connection %d is %s",
		CNV_LANG(smb_cli.con[smb_tidx].full_share)));
  DEBUG(0,("%s\n", CNV_LANG(info->cur_dir)));
}


/****************************************************************************
initialise smb client structure
****************************************************************************/
void client_smb_init(void)
{
	bzero(&smb_cli, sizeof(smb_cli));
}

/****************************************************************************
make smb client connection
****************************************************************************/
void client_smb_connect(struct client_info *info,
				char *username, char *password, char *workgroup)
{
	BOOL anonymous = !username || username[0] == 0;
	BOOL got_pass = password && password[0] != 0;

	if (!cli_establish_connection(&smb_cli, &smb_tidx,
			info->dest_host, info->name_type, &info->dest_ip,
		     info->myhostname,
		   (got_pass || anonymous) ? NULL : "Enter Password:",
		   username, !anonymous ? password : NULL, workgroup,
	       info->share, info->svc_type,
	       False, True, !anonymous))
	{
		DEBUG(0,("client_smb_init: connection failed\n"));
		cli_shutdown(&smb_cli);
	}
}

/****************************************************************************
stop the smb connection(s?)
****************************************************************************/
void client_smb_stop(void)
{
	cli_shutdown(&smb_cli);
}
