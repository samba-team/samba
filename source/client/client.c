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

#ifndef REGISTER
#define REGISTER 0
#endif

pstring cd_path = "";
extern pstring myname;
extern pstring scope;

extern pstring user_socket_options;


extern pstring debugf;
extern int DEBUGLEVEL;


#define SEPARATORS " \t\n\r"

extern file_info def_finfo;

#define USENMB

#define CNV_LANG(s) dos2unix_format(s,False)
#define CNV_INPUT(s) unix2dos_format(s,True)

extern int coding_system;

static BOOL setup_term_code (char *code)
{
    int new;
    new = interpret_coding_system (code, UNKNOWN_CODE);
    if (new != UNKNOWN_CODE)
	{
		coding_system = new;
		return True;
    }
    return False;

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
static void send_message(struct cli_state *cli, char *username, char *desthost)
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
    if (!cli_send_message(cli, username, desthost, message, &total_len))
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
check the space on a device
****************************************************************************/
static void do_dskattr(struct cli_state *cli)
{
	uint16 num_blocks;	
	uint32 block_size;
	uint16 free_blocks;

	if (!cli_dskattr(cli, &num_blocks, &block_size, &free_blocks))
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
show cd/pwd
****************************************************************************/
static void cmd_pwd(struct cli_state *cli, struct client_info *info)
{
  DEBUG(0,("Current directory is %s", CNV_LANG(cli->fullshare)));
  DEBUG(0,("%s\n", CNV_LANG(info->cur_dir)));
}


/****************************************************************************
change directory - inner section
****************************************************************************/
static void do_cd(struct cli_state *cli, struct client_info *info, char *newdir)
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
    if (!cli_chkpath(cli, dname))
    {
      DEBUG(2,("do_cd: cli_chkpath returned %s\n", cli_errstr(cli)));
      strcpy(info->cur_dir,saved_dir);
    }

  strcpy(cd_path, info->cur_dir);
}

/****************************************************************************
change directory
****************************************************************************/
static void cmd_cd(struct cli_state *cli, struct client_info *info)
{
  fstring buf;

  if (next_token(NULL,buf,NULL))
    do_cd(cli, info, buf);
  else
    DEBUG(0,("Current directory is %s\n", CNV_LANG(info->cur_dir)));
}



/****************************************************************************
  get a directory listing
  ****************************************************************************/
static void cmd_dir(struct cli_state *cli, struct client_info *info)
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

  cli_do_dir(cli, info, mask, attribute, info->recurse_dir, NULL);

  do_dskattr(cli);

  DEBUG(3, ("Total bytes listed: %d\n", info->dir_total));
}




/****************************************************************************
  get a file
  ****************************************************************************/
static void cmd_get(struct cli_state *cli, struct client_info *info)
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

  cli_get(cli, info, rname,lname, NULL, handle,
		NULL, write_trans_file, NULL);

  if(newhandle)
  {
    close(handle);
  }
}


/****************************************************************************
  do a mget operation on one file
  ****************************************************************************/
static void do_mget(struct cli_state *cli, struct client_info *info,
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
      
      cli_dir(cli, info, mget_mask, aSYSTEM | aHIDDEN | aDIR, info->recurse_dir, do_mget);
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

	  cli_get(cli, info, rname,finfo->name, finfo, handle,
			NULL, write_trans_file, NULL);
    }
}

/****************************************************************************
view the file using the pager
****************************************************************************/
static void cmd_more(struct cli_state *cli, struct client_info *info)
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

  cli_get(cli, info, rname,lname, NULL, handle,
			NULL, write_trans_file, NULL);

  pager=getenv("PAGER");
  sprintf(pager_cmd,"%s %s",(pager? pager:PAGER), tmpname);
  system(pager_cmd);
  unlink(tmpname);
}



/****************************************************************************
do a mget command
****************************************************************************/
static void cmd_mget(struct cli_state *cli, struct client_info *info)
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
      cli_do_dir(cli, info, mget_mask, attribute, False, do_mget);
    }

  if (! *mget_mask)
    {
      strcpy(mget_mask,info->cur_dir);
      if(mget_mask[strlen(mget_mask)-1]!='\\')
	strcat(mget_mask,"\\");
      strcat(mget_mask,"*");
      cli_do_dir(cli, info, mget_mask, attribute, False, do_mget);
    }
}

/****************************************************************************
  make a directory
  ****************************************************************************/
static void cmd_mkdir(struct cli_state *cli, struct client_info *info)
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
	  if (!cli_chkpath(cli, ddir2))
	    {		  
	      cli_mkdir(cli, ddir2);
	    }
	  strcat(ddir2,"\\");
	  p = strtok(NULL,"/\\");
	}	 
    }
  else
    cli_mkdir(cli, mask);
}


/****************************************************************************
  put a file
  ****************************************************************************/
static void cmd_put(struct cli_state *cli, struct client_info *info)
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

  nread = cli_put(cli, info, rname, lname, &finfo, read_trans_file);

  if (info->archive_level >= 2 && (finfo.mode & aARCH))
  {
    if (!cli_setatr(cli, rname, finfo.mode & ~(aARCH), 0)) return;
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
  set the file selection mask
  ****************************************************************************/
static void cmd_select(struct cli_state *cli, struct client_info *info)
{
  strcpy(info->file_sel,"");
  next_token(NULL,info->file_sel,NULL);
}


/****************************************************************************
  mput some files
  ****************************************************************************/
static void cmd_mput(struct cli_state *cli, struct client_info *info)
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
	      if (!cli_chkpath(cli, rname) && !cli_mkdir(cli, rname)) {
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

	  cli_put(cli, info, rname,lname,&finfo, read_trans_file);
	}
      fclose(f);
      unlink(tmpname);
    }
}

/****************************************************************************
  cancel a print job
  ****************************************************************************/
static void cmd_cancel(struct cli_state *cli, struct client_info *info)
{
  fstring buf;
  int job; 

  if (!strequal(cli->dev,"LPT1:"))
    {
      DEBUG(0,("WARNING: You didn't use the -P option to smbclient.\n"));
      DEBUG(0,("Trying to cancel print jobs without -P may fail\n"));
    }

  if (!next_token(NULL,buf,NULL))
  {
    printf("cancel <jobid> ...\n");
    return;
  }

  do
  {
    uint16 cancelled_job;
    job = atoi(buf);
    if (cli_cancel(cli, (uint16)job, &cancelled_job))
    {
	    DEBUG(0, ("Job %d cancelled\n", cancelled_job));
    }
    else
    {
      DEBUG(0, ("Server refused cancel request\n"));
    }

  } while (next_token(NULL,buf,NULL));
}


/****************************************************************************
  get info on a file
  ****************************************************************************/
static void cmd_stat(struct cli_state *cli, struct client_info *info)
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

	cli_stat(cli, fname);
}


/****************************************************************************
  print a file
  ****************************************************************************/
static void cmd_print(struct cli_state *cli, struct client_info *info)
{
  FILE *f = NULL;
  pstring lname;
  pstring rname;
  char *p;

  if (!strequal(cli->dev,"LPT1:"))
    {
      DEBUG(0,("WARNING: You didn't use the -P option to smbclient.\n"));
      DEBUG(0,("Trying to print without -P may fail\n"));
    }

  if (!next_token(NULL,lname,NULL))
    {
      DEBUG(0,("print <filename>\n"));
      return;
    }

  strcpy(rname,lname);
  p = strrchr(rname,'/');
  if (p)
    {
      pstring tname;
      strcpy(tname,p+1);
      strcpy(rname,tname);
    }

  if ((int)strlen(rname) > 14)
    rname[14] = 0;

  if (strequal(lname,"-"))
    {
      f = stdin;
      strcpy(rname,"stdin");
    }
  
  dos_clean_name(rname);

  cli_print(cli, info, f, lname, rname);
}

/****************************************************************************
display print_q info
****************************************************************************/
static void print_q(uint16 job, char *name, uint32 size, uint8 status)
{
	fstring status_str;

	switch (status)
	  {
	  case 0x01: sprintf(status_str,"held or stopped"); break;
	  case 0x02: sprintf(status_str,"printing"); break;
	  case 0x03: sprintf(status_str,"awaiting print"); break;
	  case 0x04: sprintf(status_str,"in intercept"); break;
	  case 0x05: sprintf(status_str,"file had error"); break;
	  case 0x06: sprintf(status_str,"printer error"); break;
	  default: sprintf(status_str,"unknown"); break;
	  }

	DEBUG(0,("%-6d   %-16.16s  %-9d    %s\n", job, name, size, status_str));
}


/****************************************************************************
show a print queue - this is deprecated as it uses the old smb that
has limited support - the correct call is the cmd_p_queue_2() after this.
****************************************************************************/
static void cmd_queue(struct cli_state *cli, struct client_info *info)
{
	int count;

	if (!strequal(cli->dev,"LPT1:"))
	{
		DEBUG(0,("WARNING: You didn't use the -P option to smbclient.\n"));
		DEBUG(0,("Trying to print without -P may fail\n"));
	}

    DEBUG(0,("Job      Name              Size         Status\n"));

	count = cli_queue(cli, info, print_q);

	if (count <= 0)
	{
		DEBUG(0,("No entries in the print queue\n"));
		return;
	}  
}

/****************************************************************************
display print_queue_2 info
****************************************************************************/
static void print_q2( char *PrinterName, uint16 JobId, uint16 Priority,
          char *UserName, time_t JobTime, uint32 Size, char *JobName)
{
	char *JobTimeStr;


	JobTimeStr = asctime(LocalTime( &JobTime));

	printf("%s-%u    %s    priority %u   %s    %s   %u bytes\n", 
	            PrinterName, JobId, UserName,
	            Priority, JobTimeStr, JobName, Size);
}

/****************************************************************************
show information about a print queue
****************************************************************************/
static void cmd_p_queue_2(struct cli_state *cli, struct client_info *info)
{
	if (!strequal(cli->dev,"LPT1:"))
	{
		DEBUG(0,("WARNING: You didn't use the -P option to smbclient.\n"));
		DEBUG(0,("Trying to print without -P may fail\n"));
	}
	cli_pqueue_2(cli, info, print_q2);
}

/****************************************************************************
show information about a print queue
****************************************************************************/
static void cmd_qinfo(struct cli_state *cli, struct client_info *info)
{
	fstring params, comment, printers, driver_name;
	fstring name, separator_file, print_processor;
	uint16 priority, start_time, until_time, status, jobs;
	int driver_count;
	char *driver_data;

	if (!cli_printq_info(cli, info,
	                    name, &priority,
	                    &start_time, &until_time,
	                    separator_file, print_processor,
	                    params, comment,
	                    &status, &jobs,
	                    printers, driver_name,
	                    &driver_data, &driver_count))
	{
		return;
	}

	DEBUG(0, ("Name: \"%s\"\n", name));
	DEBUG(0, ("Priority: %u\n", priority));
	DEBUG(0, ("Start time: %u\n", start_time));
	DEBUG(0, ("Until time: %u\n", until_time));
	DEBUG(0, ("Separator file: \"%s\"\n", separator_file));
	DEBUG(0, ("Print processor: \"%s\"\n", print_processor));
	DEBUG(0, ("Parameters: \"%s\"\n", params));
	DEBUG(0, ("Comment: \"%s\"\n", comment));
	DEBUG(0, ("Status: %u\n", status));
	DEBUG(0, ("Jobs: %u\n", jobs));
	DEBUG(0, ("Printers: \"%s\"\n", printers));
	DEBUG(0, ("Drivername: \"%s\"\n", driver_name));

	DEBUG(0, ("Driverdata: size=%d, version=%u\n",
			driver_count, IVAL(driver_data,4) ));

	dump_data(0, driver_data, driver_count);
}

/****************************************************************************
delete some files
****************************************************************************/
static void do_del(struct cli_state *cli, struct client_info *info,
				file_info *finfo)
{
	pstring mask;

	strcpy(mask,info->cur_dir);
	strcat(mask,finfo->name);

	if (finfo->mode & aDIR) return;

    if (!cli_unlink(cli, mask))
	{
    	DEBUG(0,("%s deleting remote file %s\n", cli_errstr(cli), CNV_LANG(mask)));
	}
}

/****************************************************************************
delete some files
****************************************************************************/
static void cmd_del(struct cli_state *cli, struct client_info *info)
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

  cli_do_dir(cli, info, mask, attribute, info->recurse_dir, do_del);
}


/****************************************************************************
remove a directory
****************************************************************************/
static void cmd_rmdir(struct cli_state *cli, struct client_info *info)
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

	if (!cli_rmdir(cli, mask))
    {
		DEBUG(0,("%s removing remote directory file %s\n", cli_errstr(cli), CNV_LANG(mask)));
		return;
    }
}

/****************************************************************************
rename some files
****************************************************************************/
static void cmd_rename(struct cli_state *cli, struct client_info *info)
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

	cli_move(cli, src, dest);
}


/****************************************************************************
toggle the prompt flag
****************************************************************************/
static void cmd_prompt(struct cli_state *cli, struct client_info *info)
{
  info->prompt = !info->prompt;
  DEBUG(2,("prompting is now %s\n", BOOLSTR(info->prompt)));
}


/****************************************************************************
set the newer than time
****************************************************************************/
static void cmd_newer(struct cli_state *cli, struct client_info *info)
{
  fstring buf;
  BOOL ok;
  struct stat sbuf;

  ok = next_token(NULL,buf,NULL);
  if (ok && (sys_stat(buf,&sbuf) == 0))
    {
      info->newer_than = sbuf.st_mtime;
      DEBUG(1,("Getting files newer than %s",
	       asctime(LocalTime(&info->newer_than))));
    }
  else
    info->newer_than = 0;

  if (ok && info->newer_than == 0)
    DEBUG(0,("Error setting newer-than time\n"));
}

/****************************************************************************
set the archive level
****************************************************************************/
static void cmd_archive(struct cli_state *cli, struct client_info *info)
{
  fstring buf;

  if (next_token(NULL,buf,NULL)) {
    info->archive_level = atoi(buf);
  } else
    DEBUG(0,("Archive level is %d\n",info->archive_level));
}

/****************************************************************************
toggle the info->lowercaseflag
****************************************************************************/
static void cmd_lowercase(struct cli_state *cli, struct client_info *info)
{
  info->lowercase = !info->lowercase;
  DEBUG(2,("filename lowercasing is now %s\n",info->lowercase?"on":"off"));
}




/****************************************************************************
toggle the info->recurse flag
****************************************************************************/
static void cmd_recurse(struct cli_state *cli, struct client_info *info)
{
  info->recurse_dir = !info->recurse_dir;
  DEBUG(2,("directory recursion is now %s\n", BOOLSTR(info->recurse_dir)));
}

/****************************************************************************
toggle the translate flag
****************************************************************************/
static void cmd_translate(struct cli_state *cli, struct client_info *info)
{
  info->translation = !info->translation;
  DEBUG(2,("CR/LF<->LF and print text info->translation now %s\n",
	info->translation?"on":"off"));
}


/****************************************************************************
do a print_mode command
****************************************************************************/
static void cmd_printmode(struct cli_state *cli, struct client_info *info)
{
  fstring buf;
  fstring mode;

  if (next_token(NULL,buf,NULL))
    {
      if (strequal(buf,"text"))
	info->print_mode = 0;      
      else
	{
	  if (strequal(buf,"graphics"))
	    info->print_mode = 1;
	  else
	    info->print_mode = atoi(buf);
	}
    }

  switch(info->print_mode)
    {
    case 0: 
      strcpy(mode,"text");
      break;
    case 1: 
      strcpy(mode,"graphics");
      break;
    default: 
      sprintf(mode,"%d", info->print_mode);
      break;
    }

  DEBUG(2,("the print_mode is now %s\n",mode));
}

/****************************************************************************
do the lcd command
****************************************************************************/
static void cmd_lcd(struct cli_state *cli, struct client_info *info)
{
  fstring buf;
  pstring d;

  if (next_token(NULL,buf,NULL))
    sys_chdir(buf);
  DEBUG(2,("the local directory is now %s\n",GetWd(d)));
}

/****************************************************************************
do a (presumably graceful) quit...
****************************************************************************/
static void cmd_quit(struct cli_state *cli, struct client_info *info)
{
	cli_shutdown(cli);
	exit(0);
}


/****************************************************************************
print browse connection on a host
****************************************************************************/
static void print_server(char *sname, uint32 type, char *comment)
{
	fstring typestr;
	*typestr=0;

	if (type == SV_TYPE_ALL)
	{
		strcpy(typestr, "All");
	}
	else
	{
		int i;
		typestr[0] = 0;
		for (i = 0; i < 32; i++)
		{
			if (IS_BIT_SET(type, 1 << i)
			{
				switch (1 << i)
				{
					case SV_TYPE_WORKSTATION      : strcat(typestr, "Wk " ); break;
					case SV_TYPE_SERVER           : strcat(typestr, "Sv " ); break;
					case SV_TYPE_SQLSERVER        : strcat(typestr, "Sql "); break;
					case SV_TYPE_DOMAIN_CTRL      : strcat(typestr, "PDC "); break;
					case SV_TYPE_DOMAIN_BAKCTRL   : strcat(typestr, "BDC "); break;
					case SV_TYPE_TIME_SOURCE      : strcat(typestr, "Tim "); break;
					case SV_TYPE_AFP              : strcat(typestr, "AFP "); break;
					case SV_TYPE_NOVELL           : strcat(typestr, "Nov "); break;
					case SV_TYPE_DOMAIN_MEMBER    : strcat(typestr, "Dom "); break;
					case SV_TYPE_PRINTQ_SERVER    : strcat(typestr, "PrQ "); break;
					case SV_TYPE_DIALIN_SERVER    : strcat(typestr, "Din "); break;
					case SV_TYPE_SERVER_UNIX      : strcat(typestr, "Unx "); break;
					case SV_TYPE_NT               : strcat(typestr, "NT " ); break;
					case SV_TYPE_WFW              : strcat(typestr, "Wfw "); break;
					case SV_TYPE_SERVER_MFPN      : strcat(typestr, "Mfp "); break;
					case SV_TYPE_SERVER_NT        : strcat(typestr, "SNT "); break;
					case SV_TYPE_POTENTIAL_BROWSER: strcat(typestr, "PtB "); break;
					case SV_TYPE_BACKUP_BROWSER   : strcat(typestr, "BMB "); break;
					case SV_TYPE_MASTER_BROWSER   : strcat(typestr, "LMB "); break;
					case SV_TYPE_DOMAIN_MASTER    : strcat(typestr, "DMB "); break;
					case SV_TYPE_SERVER_OSF       : strcat(typestr, "OSF "); break;
					case SV_TYPE_SERVER_VMS       : strcat(typestr, "VMS "); break;
					case SV_TYPE_WIN95_PLUS       : strcat(typestr, "W95 "); break;
					case SV_TYPE_ALTERNATE_XPORT  : strcat(typestr, "Xpt "); break;
					case SV_TYPE_LOCAL_LIST_ONLY  : strcat(typestr, "Dom "); break;
					case SV_TYPE_DOMAIN_ENUM      : strcat(typestr, "Loc "); break;
				}
			}
		}
		i = strlen(typestr)-1;
		if (typestr[i] == ' ') typestr[i] = 0;

	}

	printf("\t%-15.15s%-16s %s\n", sname, typestr, comment);
}


/****************************************************************************
print browse connection on a host
****************************************************************************/
static void print_share(char *sname, uint32 type, char *comment)
{
	fstring typestr;
	*typestr=0;

	switch (type)
	{
		case STYPE_DISKTREE: strcpy(typestr,"Disk"); break;
		case STYPE_PRINTQ  : strcpy(typestr,"Printer"); break;	      
		case STYPE_DEVICE  : strcpy(typestr,"Device"); break;
		case STYPE_IPC     : strcpy(typestr,"IPC"); break;      
		default            : strcpy(typestr,"????"); break;      
	}

	printf("\t%-15.15s%-10.10s%s\n", sname, typestr, comment);
}


/****************************************************************************
try and browse available connections on a host
****************************************************************************/
static void browse_host(struct cli_state *cli, char *workgroup, BOOL sort)
{
	int count = 0;
	BOOL long_share_name = False;
	
	printf("\n\tSharename      Type      Comment\n");
	printf(  "\t---------      ----      -------\n");

	count = cli_NetShareEnum(cli, sort, &long_share_name, print_share);

	if (count == 0)
	{
		printf("\tNo shares available on this host\n");
	}

	if (long_share_name)
	{
		printf("\nNOTE: There were share names longer than 8 chars.\nOn older clients these may not be accessible or may give browsing errors\n");
	}

	printf("\n");
	printf("\tServer            Type               Comment\n");
	printf("\t------            ----               -------\n");
	
	cli_NetServerEnum(cli, workgroup, SV_TYPE_DOMAIN_ENUM, print_server);

	printf("\n");
	printf("\tWorkgroup         Type               Master\n");
	printf("\t---------         ----               -------\n");

	cli_NetServerEnum(cli, workgroup, SV_TYPE_ALL, print_server);
}


/* This defines the commands supported by this client */
struct
{
  char *name;
  void (*fn)();
  char *description;
} commands[] = 
{
  {"ls",         cmd_dir,         "<mask> list the contents of the current directory"},
  {"dir",        cmd_dir,         "<mask> list the contents of the current directory"},
  {"lcd",        cmd_lcd,         "[directory] change/report the local current working directory"},
  {"cd",         cmd_cd,          "[directory] change/report the remote directory"},
  {"pwd",        cmd_pwd,         "show current remote directory (same as 'cd' with no args)"},
  {"get",        cmd_get,         "<remote name> [local name] get a file"},
  {"mget",       cmd_mget,        "<mask> get all the matching files"},
  {"put",        cmd_put,         "<local name> [remote name] put a file"},
  {"mput",       cmd_mput,        "<mask> put all matching files"},
  {"rename",     cmd_rename,      "<src> <dest> rename some files"},
  {"more",       cmd_more,        "<remote name> view a remote file with your pager"},  
  {"mask",       cmd_select,      "<mask> mask all filenames against this"},
  {"del",        cmd_del,         "<mask> delete all matching files"},
  {"rm",         cmd_del,         "<mask> delete all matching files"},
  {"mkdir",      cmd_mkdir,       "<directory> make a directory"},
  {"md",         cmd_mkdir,       "<directory> make a directory"},
  {"rmdir",      cmd_rmdir,       "<directory> remove a directory"},
  {"rd",         cmd_rmdir,       "<directory> remove a directory"},
  {"pq",         cmd_p_queue_2,   "enumerate the print queue"},
  {"prompt",     cmd_prompt,      "toggle prompting for filenames for mget and mput"},  
  {"recurse",    cmd_recurse,     "toggle directory recursion for mget and mput"},  
  {"translate",  cmd_translate,   "toggle text translation for printing"},  
  {"lowercase",  cmd_lowercase,   "toggle lowercasing of filenames for get"},  
  {"print",      cmd_print,       "<file name> print a file"},
  {"print_mode", cmd_printmode,   "<graphics or text> set the print mode"},
  {"queue",      cmd_queue,       "show the print queue"},
  {"qinfo",      cmd_qinfo,       "show print queue information"},
  {"cancel",     cmd_cancel,      "<jobid> cancel a print queue entry"},
  {"stat",       cmd_stat,        "<file> get info on a file (experimental!)"},
  {"quit",       cmd_quit,        "logoff the server"},
  {"q",          cmd_quit,        "logoff the server"},
  {"exit",       cmd_quit,        "logoff the server"},
  {"newer",      cmd_newer,       "<file> only mget files newer than the specified local file"},
  {"archive",    cmd_archive,     "<level>\n0=ignore archive bit\n1=only get archive files\n2=only get archive files and reset archive bit\n3=get all files and reset archive bit"},
  {"tar",        cmd_tar,         "tar <c|x>[IXbgNa] current directory to/from <file name>" },
  {"blocksize",  cmd_block,       "blocksize <number> (default 20)" },
  {"tarmode",    cmd_tarmode,
     "<full|inc|reset|noreset> tar's behaviour towards archive bits" },
  {"setmode",    cmd_setmode,     "filename <setmode string> change modes of file"},
  {"help",       cmd_help,        "[command] give help on a command"},
  {"?",          cmd_help,        "[command] give help on a command"},
  {"!",          NULL,            "run a shell command on the local system"},
  {"",           NULL,            NULL}
};


/*******************************************************************
  lookup a command string in the list of commands, including 
  abbreviations
  ******************************************************************/
static int process_tok(fstring tok)
{
  int i = 0, matches = 0;
  int cmd=0;
  int tok_len = strlen(tok);
  
  while (commands[i].fn != NULL)
    {
      if (strequal(commands[i].name,tok))
	{
	  matches = 1;
	  cmd = i;
	  break;
	}
      else if (strnequal(commands[i].name, tok, tok_len+1))
	{
	  matches++;
	  cmd = i;
	}
      i++;
    }
  
  if (matches == 0)
    return(-1);
  else if (matches == 1)
    return(cmd);
  else
    return(-2);
}

/****************************************************************************
help
****************************************************************************/
void cmd_help(void)
{
  int i=0,j;
  fstring buf;

  if (next_token(NULL,buf,NULL))
    {
      if ((i = process_tok(buf)) >= 0)
	DEBUG(0,("HELP %s:\n\t%s\n\n",commands[i].name,commands[i].description));		    
    }
  else
    while (commands[i].description)
      {
	for (j=0; commands[i].description && (j<5); j++) {
	  DEBUG(0,("%-15s",commands[i].name));
	  i++;
	}
	DEBUG(0,("\n"));
      }
}

/****************************************************************************
wait for keyboard activity, swallowing network packets
****************************************************************************/
#ifdef CLIX
static char wait_keyboard(struct cli_state *cli)
#else
static void wait_keyboard(struct cli_state *cli)
#endif
{
  fd_set fds;
  int selrtn;
  struct timeval timeout;
  
#ifdef CLIX
  int delay = 0;
#endif
  
  while (1) 
    {
      FD_ZERO(&fds);
      FD_SET(cli->fd,&fds);
#ifndef CLIX
      FD_SET(fileno(stdin),&fds);
#endif

      timeout.tv_sec = 20;
      timeout.tv_usec = 0;
#ifdef CLIX
      timeout.tv_sec = 0;
#endif
      selrtn = sys_select(&fds,&timeout);
      
#ifndef CLIX
      if (FD_ISSET(fileno(stdin),&fds))
  	return;
#else
      {
	char ch;
	int readret;

    set_blocking(fileno(stdin), False);	
	readret = read_data( fileno(stdin), &ch, 1);
	set_blocking(fileno(stdin), True);
	if (readret == -1)
	  {
	    if (errno != EAGAIN)
	      {
		/* should crash here */
		DEBUG(1,("readchar stdin failed\n"));
	      }
	  }
	else if (readret != 0)
	  {
	    return ch;
	  }
      }
#endif
      if (FD_ISSET(cli->fd,&fds))
  	receive_smb(cli->fd,cli->inbuf,0);
      
#ifdef CLIX
      delay++;
      if (delay > 100000)
	{
	  delay = 0;
	  cli_chkpath(cli, "\\");
	}
#else
      cli_chkpath(cli, "\\");
#endif
    }  
}


/****************************************************************************
  process commands from the client
****************************************************************************/
static BOOL process(struct cli_state *cli, struct client_info *info,
				char *cmd_str)
{
  extern FILE *dbf;
  pstring line;
  char *cmd;

  if (*info->base_dir) do_cd(cli, info, info->base_dir);

  cmd = cmd_str;
  if (cmd[0] != '\0') while (cmd[0] != '\0')
    {
      char *p;
      fstring tok;
      int i;

      if ((p = strchr(cmd, ';')) == 0)
	{
	  strncpy(line, cmd, 999);
	  line[1000] = '\0';
	  cmd += strlen(cmd);
	}
      else
	{
	  if (p - cmd > 999) p = cmd + 999;
	  strncpy(line, cmd, p - cmd);
	  line[p - cmd] = '\0';
	  cmd = p + 1;
	}

      /* input language code to internal one */
      CNV_INPUT (line);
      
      /* and get the first part of the command */
      {
	char *ptr = line;
	if (!next_token(&ptr,tok,NULL)) continue;
      }

      if ((i = process_tok(tok)) >= 0)
	commands[i].fn(cli, info);
      else if (i == -2)
	DEBUG(0,("%s: command abbreviation ambiguous\n", CNV_LANG(tok)));
      else
	DEBUG(0,("%s: command not found\n", CNV_LANG(tok)));
    }
  else while (!feof(stdin))
    {
      fstring tok;
      int i;

      bzero(cli->outbuf,smb_size);

      /* display a prompt */
      DEBUG(0,("smb: %s> ", CNV_LANG(info->cur_dir)));
      fflush(dbf);

#ifdef CLIX
      line[0] = wait_keyboard(cli);
      /* this might not be such a good idea... */
      if ( line[0] == EOF)
	break;
#else
      wait_keyboard(cli);
#endif
  
      /* and get a response */
#ifdef CLIX
      fgets( &line[1],999, stdin);
#else
      if (!fgets(line,1000,stdin))
	break;
#endif

      /* input language code to internal one */
      CNV_INPUT (line);

      /* special case - first char is ! */
      if (*line == '!')
	{
	  system(line + 1);
	  continue;
	}
      
      /* and get the first part of the command */
      {
	char *ptr = line;
	if (!next_token(&ptr,tok,NULL)) continue;
      }

      if ((i = process_tok(tok)) >= 0)
	commands[i].fn(cli, info);
      else if (i == -2)
	DEBUG(0,("%s: command abbreviation ambiguous\n", CNV_LANG(tok)));
      else
	DEBUG(0,("%s: command not found\n", CNV_LANG(tok)));
    }
  
  return(True);
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
  DEBUG(0,("Usage: %s service <password> [-p port] [-d debuglevel] [-l log] ",
	   pname));

  DEBUG(0,("\nVersion %s\n",VERSION));
  DEBUG(0,("\t-p port               listen on the specified port\n"));
  DEBUG(0,("\t-d debuglevel         set the debuglevel\n"));
  DEBUG(0,("\t-l log basename.      Basename for log/debug files\n"));
  DEBUG(0,("\t-n netbios name.      Use this name as my netbios name\n"));
  DEBUG(0,("\t-N                    don't ask for a password\n"));
  DEBUG(0,("\t-P                    connect to service as a printer\n"));
  DEBUG(0,("\t-M host               send a winpopup message to the host\n"));
  DEBUG(0,("\t-m max protocol       set the max protocol level\n"));
  DEBUG(0,("\t-L host               get a list of shares available on a host\n"));
  DEBUG(0,("\t-I dest IP            use this IP to connect to\n"));
  DEBUG(0,("\t-E                    write messages to stderr instead of stdout\n"));
  DEBUG(0,("\t-U username           set the network username\n"));
  DEBUG(0,("\t-W workgroup          set the workgroup name\n"));
  DEBUG(0,("\t-c command string     execute semicolon separated commands\n"));
  DEBUG(0,("\t-t terminal code      terminal i/o code {sjis|euc|jis7|jis8|junet|hex}\n"));
  DEBUG(0,("\t-T<c|x>IXgbNa          command line tar\n"));
  DEBUG(0,("\t-D directory          start from directory\n"));
  DEBUG(0,("\n"));
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	char *pname = argv[0];
	int port = SMB_PORT;
	int opt;
	extern FILE *dbf;
	extern char *optarg;
	extern int optind;
	BOOL message = False;
	BOOL nt_domain_logon = False;
	static pstring servicesf = CONFIGFILE;
	pstring term_code;
	char *p;
	BOOL got_pass = False;
	char *cmd_str="";
	int myumask = 0755;

	struct cli_state smb_cli;
	struct client_info cli_info;

	pstring query_host;
	pstring desthost;
	struct in_addr dest_ip;
	int name_type = 0x0;

	pstring myhostname;
	pstring workgroup;

	pstring username;
	pstring password;

	pstring service;
	pstring share;
	fstring svc_type;
	pstring tmp;

	dest_ip.s_addr = 0;
	desthost[0] = 0;
	query_host[0] = 0;

	strcpy(svc_type, "A:");

	bzero(&smb_cli, sizeof(smb_cli));

	#ifdef KANJI
	strcpy(term_code, KANJI);
	#else /* KANJI */
	*term_code = 0;
	#endif /* KANJI */

	DEBUGLEVEL = 2;

	cli_info.put_total_size = 0;
	cli_info.put_total_time_ms = 0;
	cli_info.get_total_size = 0;
	cli_info.get_total_time_ms = 0;

	cli_info.dir_total = 0;
	cli_info.newer_than = 0;
	cli_info.archive_level = 0;
	cli_info.print_mode = 1;

	cli_info.translation = False;
	cli_info.recurse_dir = False;
	cli_info.lowercase = False;
	cli_info.prompt = True;
	cli_info.abort_mget = True;

	strcpy(cli_info.cur_dir , "\\");
	strcpy(cli_info.file_sel, "");
	strcpy(cli_info.base_dir, "");

	cli_info.tar.blocksize = 20;
	cli_info.tar.attrib = aDIR | aSYSTEM | aHIDDEN;
	cli_info.tar.inc = False;
	cli_info.tar.reset = False;
	cli_info.tar.excl = True;
	cli_info.tar.type = '\0';
	cli_info.tar.cliplist = NULL;
	cli_info.tar.clipn = 0;
	cli_info.tar.tp = 0;
	cli_info.tar.buf_size = 0;
	cli_info.tar.num_files = 0;
	cli_info.tar.bytes_written = 0;
	cli_info.tar.buf = NULL;
	cli_info.tar.handle = 0;


	setup_logging(pname,True);

	TimeInit();
	charset_initialise();

	myumask = umask(0);
	umask(myumask);

	if (getenv("USER"))
	{
		strcpy(username,getenv("USER"));

		/* modification to support userid%passwd syntax in the USER var
		25.Aug.97, jdblair@uab.edu */

		if ((p=strchr(username,'%')))
		{
			*p = 0;
			strcpy(password,p+1);
			got_pass = True;
			memset(strchr(getenv("USER"),'%')+1,'X',strlen(password));
		}
		strupper(username);
	}

	/* modification to support PASSWD environmental var
	   25.Aug.97, jdblair@uab.edu */
	if (getenv("PASSWD"))
	{
		strcpy(password,getenv("PASSWD"));
	}

	if (*username == 0 && getenv("LOGNAME"))
	{
		strcpy(username,getenv("LOGNAME"));
		strupper(username);
	}

	if (argc < 2)
	{
		usage(pname);
		exit(1);
	}

	if (*argv[1] != '-')
	{

		strcpy(service, argv[1]);  
		/* Convert any '/' characters in the service name to '\' characters */
		string_replace( service, '/','\\');
		argc--;
		argv++;

		if (count_chars(service,'\\') < 3)
		{
			usage(pname);
			printf("\n%s: Not enough '\\' characters in service\n",service);
			exit(1);
		}

		/*
		if (count_chars(service,'\\') > 3)
		{
			usage(pname);
			printf("\n%s: Too many '\\' characters in service\n",service);
			exit(1);
		}
		*/

		if (argc > 1 && (*argv[1] != '-'))
		{
			got_pass = True;
			strcpy(password,argv[1]);  
			memset(argv[1],'X',strlen(argv[1]));
			argc--;
			argv++;
		}
	}

	while ((opt = getopt(argc, argv,"s:B:O:M:S:i:Nn:d:Pp:l:hI:EB:U:L:t:m:W:T:D:c:")) != EOF)
	{
		switch (opt)
		{
			case 'm':
			{
				int max_protocol = interpret_protocol(optarg,max_protocol);
				DEBUG(0,("max protocol not currently supported\n"));
				break;
			}

			case 'O':
			{
				strcpy(user_socket_options,optarg);
				break;	
			}

			case 'S':
			{
				strcpy(desthost,optarg);
				strupper(desthost);
				nt_domain_logon = True;
				break;
			}

			case 'M':
			{
				name_type = 0x03; /* messages sent to NetBIOS name type 0x3 */
				strcpy(desthost,optarg);
				strupper(desthost);
				message = True;
				break;
			}

			case 'B':
			{
				iface_set_default(NULL,optarg,NULL);
				break;
			}

			case 'D':
			{
				strcpy(cli_info.base_dir,optarg);
				break;
			}

			case 'T':
			{
				if (!tar_parseargs(&cli_info, argc, argv, optarg, optind))
				{
					usage(pname);
					exit(1);
				}
				break;
			}

			case 'i':
			{
				strcpy(scope, optarg);
				break;
			}

			case 'L':
			{
				got_pass = True;
				strcpy(query_host,optarg);
				break;
			}

			case 'U':
			{
				char *lp;
				strcpy(username,optarg);
				if ((lp=strchr(username,'%')))
				{
					*lp = 0;
					strcpy(password,lp+1);
					got_pass = True;
					memset(strchr(optarg,'%')+1,'X',strlen(password));
				}
				break;
			}

			case 'W':
			{
				strcpy(workgroup,optarg);
				break;
			}

			case 'E':
			{
				dbf = stderr;
				break;
			}

			case 'I':
			{
				dest_ip = *interpret_addr2(optarg);
				if (zero_ip(dest_ip))
				{
					exit(1);
				}
				break;
			}
			case 'n':
			{
				strcpy(myname,optarg);
				break;
			}

			case 'N':
			{
				got_pass = True;
				break;
			}

			case 'P':
			{
				strcpy(svc_type, "LPT1:");
				break;
			}

			case 'd':
			{
				if (*optarg == 'A')
					DEBUGLEVEL = 10000;
				else
					DEBUGLEVEL = atoi(optarg);
				break;
			}

			case 'l':
			{
				sprintf(debugf,"%s.client",optarg);
				break;
			}

			case 'p':
			{
				port = atoi(optarg);
				break;
			}

			case 'c':
			{
				cmd_str = optarg;
				got_pass = True;
				break;
			}

			case 'h':
			{
				usage(pname);
				exit(0);
				break;
			}

			case 's':
			{
				strcpy(servicesf, optarg);
				break;
			}

			case 't':
			{
				strcpy(term_code, optarg);
				break;
			}

			default:
			{
				usage(pname);
				exit(1);
				break;
			}
		}
	}

	if (!cli_info.tar.type && !*query_host && !*service && !message)
	{
		usage(pname);
		exit(1);
	}

	DEBUG(3,("%s client started (version %s)\n",timestring(),VERSION));

	if(!get_myname(myhostname, NULL))
	{
		DEBUG(0,("Failed to get my hostname.\n"));
	}

	if (!lp_load(servicesf,True))
	{
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
	}

	codepage_initialise(lp_client_code_page());

	if(lp_client_code_page() == KANJI_CODEPAGE)
	{
		if (!setup_term_code (term_code))
		{
			DEBUG(0, ("%s: unknown terminal code name\n", optarg));
			usage (pname);
			exit (1);
		}
	}

	if (*workgroup == 0) strcpy(workgroup,lp_workgroup());

	load_interfaces();
	get_myname((*myname)?NULL:myname,NULL);  
	strupper(myname);

	if (*query_host && !nt_domain_logon)
	{
		strupper(service);

		if (!cli_establish_connection(&smb_cli, query_host, name_type, &dest_ip,
		     myhostname,
		     got_pass ? NULL : "Enter Password:",
		     username, password, workgroup,
		     "IPC$", "IPC",
		     False, True, False))
		{
			cli_shutdown(&smb_cli);
			return 1;
		}

		browse_host(&smb_cli, workgroup, True);

		cli_shutdown(&smb_cli);

		return 0;
	}

	if (message)
	{
		int ret = 0;
		if (!cli_establish_connection(&smb_cli, desthost, name_type, &dest_ip,
		     myhostname,
		     got_pass ? NULL : "Enter Password:",
		     username, password, workgroup,
		     service, svc_type,
		     False, False, True))
		{
			cli_shutdown(&smb_cli);
			return 1;
		}

		send_message(&smb_cli, username, desthost);

		cli_shutdown(&smb_cli);

		return(ret);
	}

#ifdef NTDOMAIN

	if (nt_domain_logon)
	{
		fstring mach_acct;

		fstrcpy(mach_acct, myhostname);
		strlower(mach_acct);
		strcat(mach_acct, "$");

		DEBUG(5,("NT Domain Logon[%s].  Host:%s Mac-acct:%s\n",
		workgroup, desthost, mach_acct));

		do_nt_login_test(dest_ip, desthost, myhostname,
		                 username, workgroup, mach_acct);

		return(0);
	}
#endif 
	
	/* extract destination host (if there isn't one) and share from service */
	pstrcpy(tmp, service);
	p = strtok(tmp, "\\/");
	if (desthost[0] == 0)
	{
		strcpy(desthost, p);
	}
	p = strtok(NULL, "\\/");
	strcpy(share, p);

	if (desthost[0] == 0)
	{
		DEBUG(0,("Could not get host name from service %s\n", service));
		return 1;
	}

	if (share[0] == 0)
	{
		DEBUG(0,("Could not get share name from service %s\n", service));
		return 1;
	}

	if (cli_info.tar.type)
	{
		int ret = 0;
		cli_info.recurse_dir = True;

		if (!cli_establish_connection(&smb_cli, desthost, name_type, &dest_ip,
		     myhostname,
		     got_pass ? NULL : "Enter Password:",
		     username, password, workgroup,
		     service, svc_type,
		     False, True, True))
		{
			cli_shutdown(&smb_cli);
			return 1;
		}

		bzero(smb_cli.outbuf,smb_size);
		if (*cli_info.base_dir)
		{
			do_cd(&smb_cli, &cli_info, cli_info.base_dir);
		}
		ret = process_tar(&smb_cli, &cli_info);

		cli_shutdown(&smb_cli);
		return ret;
	}

	if (!cli_establish_connection(&smb_cli, desthost, name_type, &dest_ip,
		   myhostname,
		   got_pass ? NULL : "Enter Password:",
		   username, password, workgroup,
	       share, svc_type,
	       False, True, True))
	{
		cli_shutdown(&smb_cli);
		return 1;
	}

	if (!process(&smb_cli, &cli_info, cmd_str))
	{
		cli_shutdown(&smb_cli);
		return 1;
	}

	cli_shutdown(&smb_cli);

	return(0);
}
