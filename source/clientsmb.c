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
void cmd_pwd(struct cli_state *cli, struct client_info *info)
{
  DEBUG(0,("Current directory is %s", CNV_LANG(cli->fullshare)));
  DEBUG(0,("%s\n", CNV_LANG(info->cur_dir)));
}


/****************************************************************************
change directory - inner section
****************************************************************************/
void do_cd(struct cli_state *cli, struct client_info *info, char *newdir)
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
void cmd_cd(struct cli_state *cli, struct client_info *info)
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
void cmd_dir(struct cli_state *cli, struct client_info *info)
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
void cmd_get(struct cli_state *cli, struct client_info *info)
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
void cmd_more(struct cli_state *cli, struct client_info *info)
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
void cmd_mget(struct cli_state *cli, struct client_info *info)
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
void cmd_mkdir(struct cli_state *cli, struct client_info *info)
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
void cmd_put(struct cli_state *cli, struct client_info *info)
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
void cmd_select(struct cli_state *cli, struct client_info *info)
{
  strcpy(info->file_sel,"");
  next_token(NULL,info->file_sel,NULL);
}


/****************************************************************************
  mput some files
  ****************************************************************************/
void cmd_mput(struct cli_state *cli, struct client_info *info)
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
void cmd_cancel(struct cli_state *cli, struct client_info *info)
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
void cmd_stat(struct cli_state *cli, struct client_info *info)
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
void cmd_print(struct cli_state *cli, struct client_info *info)
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
void cmd_queue(struct cli_state *cli, struct client_info *info)
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
void cmd_p_queue_2(struct cli_state *cli, struct client_info *info)
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
void cmd_qinfo(struct cli_state *cli, struct client_info *info)
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
void cmd_del(struct cli_state *cli, struct client_info *info)
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
void cmd_rmdir(struct cli_state *cli, struct client_info *info)
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
void cmd_rename(struct cli_state *cli, struct client_info *info)
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
void cmd_prompt(struct cli_state *cli, struct client_info *info)
{
  info->prompt = !info->prompt;
  DEBUG(2,("prompting is now %s\n", BOOLSTR(info->prompt)));
}


/****************************************************************************
set the newer than time
****************************************************************************/
void cmd_newer(struct cli_state *cli, struct client_info *info)
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
void cmd_archive(struct cli_state *cli, struct client_info *info)
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
void cmd_lowercase(struct cli_state *cli, struct client_info *info)
{
  info->lowercase = !info->lowercase;
  DEBUG(2,("filename lowercasing is now %s\n",info->lowercase?"on":"off"));
}




/****************************************************************************
toggle the info->recurse flag
****************************************************************************/
void cmd_recurse(struct cli_state *cli, struct client_info *info)
{
  info->recurse_dir = !info->recurse_dir;
  DEBUG(2,("directory recursion is now %s\n", BOOLSTR(info->recurse_dir)));
}

/****************************************************************************
toggle the translate flag
****************************************************************************/
void cmd_translate(struct cli_state *cli, struct client_info *info)
{
  info->translation = !info->translation;
  DEBUG(2,("CR/LF<->LF and print text info->translation now %s\n",
	info->translation?"on":"off"));
}


/****************************************************************************
do a print_mode command
****************************************************************************/
void cmd_printmode(struct cli_state *cli, struct client_info *info)
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
void cmd_lcd(struct cli_state *cli, struct client_info *info)
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
void cmd_quit(struct cli_state *cli, struct client_info *info)
{
	cli_shutdown(cli);
	exit(0);
}

