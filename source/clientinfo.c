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

extern pstring debugf;
extern int DEBUGLEVEL;


#define CNV_LANG(s) dos2unix_format(s,False)
#define CNV_INPUT(s) unix2dos_format(s,True)

/****************************************************************************
 smb client interactive commands
 ****************************************************************************/



/****************************************************************************
  set the file selection mask
  ****************************************************************************/
void cmd_select(struct client_info*info)
{
  strcpy(info->file_sel,"");
  next_token(NULL,info->file_sel,NULL);
}


/****************************************************************************
toggle the prompt flag
****************************************************************************/
void cmd_prompt(struct client_info*info)
{
  info->prompt = !info->prompt;
  DEBUG(2,("prompting is now %s\n", BOOLSTR(info->prompt)));
}


/****************************************************************************
set the newer than time
****************************************************************************/
void cmd_newer(struct client_info*info)
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
void cmd_archive(struct client_info*info)
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
void cmd_lowercase(struct client_info*info)
{
  info->lowercase = !info->lowercase;
  DEBUG(2,("filename lowercasing is now %s\n",info->lowercase?"on":"off"));
}




/****************************************************************************
toggle the info->recurse flag
****************************************************************************/
void cmd_recurse(struct client_info*info)
{
  info->recurse_dir = !info->recurse_dir;
  DEBUG(2,("directory recursion is now %s\n", BOOLSTR(info->recurse_dir)));
}

/****************************************************************************
toggle the translate flag
****************************************************************************/
void cmd_translate(struct client_info*info)
{
  info->translation = !info->translation;
  DEBUG(2,("CR/LF<->LF and print text info->translation now %s\n",
	info->translation?"on":"off"));
}


/****************************************************************************
do a print_mode command
****************************************************************************/
void cmd_printmode(struct client_info*info)
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
void cmd_lcd(struct client_info *info)
{
  fstring buf;
  pstring d;

  if (next_token(NULL,buf,NULL))
    sys_chdir(buf);
  DEBUG(2,("the local directory is now %s\n", GetWd(d)));
}



/****************************************************************************
 smb tar interactive commands
 ****************************************************************************/


/****************************************************************************
Blocksize command
***************************************************************************/
void cmd_block(struct client_info *info)
{
  fstring buf;
  int block;

  if (!next_token(NULL,buf,NULL))
    {
      DEBUG(0, ("blocksize <n>\n"));
      return;
    }

  block=atoi(buf);
  if (block < 0 || block > 65535)
    {
      DEBUG(0, ("blocksize out of range"));
      return;
    }

  info->tar.blocksize=block;
  DEBUG(1,("blocksize is now %d\n", info->tar.blocksize));
}

/****************************************************************************
command to set incremental / reset mode
***************************************************************************/
void cmd_tarmode(struct client_info *info)
{
  fstring buf;

  while (next_token(NULL,buf,NULL)) {
    if (strequal(buf, "full"))
      info->tar.inc=False;
    else if (strequal(buf, "inc"))
      info->tar.inc=True;
    else if (strequal(buf, "reset"))
      info->tar.reset=True;
    else if (strequal(buf, "noreset"))
      info->tar.reset=False;
    else DEBUG(0, ("tarmode: unrecognised option %s\n", buf));
  }

  DEBUG(0, ("tarmode is now %s, %s\n",
	    info->tar.inc ? "incremental" : "full",
	    info->tar.reset ? "reset" : "noreset"));
}

