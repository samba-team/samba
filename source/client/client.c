/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell 1994-1998
   
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

#define NO_SYSLOG

#include "includes.h"

#ifndef REGISTER
#define REGISTER 0
#endif

struct cli_state *cli;
extern BOOL in_client;
static int port = SMB_PORT;
pstring cur_dir = "\\";
pstring cd_path = "";
static pstring service;
static pstring desthost;
extern pstring global_myname;
static pstring password;
static pstring username;
static pstring workgroup;
static char *cmdstr;
static BOOL got_pass;
extern struct in_addr ipzero;
extern pstring scope;

static int name_type = 0x20;

extern pstring user_socket_options;

static int process_tok(fstring tok);
static void cmd_help(void);

/* 30 second timeout on most commands */
#define CLIENT_TIMEOUT (30*1000)
#define SHORT_TIMEOUT (5*1000)

/* value for unused fid field in trans2 secondary request */
#define FID_UNUSED (0xFFFF)

time_t newer_than = 0;
int archive_level = 0;

extern pstring debugf;
extern int DEBUGLEVEL;

BOOL translation = False;

static BOOL have_ip;

/* clitar bits insert */
extern int blocksize;
extern BOOL tar_inc;
extern BOOL tar_reset;
/* clitar bits end */
 

mode_t myumask = 0755;

BOOL prompt = True;

int printmode = 1;

static BOOL recurse = False;
BOOL lowercase = False;

struct in_addr dest_ip;

#define SEPARATORS " \t\n\r"

BOOL abort_mget = True;

pstring fileselection = "";

extern file_info def_finfo;

/* timing globals */
int get_total_size = 0;
int get_total_time_ms = 0;
int put_total_size = 0;
int put_total_time_ms = 0;

/* totals globals */
static double dir_total;

#define USENMB

#define CNV_LANG(s) dos_to_unix(s,False)
#define CNV_INPUT(s) unix_to_dos(s,True)


/****************************************************************************
write to a local file with CR/LF->LF translation if appropriate. return the 
number taken from the buffer. This may not equal the number written.
****************************************************************************/
static int writefile(int f, char *b, int n)
{
	int i;

	if (!translation) {
		return write(f,b,n);
	}

	i = 0;
	while (i < n) {
		if (*b == '\r' && (i<(n-1)) && *(b+1) == '\n') {
			b++;i++;
		}
		if (write(f, b, 1) != 1) {
			break;
		}
		b++;
		i++;
	}
  
	return(i);
}

/****************************************************************************
  read from a file with LF->CR/LF translation if appropriate. return the 
  number read. read approx n bytes.
****************************************************************************/
static int readfile(char *b, int size, int n, FILE *f)
{
	int i;
	int c;

	if (!translation || (size != 1))
		return(fread(b,size,n,f));
  
	i = 0;
	while (i < n) {
		if ((c = getc(f)) == EOF) {
			break;
		}
      
		if (c == '\n') { /* change all LFs to CR/LF */
			b[i++] = '\r';
			n++;
		}
      
		if(i < n)
			b[i++] = c;
	}
  
	return(i);
}
 

/****************************************************************************
send a message
****************************************************************************/
static void send_message(void)
{
	int total_len = 0;
	int grp_id;

	if (!cli_message_start(cli, desthost, username, &grp_id)) {
		DEBUG(0,("message start: %s\n", cli_errstr(cli)));
		return;
	}


	printf("Connected. Type your message, ending it with a Control-D\n");

	while (!feof(stdin) && total_len < 1600) {
		int maxlen = MIN(1600 - total_len,127);
		pstring msg;
		int l=0;
		int c;

		ZERO_ARRAY(msg);

		for (l=0;l<maxlen && (c=fgetc(stdin))!=EOF;l++) {
			if (c == '\n')
				msg[l++] = '\r';
			msg[l] = c;   
		}

		if (!cli_message_text(cli, msg, l, grp_id)) {
			printf("SMBsendtxt failed (%s)\n",cli_errstr(cli));
			return;
		}      
		
		total_len += l;
	}

	if (total_len >= 1600)
		printf("the message was truncated to 1600 bytes\n");
	else
		printf("sent %d bytes\n",total_len);

	if (!cli_message_end(cli, grp_id)) {
		printf("SMBsendend failed (%s)\n",cli_errstr(cli));
		return;
	}      
}



/****************************************************************************
check the space on a device
****************************************************************************/
static void do_dskattr(void)
{
	int total, bsize, avail;

	if (!cli_dskattr(cli, &bsize, &total, &avail)) {
		DEBUG(0,("Error in dskattr: %s\n",cli_errstr(cli))); 
		return;
	}

	DEBUG(0,("\n\t\t%d blocks of size %d. %d blocks available\n",
		 total, bsize, avail));
}

/****************************************************************************
show cd/pwd
****************************************************************************/
static void cmd_pwd(void)
{
	DEBUG(0,("Current directory is %s",CNV_LANG(service)));
	DEBUG(0,("%s\n",CNV_LANG(cur_dir)));
}


/****************************************************************************
change directory - inner section
****************************************************************************/
static void do_cd(char *newdir)
{
	char *p = newdir;
	pstring saved_dir;
	pstring dname;
      
	dos_format(newdir);

	/* Save the current directory in case the
	   new directory is invalid */
	pstrcpy(saved_dir, cur_dir);
	if (*p == '\\')
		pstrcpy(cur_dir,p);
	else
		pstrcat(cur_dir,p);
	if (*(cur_dir+strlen(cur_dir)-1) != '\\') {
		pstrcat(cur_dir, "\\");
	}
	dos_clean_name(cur_dir);
	pstrcpy(dname,cur_dir);
	pstrcat(cur_dir,"\\");
	dos_clean_name(cur_dir);
	
	if (!strequal(cur_dir,"\\")) {
		if (!cli_chkpath(cli, dname)) {
			DEBUG(0,("cd %s: %s\n", dname, cli_errstr(cli)));
			pstrcpy(cur_dir,saved_dir);
		}
	}
	
	pstrcpy(cd_path,cur_dir);
}

/****************************************************************************
change directory
****************************************************************************/
static void cmd_cd(void)
{
	fstring buf;

	if (next_token(NULL,buf,NULL,sizeof(buf)))
		do_cd(buf);
	else
		DEBUG(0,("Current directory is %s\n",CNV_LANG(cur_dir)));
}


/*******************************************************************
  decide if a file should be operated on
  ********************************************************************/
static BOOL do_this_one(file_info *finfo)
{
	if (finfo->mode & aDIR) return(True);

	if (*fileselection && 
	    !mask_match(finfo->name,fileselection,False,False)) {
		DEBUG(3,("match_match %s failed\n", finfo->name));
		return False;
	}

	if (newer_than && finfo->mtime < newer_than) {
		DEBUG(3,("newer_than %s failed\n", finfo->name));
		return(False);
	}

	if ((archive_level==1 || archive_level==2) && !(finfo->mode & aARCH)) {
		DEBUG(3,("archive %s failed\n", finfo->name));
		return(False);
	}
	
	return(True);
}

/****************************************************************************
  display info about a file
  ****************************************************************************/
static void display_finfo(file_info *finfo)
{
	if (do_this_one(finfo)) {
		time_t t = finfo->mtime; /* the time is assumed to be passed as GMT */
		DEBUG(0,("  %-30s%7.7s%8.0f  %s",
			 CNV_LANG(finfo->name),
			 attrib_string(finfo->mode),
			 (double)finfo->size,
			 asctime(LocalTime(&t))));
		dir_total += finfo->size;
	}
}


/****************************************************************************
   accumulate size of a file
  ****************************************************************************/
static void do_du(file_info *finfo)
{
	if (do_this_one(finfo)) {
		dir_total += finfo->size;
	}
}

static BOOL do_list_recurse;
static BOOL do_list_dirs;
static int do_list_attr;
static void (*do_list_fn)(file_info *);

/****************************************************************************
a helper for do_list
  ****************************************************************************/
static void do_list_helper(file_info *f, const char *mask)
{
	if (f->mode & aDIR) {
		if (do_list_dirs && do_this_one(f)) {
			do_list_fn(f);
		}
		if (do_list_recurse && 
		    !strequal(f->name,".") && 
		    !strequal(f->name,"..")) {
			pstring mask2;
			char *p;

			pstrcpy(mask2, mask);
			p = strrchr(mask2,'\\');
			if (!p) return;
			p[1] = 0;
			pstrcat(mask2, f->name);
			if (do_list_fn == display_finfo) {
				DEBUG(0,("\n%s\n",CNV_LANG(mask2)));
			}
			pstrcat(mask2,"\\*");
			do_list(mask2, do_list_attr, do_list_fn, True, True);
		}
		return;
	}

	if (do_this_one(f)) {
		do_list_fn(f);
	}
}


/****************************************************************************
a wrapper around cli_list that adds recursion
  ****************************************************************************/
void do_list(const char *mask,uint16 attribute,void (*fn)(file_info *),BOOL rec, BOOL dirs)
{
	do_list_recurse = rec;
	do_list_dirs = dirs;
	do_list_fn = fn;
	do_list_attr = attribute;

	cli_list(cli, mask, attribute, do_list_helper);
}

/****************************************************************************
  get a directory listing
  ****************************************************************************/
static void cmd_dir(void)
{
	uint16 attribute = aDIR | aSYSTEM | aHIDDEN;
	pstring mask;
	fstring buf;
	char *p=buf;
	
	dir_total = 0;
	pstrcpy(mask,cur_dir);
	if(mask[strlen(mask)-1]!='\\')
		pstrcat(mask,"\\");
	
	if (next_token(NULL,buf,NULL,sizeof(buf))) {
		dos_format(p);
		if (*p == '\\')
			pstrcpy(mask,p);
		else
			pstrcat(mask,p);
	}
	else {
		pstrcat(mask,"*");
	}

	do_list(mask, attribute, display_finfo, recurse, True);

	do_dskattr();

	DEBUG(3, ("Total bytes listed: %.0f\n", dir_total));
}


/****************************************************************************
  get a directory listing
  ****************************************************************************/
static void cmd_du(void)
{
	uint16 attribute = aDIR | aSYSTEM | aHIDDEN;
	pstring mask;
	fstring buf;
	char *p=buf;
	
	dir_total = 0;
	pstrcpy(mask,cur_dir);
	if(mask[strlen(mask)-1]!='\\')
		pstrcat(mask,"\\");
	
	if (next_token(NULL,buf,NULL,sizeof(buf))) {
		dos_format(p);
		if (*p == '\\')
			pstrcpy(mask,p);
		else
			pstrcat(mask,p);
	} else {
		pstrcat(mask,"*");
	}

	do_list(mask, attribute, do_du, recurse, True);

	do_dskattr();

	DEBUG(0, ("Total number of bytes: %.0f\n", dir_total));
}


/****************************************************************************
  get a file from rname to lname
  ****************************************************************************/
static void do_get(char *rname,char *lname)
{  
	int handle=0,fnum;
	BOOL newhandle = False;
	char *data;
	struct timeval tp_start;
	int read_size = 65520;
	uint16 attr;
	size_t size;
	off_t nread = 0;

	GetTimeOfDay(&tp_start);

	if (lowercase) {
		strlower(lname);
	}

	fnum = cli_open(cli, rname, O_RDONLY, DENY_NONE);

	if (fnum == -1) {
		DEBUG(0,("%s opening remote file %s\n",cli_errstr(cli),CNV_LANG(rname)));
		return;
	}

	if(!strcmp(lname,"-")) {
		handle = fileno(stdout);
	} else {
		handle = sys_open(lname,O_WRONLY|O_CREAT|O_TRUNC,0644);
		newhandle = True;
	}
	if (handle < 0) {
		DEBUG(0,("Error opening local file %s\n",lname));
		return;
	}


	if (!cli_qfileinfo(cli, fnum, 
			   &attr, &size, NULL, NULL, NULL, NULL, NULL) &&
	    !cli_getattrE(cli, fnum, 
			  &attr, &size, NULL, NULL, NULL)) {
		DEBUG(0,("getattrib: %s\n",cli_errstr(cli)));
		return;
	}

	DEBUG(2,("getting file %s of size %.0f as %s ", 
		 lname, (double)size, lname));

	data = (char *)malloc(read_size);

	while (1) {
		int n = cli_read(cli, fnum, data, nread, read_size, True);

		if (n <= 0) break;
 
		if (writefile(handle,data, n) != n) {
			DEBUG(0,("Error writing local file\n"));
			break;
		}
      
		nread += n;
	}
	
	if (!cli_close(cli, fnum)) {
		DEBUG(0,("Error %s closing remote file\n",cli_errstr(cli)));
	}

	if (newhandle) {
		close(handle);
	}

	if (archive_level >= 2 && (attr & aARCH)) {
		cli_setatr(cli, rname, attr & ~(uint16)aARCH, 0);
	}

	{
		struct timeval tp_end;
		int this_time;
		
		GetTimeOfDay(&tp_end);
		this_time = 
			(tp_end.tv_sec - tp_start.tv_sec)*1000 +
			(tp_end.tv_usec - tp_start.tv_usec)/1000;
		get_total_time_ms += this_time;
		get_total_size += nread;
		
		DEBUG(2,("(%g kb/s) (average %g kb/s)\n",
			 nread / (1.024*this_time + 1.0e-4),
			 get_total_size / (1.024*get_total_time_ms)));
	}
}


/****************************************************************************
  get a file
  ****************************************************************************/
static void cmd_get(void)
{
	pstring lname;
	pstring rname;
	char *p;

	pstrcpy(rname,cur_dir);
	pstrcat(rname,"\\");
	
	p = rname + strlen(rname);
	
	if (!next_token(NULL,p,NULL,sizeof(rname)-strlen(rname))) {
		DEBUG(0,("get <filename>\n"));
		return;
	}
	pstrcpy(lname,p);
	dos_clean_name(rname);
	
	next_token(NULL,lname,NULL,sizeof(lname));
	
	do_get(rname, lname);
}


/****************************************************************************
  do a mget operation on one file
  ****************************************************************************/
static void do_mget(file_info *finfo)
{
	pstring rname;
	pstring quest;
	pstring saved_curdir;
	pstring mget_mask;

	if (strequal(finfo->name,".") || strequal(finfo->name,".."))
		return;

	if (abort_mget)	{
		DEBUG(0,("mget aborted\n"));
		return;
	}

	if (finfo->mode & aDIR)
		slprintf(quest,sizeof(pstring)-1,
			 "Get directory %s? ",CNV_LANG(finfo->name));
	else
		slprintf(quest,sizeof(pstring)-1,
			 "Get file %s? ",CNV_LANG(finfo->name));

	if (prompt && !yesno(quest)) return;

	if (!(finfo->mode & aDIR)) {
		pstrcpy(rname,cur_dir);
		pstrcat(rname,finfo->name);
		do_get(rname,finfo->name);
		return;
	}

	/* handle directories */
	pstrcpy(saved_curdir,cur_dir);

	pstrcat(cur_dir,finfo->name);
	pstrcat(cur_dir,"\\");

	unix_format(finfo->name);
	if (lowercase)
		strlower(finfo->name);
	
	if (!dos_directory_exist(finfo->name,NULL) && 
	    dos_mkdir(finfo->name,0777) != 0) {
		DEBUG(0,("failed to create directory %s\n",CNV_LANG(finfo->name)));
		pstrcpy(cur_dir,saved_curdir);
		return;
	}
	
	if (dos_chdir(finfo->name) != 0) {
		DEBUG(0,("failed to chdir to directory %s\n",CNV_LANG(finfo->name)));
		pstrcpy(cur_dir,saved_curdir);
		return;
	}

	pstrcpy(mget_mask,cur_dir);
	pstrcat(mget_mask,"*");
	
	do_list(mget_mask, aSYSTEM | aHIDDEN | aDIR,do_mget,False, True);
	chdir("..");
	pstrcpy(cur_dir,saved_curdir);
}


/****************************************************************************
view the file using the pager
****************************************************************************/
static void cmd_more(void)
{
	fstring rname,lname,tmpname,pager_cmd;
	char *pager;

	fstrcpy(rname,cur_dir);
	fstrcat(rname,"\\");
	slprintf(tmpname,
		 sizeof(fstring)-1,
		 "%s/smbmore.%d",tmpdir(),(int)getpid());
	fstrcpy(lname,tmpname);
	
	if (!next_token(NULL,rname+strlen(rname),NULL,sizeof(rname)-strlen(rname))) {
		DEBUG(0,("more <filename>\n"));
		return;
	}
	dos_clean_name(rname);

	do_get(rname,lname);

	pager=getenv("PAGER");

	slprintf(pager_cmd,sizeof(pager_cmd)-1,
		 "%s %s",(pager? pager:PAGER), tmpname);
	system(pager_cmd);
	unlink(tmpname);
}



/****************************************************************************
do a mget command
****************************************************************************/
static void cmd_mget(void)
{
	uint16 attribute = aSYSTEM | aHIDDEN;
	pstring mget_mask;
	fstring buf;
	char *p=buf;

	*mget_mask = 0;

	if (recurse)
		attribute |= aDIR;
	
	abort_mget = False;

	while (next_token(NULL,p,NULL,sizeof(buf))) {
		pstrcpy(mget_mask,cur_dir);
		if(mget_mask[strlen(mget_mask)-1]!='\\')
			pstrcat(mget_mask,"\\");
		
		if (*p == '\\')
			pstrcpy(mget_mask,p);
		else
			pstrcat(mget_mask,p);
		do_list(mget_mask, attribute,do_mget,False,True);
	}

	if (!*mget_mask) {
		pstrcpy(mget_mask,cur_dir);
		if(mget_mask[strlen(mget_mask)-1]!='\\')
			pstrcat(mget_mask,"\\");
		pstrcat(mget_mask,"*");
		do_list(mget_mask, attribute,do_mget,False,True);
	}
}


/****************************************************************************
make a directory of name "name"
****************************************************************************/
static BOOL do_mkdir(char *name)
{
	if (!cli_mkdir(cli, name)) {
		DEBUG(0,("%s making remote directory %s\n",
			 cli_errstr(cli),CNV_LANG(name)));
		return(False);
	}

	return(True);
}


/****************************************************************************
make a directory of name "name"
****************************************************************************/
static void cmd_quit(void)
{
	cli_shutdown(cli);
	exit(0);
}


/****************************************************************************
  make a directory
  ****************************************************************************/
static void cmd_mkdir(void)
{
	pstring mask;
	fstring buf;
	char *p=buf;
  
	pstrcpy(mask,cur_dir);

	if (!next_token(NULL,p,NULL,sizeof(buf))) {
		if (!recurse)
			DEBUG(0,("mkdir <dirname>\n"));
		return;
	}
	pstrcat(mask,p);

	if (recurse) {
		pstring ddir;
		pstring ddir2;
		*ddir2 = 0;
		
		pstrcpy(ddir,mask);
		trim_string(ddir,".",NULL);
		p = strtok(ddir,"/\\");
		while (p) {
			pstrcat(ddir2,p);
			if (!cli_chkpath(cli, ddir2)) { 
				do_mkdir(ddir2);
			}
			pstrcat(ddir2,"\\");
			p = strtok(NULL,"/\\");
		}	 
	} else {
		do_mkdir(mask);
	}
}


/****************************************************************************
  put a single file
  ****************************************************************************/
static void do_put(char *rname,char *lname)
{
	int fnum;
	FILE *f;
	int nread=0;
	char *buf=NULL;
	int maxwrite=65520;
	
	struct timeval tp_start;
	GetTimeOfDay(&tp_start);

	fnum = cli_open(cli, rname, O_WRONLY|O_CREAT|O_TRUNC, DENY_NONE);
  
	if (fnum == -1) {
		DEBUG(0,("%s opening remote file %s\n",cli_errstr(cli),CNV_LANG(rname)));
		return;
	}

	/* allow files to be piped into smbclient
	   jdblair 24.jun.98 */
	if (!strcmp(lname, "-")) {
		f = stdin;
		/* size of file is not known */
	} else {
		f = sys_fopen(lname,"r");
	}

	if (!f) {
		DEBUG(0,("Error opening local file %s\n",lname));
		return;
	}

  
	DEBUG(1,("putting file %s as %s ",lname,
		 CNV_LANG(rname)));
  
	buf = (char *)malloc(maxwrite);
	while (!feof(f)) {
		int n = maxwrite;
		int ret;

		if ((n = readfile(buf,1,n,f)) < 1) {
			DEBUG(0,("Error reading local file\n"));
			break;
		}

		ret = cli_write(cli, fnum, 0, buf, nread, n, 0);

		if (n != ret) {
			DEBUG(0,("Error writing file: %s\n", cli_errstr(cli)));
			break;
		} 

		nread += n;
	}

	if (!cli_close(cli, fnum)) {
		DEBUG(0,("%s closing remote file %s\n",cli_errstr(cli),CNV_LANG(rname)));
		fclose(f);
		if (buf) free(buf);
		return;
	}

	
	fclose(f);
	if (buf) free(buf);

	{
		struct timeval tp_end;
		int this_time;
		
		GetTimeOfDay(&tp_end);
		this_time = 
			(tp_end.tv_sec - tp_start.tv_sec)*1000 +
			(tp_end.tv_usec - tp_start.tv_usec)/1000;
		put_total_time_ms += this_time;
		put_total_size += nread;
		
		DEBUG(1,("(%g kb/s) (average %g kb/s)\n",
			 nread / (1.024*this_time + 1.0e-4),
			 put_total_size / (1.024*put_total_time_ms)));
	}

	if (f == stdin) {
		cli_shutdown(cli);
		exit(0);
	}
}

 

/****************************************************************************
  put a file
  ****************************************************************************/
static void cmd_put(void)
{
	pstring lname;
	pstring rname;
	fstring buf;
	char *p=buf;
	
	pstrcpy(rname,cur_dir);
	pstrcat(rname,"\\");
  
	if (!next_token(NULL,p,NULL,sizeof(buf))) {
		DEBUG(0,("put <filename>\n"));
		return;
	}
	pstrcpy(lname,p);
  
	if (next_token(NULL,p,NULL,sizeof(buf)))
		pstrcat(rname,p);      
	else
		pstrcat(rname,lname);
	
	dos_clean_name(rname);

	{
		SMB_STRUCT_STAT st;
		/* allow '-' to represent stdin
		   jdblair, 24.jun.98 */
		if (!file_exist(lname,&st) &&
		    (strcmp(lname,"-"))) {
			DEBUG(0,("%s does not exist\n",lname));
			return;
		}
	}

	do_put(rname,lname);
}


/****************************************************************************
  seek in a directory/file list until you get something that doesn't start with
  the specified name
  ****************************************************************************/
static BOOL seek_list(FILE *f,char *name)
{
	pstring s;
	while (!feof(f)) {
		if (fscanf(f,"%s",s) != 1) return(False);
		trim_string(s,"./",NULL);
		if (strncmp(s,name,strlen(name)) != 0) {
			pstrcpy(name,s);
			return(True);
		}
	}
      
	return(False);
}


/****************************************************************************
  set the file selection mask
  ****************************************************************************/
static void cmd_select(void)
{
	pstrcpy(fileselection,"");
	next_token(NULL,fileselection,NULL,sizeof(fileselection));
}


/****************************************************************************
  mput some files
  ****************************************************************************/
static void cmd_mput(void)
{
	pstring lname;
	pstring rname;
	fstring buf;
	char *p=buf;
	
	while (next_token(NULL,p,NULL,sizeof(buf))) {
		SMB_STRUCT_STAT st;
		pstring cmd;
		pstring tmpname;
		FILE *f;
		
		slprintf(tmpname,sizeof(pstring)-1,
			 "%s/ls.smb.%d",tmpdir(),(int)getpid());
		if (recurse)
			slprintf(cmd,sizeof(pstring)-1,
				 "find . -name \"%s\" -print > %s",p,tmpname);
		else
			slprintf(cmd,sizeof(pstring)-1,
				 "/bin/ls %s > %s",p,tmpname);
		system(cmd);

		f = sys_fopen(tmpname,"r");
		if (!f) continue;
		
		while (!feof(f)) {
			pstring quest;

			if (fscanf(f,"%s",lname) != 1) break;
			trim_string(lname,"./",NULL);
			
		again1:
			
			/* check if it's a directory */
			if (directory_exist(lname,&st)) {
				if (!recurse) continue;
				slprintf(quest,sizeof(pstring)-1,
					 "Put directory %s? ",lname);
				if (prompt && !yesno(quest)) {
					pstrcat(lname,"/");
					if (!seek_list(f,lname))
						break;
					goto again1;		    
				}
	      
				pstrcpy(rname,cur_dir);
				pstrcat(rname,lname);
				if (!cli_chkpath(cli, rname) && !do_mkdir(rname)) {
					pstrcat(lname,"/");
					if (!seek_list(f,lname))
						break;
					goto again1;
				}
				continue;
			} else {
				slprintf(quest,sizeof(quest)-1,
					 "Put file %s? ",lname);
				if (prompt && !yesno(quest)) continue;
				
				pstrcpy(rname,cur_dir);
				pstrcat(rname,lname);
			}

			dos_format(rname);

			do_put(rname,lname);
		}
		fclose(f);
		unlink(tmpname);
	}
}


/****************************************************************************
  cancel a print job
  ****************************************************************************/
static void do_cancel(int job)
{
	if (cli_printjob_del(cli, job)) {
		printf("Job %d cancelled\n",job);
	} else {
		printf("Error calcelling job %d : %s\n",job,cli_errstr(cli));
	}
}


/****************************************************************************
  cancel a print job
  ****************************************************************************/
static void cmd_cancel(void)
{
	fstring buf;
	int job; 

	if (!next_token(NULL,buf,NULL,sizeof(buf))) {
		printf("cancel <jobid> ...\n");
		return;
	}
	do {
		job = atoi(buf);
		do_cancel(job);
	} while (next_token(NULL,buf,NULL,sizeof(buf)));
}


/****************************************************************************
  print a file
  ****************************************************************************/
static void cmd_print(void)
{
	pstring lname;
	pstring rname;
	char *p;

	if (!next_token(NULL,lname,NULL, sizeof(lname))) {
		DEBUG(0,("print <filename>\n"));
		return;
	}

	pstrcpy(rname,lname);
	p = strrchr(rname,'/');
	if (p) {
		slprintf(rname, sizeof(rname)-1, "%s-%d", p+1, (int)getpid());
	}

	if (strequal(lname,"-")) {
		slprintf(rname, sizeof(rname)-1, "stdin-%d", (int)getpid());
	}

	do_put(rname, lname);
}


/****************************************************************************
 show a print queue entry
****************************************************************************/
static void queue_fn(struct print_job_info *p)
{
	DEBUG(0,("%-6d   %-9d    %s\n", (int)p->id, (int)p->size, p->name));
}

/****************************************************************************
 show a print queue
****************************************************************************/
static void cmd_queue(void)
{
	cli_print_queue(cli, queue_fn);  
}

/****************************************************************************
delete some files
****************************************************************************/
static void do_del(file_info *finfo)
{
	pstring mask;

	pstrcpy(mask,cur_dir);
	pstrcat(mask,finfo->name);

	if (finfo->mode & aDIR) 
		return;

	if (!cli_unlink(cli, mask)) {
		DEBUG(0,("%s deleting remote file %s\n",cli_errstr(cli),CNV_LANG(mask)));
	}
}

/****************************************************************************
delete some files
****************************************************************************/
static void cmd_del(void)
{
	pstring mask;
	fstring buf;
	uint16 attribute = aSYSTEM | aHIDDEN;

	if (recurse)
		attribute |= aDIR;
	
	pstrcpy(mask,cur_dir);
	
	if (!next_token(NULL,buf,NULL,sizeof(buf))) {
		DEBUG(0,("del <filename>\n"));
		return;
	}
	pstrcat(mask,buf);

	do_list(mask, attribute,do_del,False,False);
}


/****************************************************************************
remove a directory
****************************************************************************/
static void cmd_rmdir(void)
{
	pstring mask;
	fstring buf;
  
	pstrcpy(mask,cur_dir);
	
	if (!next_token(NULL,buf,NULL,sizeof(buf))) {
		DEBUG(0,("rmdir <dirname>\n"));
		return;
	}
	pstrcat(mask,buf);

	if (!cli_rmdir(cli, mask)) {
		DEBUG(0,("%s removing remote directory file %s\n",
			 cli_errstr(cli),CNV_LANG(mask)));
	}  
}

/****************************************************************************
rename some files
****************************************************************************/
static void cmd_rename(void)
{
	pstring src,dest;
	fstring buf,buf2;
  
	pstrcpy(src,cur_dir);
	pstrcpy(dest,cur_dir);
	
	if (!next_token(NULL,buf,NULL,sizeof(buf)) || 
	    !next_token(NULL,buf2,NULL, sizeof(buf2))) {
		DEBUG(0,("rename <src> <dest>\n"));
		return;
	}

	pstrcat(src,buf);
	pstrcat(dest,buf2);

	if (!cli_rename(cli, src, dest)) {
		DEBUG(0,("%s renaming files\n",cli_errstr(cli)));
		return;
	}  
}


/****************************************************************************
toggle the prompt flag
****************************************************************************/
static void cmd_prompt(void)
{
	prompt = !prompt;
	DEBUG(2,("prompting is now %s\n",prompt?"on":"off"));
}


/****************************************************************************
set the newer than time
****************************************************************************/
static void cmd_newer(void)
{
	fstring buf;
	BOOL ok;
	SMB_STRUCT_STAT sbuf;

	ok = next_token(NULL,buf,NULL,sizeof(buf));
	if (ok && (dos_stat(buf,&sbuf) == 0)) {
		newer_than = sbuf.st_mtime;
		DEBUG(1,("Getting files newer than %s",
			 asctime(LocalTime(&newer_than))));
	} else {
		newer_than = 0;
	}

	if (ok && newer_than == 0)
		DEBUG(0,("Error setting newer-than time\n"));
}

/****************************************************************************
set the archive level
****************************************************************************/
static void cmd_archive(void)
{
	fstring buf;

	if (next_token(NULL,buf,NULL,sizeof(buf))) {
		archive_level = atoi(buf);
	} else
		DEBUG(0,("Archive level is %d\n",archive_level));
}

/****************************************************************************
toggle the lowercaseflag
****************************************************************************/
static void cmd_lowercase(void)
{
	lowercase = !lowercase;
	DEBUG(2,("filename lowercasing is now %s\n",lowercase?"on":"off"));
}




/****************************************************************************
toggle the recurse flag
****************************************************************************/
static void cmd_recurse(void)
{
	recurse = !recurse;
	DEBUG(2,("directory recursion is now %s\n",recurse?"on":"off"));
}

/****************************************************************************
toggle the translate flag
****************************************************************************/
static void cmd_translate(void)
{
	translation = !translation;
	DEBUG(2,("CR/LF<->LF and print text translation now %s\n",
		 translation?"on":"off"));
}


/****************************************************************************
do a printmode command
****************************************************************************/
static void cmd_printmode(void)
{
	fstring buf;
	fstring mode;

	if (next_token(NULL,buf,NULL,sizeof(buf))) {
		if (strequal(buf,"text")) {
			printmode = 0;      
		} else {
			if (strequal(buf,"graphics"))
				printmode = 1;
			else
				printmode = atoi(buf);
		}
	}

	switch(printmode)
		{
		case 0: 
			fstrcpy(mode,"text");
			break;
		case 1: 
			fstrcpy(mode,"graphics");
			break;
		default: 
			slprintf(mode,sizeof(mode)-1,"%d",printmode);
			break;
		}
	
	DEBUG(2,("the printmode is now %s\n",mode));
}

/****************************************************************************
do the lcd command
****************************************************************************/
static void cmd_lcd(void)
{
	fstring buf;
	pstring d;
	
	if (next_token(NULL,buf,NULL,sizeof(buf)))
		chdir(buf);
	DEBUG(2,("the local directory is now %s\n",sys_getwd(d)));
}

/****************************************************************************
list a share name
****************************************************************************/
static void browse_fn(const char *name, uint32 m, const char *comment)
{
        fstring typestr;
        *typestr=0;

        switch (m)
        {
          case STYPE_DISKTREE:
            fstrcpy(typestr,"Disk"); break;
          case STYPE_PRINTQ:
            fstrcpy(typestr,"Printer"); break;
          case STYPE_DEVICE:
            fstrcpy(typestr,"Device"); break;
          case STYPE_IPC:
            fstrcpy(typestr,"IPC"); break;
        }

        printf("\t%-15.15s%-10.10s%s\n",
               name, typestr,comment);
}


/****************************************************************************
try and browse available connections on a host
****************************************************************************/
static BOOL browse_host(BOOL sort)
{
        printf("\n\tSharename      Type      Comment\n");
        printf("\t---------      ----      -------\n");

	return cli_RNetShareEnum(cli, browse_fn);
}

/****************************************************************************
list a server name
****************************************************************************/
static void server_fn(const char *name, uint32 m, const char *comment)
{
        printf("\t%-16.16s     %s\n", name, comment);
}

/****************************************************************************
try and browse available connections on a host
****************************************************************************/
static BOOL list_servers(char *wk_grp)
{
        printf("\n\tServer               Comment\n");
        printf("\t---------            -------\n");

	cli_NetServerEnum(cli, workgroup, SV_TYPE_ALL, server_fn);

        printf("\n\tWorkgroup            Master\n");
        printf("\t---------            -------\n");

	cli_NetServerEnum(cli, workgroup, SV_TYPE_DOMAIN_ENUM, server_fn);
	return True;
}


/* Some constants for completing filename arguments */

#define COMPL_NONE        0          /* No completions */
#define COMPL_REMOTE      1          /* Complete remote filename */
#define COMPL_LOCAL       2          /* Complete local filename */

/* This defines the commands supported by this client */
struct
{
  char *name;
  void (*fn)(void);
  char *description;
  char compl_args[2];      /* Completion argument info */
} commands[] = 
{
  {"ls",cmd_dir,"<mask> list the contents of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"dir",cmd_dir,"<mask> list the contents of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"du",cmd_du,"<mask> computes the total size of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"lcd",cmd_lcd,"[directory] change/report the local current working directory",{COMPL_LOCAL,COMPL_NONE}},
  {"cd",cmd_cd,"[directory] change/report the remote directory",{COMPL_REMOTE,COMPL_NONE}},
  {"pwd",cmd_pwd,"show current remote directory (same as 'cd' with no args)",{COMPL_NONE,COMPL_NONE}},
  {"get",cmd_get,"<remote name> [local name] get a file",{COMPL_REMOTE,COMPL_LOCAL}},
  {"mget",cmd_mget,"<mask> get all the matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"put",cmd_put,"<local name> [remote name] put a file",{COMPL_LOCAL,COMPL_REMOTE}},
  {"mput",cmd_mput,"<mask> put all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"rename",cmd_rename,"<src> <dest> rename some files",{COMPL_REMOTE,COMPL_REMOTE}},
  {"more",cmd_more,"<remote name> view a remote file with your pager",{COMPL_REMOTE,COMPL_NONE}},  
  {"mask",cmd_select,"<mask> mask all filenames against this",{COMPL_REMOTE,COMPL_NONE}},
  {"del",cmd_del,"<mask> delete all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"rm",cmd_del,"<mask> delete all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"mkdir",cmd_mkdir,"<directory> make a directory",{COMPL_NONE,COMPL_NONE}},
  {"md",cmd_mkdir,"<directory> make a directory",{COMPL_NONE,COMPL_NONE}},
  {"rmdir",cmd_rmdir,"<directory> remove a directory",{COMPL_NONE,COMPL_NONE}},
  {"rd",cmd_rmdir,"<directory> remove a directory",{COMPL_NONE,COMPL_NONE}},
  {"prompt",cmd_prompt,"toggle prompting for filenames for mget and mput",{COMPL_NONE,COMPL_NONE}},  
  {"recurse",cmd_recurse,"toggle directory recursion for mget and mput",{COMPL_NONE,COMPL_NONE}},  
  {"translate",cmd_translate,"toggle text translation for printing",{COMPL_NONE,COMPL_NONE}},  
  {"lowercase",cmd_lowercase,"toggle lowercasing of filenames for get",{COMPL_NONE,COMPL_NONE}},  
  {"print",cmd_print,"<file name> print a file",{COMPL_NONE,COMPL_NONE}},
  {"printmode",cmd_printmode,"<graphics or text> set the print mode",{COMPL_NONE,COMPL_NONE}},
  {"queue",cmd_queue,"show the print queue",{COMPL_NONE,COMPL_NONE}},
  {"cancel",cmd_cancel,"<jobid> cancel a print queue entry",{COMPL_NONE,COMPL_NONE}},
  {"quit",cmd_quit,"logoff the server",{COMPL_NONE,COMPL_NONE}},
  {"q",cmd_quit,"logoff the server",{COMPL_NONE,COMPL_NONE}},
  {"exit",cmd_quit,"logoff the server",{COMPL_NONE,COMPL_NONE}},
  {"newer",cmd_newer,"<file> only mget files newer than the specified local file",{COMPL_LOCAL,COMPL_NONE}},
  {"archive",cmd_archive,"<level>\n0=ignore archive bit\n1=only get archive files\n2=only get archive files and reset archive bit\n3=get all files and reset archive bit",{COMPL_NONE,COMPL_NONE}},
  {"tar",cmd_tar,"tar <c|x>[IXFqbgNan] current directory to/from <file name>",{COMPL_NONE,COMPL_NONE}},
  {"blocksize",cmd_block,"blocksize <number> (default 20)",{COMPL_NONE,COMPL_NONE}},
  {"tarmode",cmd_tarmode,
     "<full|inc|reset|noreset> tar's behaviour towards archive bits",{COMPL_NONE,COMPL_NONE}},
  {"setmode",cmd_setmode,"filename <setmode string> change modes of file",{COMPL_REMOTE,COMPL_NONE}},
  {"help",cmd_help,"[command] give help on a command",{COMPL_NONE,COMPL_NONE}},
  {"?",cmd_help,"[command] give help on a command",{COMPL_NONE,COMPL_NONE}},
  {"!",NULL,"run a shell command on the local system",{COMPL_NONE,COMPL_NONE}},
  {"",NULL,NULL,{COMPL_NONE,COMPL_NONE}}
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
	
	while (commands[i].fn != NULL) {
		if (strequal(commands[i].name,tok)) {
			matches = 1;
			cmd = i;
			break;
		} else if (strnequal(commands[i].name, tok, tok_len)) {
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
static void cmd_help(void)
{
	int i=0,j;
	fstring buf;
	
	if (next_token(NULL,buf,NULL,sizeof(buf))) {
		if ((i = process_tok(buf)) >= 0)
			DEBUG(0,("HELP %s:\n\t%s\n\n",commands[i].name,commands[i].description));		    
	} else {
		while (commands[i].description) {
			for (j=0; commands[i].description && (j<5); j++) {
				DEBUG(0,("%-15s",commands[i].name));
				i++;
			}
			DEBUG(0,("\n"));
		}
	}
}

/****************************************************************************
wait for keyboard activity, swallowing network packets
****************************************************************************/
static void wait_keyboard(void)
{
	fd_set fds;
	struct timeval timeout;
  
	while (1) {
		FD_ZERO(&fds);
		FD_SET(cli->fd,&fds);
		FD_SET(fileno(stdin),&fds);

		timeout.tv_sec = 20;
		timeout.tv_usec = 0;
		sys_select(MAX(cli->fd,fileno(stdin))+1,&fds,NULL, &timeout);
      
		if (FD_ISSET(fileno(stdin),&fds))
			return;

		/* We deliberately use receive_smb instead of
		   client_receive_smb as we want to receive
		   session keepalives and then drop them here.
		*/
		if (FD_ISSET(cli->fd,&fds))
			receive_smb(cli->fd,cli->inbuf,0);
      
		cli_chkpath(cli, "\\");
	}  
}

/****************************************************************************
process a -c command string
****************************************************************************/
static void process_command_string(char *cmd)
{
	pstring line;
	char *ptr;

	while (cmd[0] != '\0')    {
		char *p;
		fstring tok;
		int i;
		
		if ((p = strchr(cmd, ';')) == 0) {
			strncpy(line, cmd, 999);
			line[1000] = '\0';
			cmd += strlen(cmd);
		} else {
			if (p - cmd > 999) p = cmd + 999;
			strncpy(line, cmd, p - cmd);
			line[p - cmd] = '\0';
			cmd = p + 1;
		}
		
		/* input language code to internal one */
		CNV_INPUT (line);
		
		/* and get the first part of the command */
		ptr = line;
		if (!next_token(&ptr,tok,NULL,sizeof(tok))) continue;
		
		if ((i = process_tok(tok)) >= 0) {
			commands[i].fn();
		} else if (i == -2) {
			DEBUG(0,("%s: command abbreviation ambiguous\n",CNV_LANG(tok)));
		} else {
			DEBUG(0,("%s: command not found\n",CNV_LANG(tok)));
		}
	}
}	

#ifdef HAVE_LIBREADLINE

/****************************************************************************
GNU readline completion functions
****************************************************************************/

/* Argh.  This is where it gets ugly.  We really need to be able to
   pass back from the do_list() iterator function. */

static int compl_state;
static char *compl_text;
static pstring result;

/* Iterator function for do_list() */

static void complete_process_file(file_info *f)
{
    /* Do we have a partial match? */
    
    if ((compl_state >= 0) && (strncmp(compl_text, f->name, 
				       strlen(compl_text)) == 0)) {
	
	/* Return filename if we have made enough matches */
	
	if (compl_state == 0) {
	    pstrcpy(result, f->name);
	    compl_state = -1;
	    
	    return;
	}
	compl_state--;
    }
}

/* Complete a remote file */

static char *complete_remote_file(char *text, int state)
{
    int attribute = aDIR | aSYSTEM | aHIDDEN;
    pstring mask;
    
    /* Create dir mask */
    
    pstrcpy(mask, cur_dir);
    pstrcat(mask, "*");
    
    /* Initialise static vars for filename match */
    
    compl_text = text;
    compl_state = state;
    result[0] = '\0';
    
    /* Iterate over all files in directory */
    
    do_list(mask, attribute, complete_process_file, False, True);
    
    /* Return matched filename */
    
    if (result[0] != '\0') {
	return strdup(result);      /* Readline will dispose of strings */
    } else {
	return NULL;
    }
}

/* Complete a smbclient command */

static char *complete_cmd(char *text, int state)
{
    static int cmd_index;
    char *name;
    
    /* Initialise */
    
    if (state == 0) {
	cmd_index = 0;
    }
    
    /* Return the next name which partially matches the list of commands */
    
    while (strlen(name = commands[cmd_index++].name) > 0) {
	if (strncmp(name, text, strlen(text)) == 0) {
	    return strdup(name);
	}
    }
    
    return NULL;
}

/* Main completion function for smbclient.  Work out which word we are
   trying to complete and call the appropriate helper function -
   complete_cmd() if we are completing smbclient commands,
   comlete_remote_file() if we are completing a file on the remote end,
   filename_completion_function() builtin to GNU readline for local 
   files. */

static char **completion_fn(char *text, int start, int end)
{
  int i, num_words, cmd_index;
  char lastch = ' ';

  /* If we are at the start of a word, we are completing a smbclient
     command. */

  if (start == 0) {
    return completion_matches(text, complete_cmd);
  }

  /* Count # of words in command */

  num_words = 0;
  for (i = 0; i <= end; i++) {
    if ((rl_line_buffer[i] != ' ') && (lastch == ' '))
      num_words++;
    lastch = rl_line_buffer[i];
  }

  if (rl_line_buffer[end] == ' ')
    num_words++;

  /* Work out which command we are completing for */

  for (cmd_index = 0; strcmp(commands[cmd_index].name, "") != 0; 
       cmd_index++) {

    /* Check each command in array */

    if (strncmp(rl_line_buffer, commands[cmd_index].name,
                strlen(commands[cmd_index].name)) == 0) {

      /* Call appropriate completion function */

      if ((num_words == 2) || (num_words == 3)) {
        switch (commands[cmd_index].compl_args[num_words - 2]) {

        case COMPL_REMOTE:
          return completion_matches(text, complete_remote_file);
          break;

        case COMPL_LOCAL:
          return completion_matches(text, filename_completion_function);
          break;

        default:
            /* An invalid completion type */
            break;
        }
      }

      /* We're either completing an argument > 3 or found an invalid
         completion type.  Either way do nothing about it. */

      break;
    }
  }
 
  return NULL;
}

/* To avoid filename completion being activated when no valid
   completions are found, we assign this stub completion function
   to the rl_completion_entry_function variable. */

static char *complete_cmd_null(char *text, int state)
{
    return NULL;
}

#endif /* HAVE_LIBREADLINE */

/****************************************************************************
process commands on stdin
****************************************************************************/
static void process_stdin(void)
{
	pstring line;
#ifdef HAVE_LIBREADLINE
	pstring promptline;
#endif
	char *ptr;

	while (!feof(stdin)) {
		fstring tok;
		int i;

#ifndef HAVE_LIBREADLINE

		/* display a prompt */
		DEBUG(0,("smb: %s> ", CNV_LANG(cur_dir)));
		dbgflush( );

		wait_keyboard();
		
		/* and get a response */
		if (!fgets(line,1000,stdin))
			break;

#else /* !HAVE_LIBREADLINE */

		/* Read input using GNU Readline */
		
		slprintf(promptline, sizeof(promptline) - 1, "smb: %s> ", 
			 CNV_LANG(cur_dir));

		if (!readline(promptline))
		    break;
		
		/* Copy read line to samba buffer */
		
		pstrcpy(line, rl_line_buffer);
		pstrcat(line, "\n");
		
		/* Add line to history */
		
		if (strlen(line) > 0)
		    add_history(line);		
#endif
		/* input language code to internal one */
		CNV_INPUT (line);
		
		/* special case - first char is ! */
		if (*line == '!') {
			system(line + 1);
			continue;
		}
      
		/* and get the first part of the command */
		ptr = line;
		if (!next_token(&ptr,tok,NULL,sizeof(tok))) continue;

		if ((i = process_tok(tok)) >= 0) {
			commands[i].fn();
		} else if (i == -2) {
			DEBUG(0,("%s: command abbreviation ambiguous\n",CNV_LANG(tok)));
		} else {
			DEBUG(0,("%s: command not found\n",CNV_LANG(tok)));
		}
	}
}


/***************************************************** 
return a connection to a server
*******************************************************/
struct cli_state *do_connect(char *server, char *share, int smb_port)
{
	struct cli_state *smb_cli;
	struct nmb_name called, calling, stupid_smbserver_called;
	char *server_n;
	struct in_addr ip;
	extern struct in_addr ipzero;

	if ((smb_cli=cli_initialise(NULL)) == NULL)
	{
		DEBUG(1,("cli_initialise failed\n"));
		return NULL;
	}

	if (*share == '\\')
	{
		server = share+2;
		share = strchr(server,'\\');
		if (!share) return NULL;
		*share = 0;
		share++;
	}

	server_n = server;
	
	ip = ipzero;

	make_nmb_name(&calling, global_myname, 0x0);
	make_nmb_name(&called , server, name_type);
	make_nmb_name(&stupid_smbserver_called , "*SMBSERVER", 0x20);

	fstrcpy(smb_cli->usr.user_name, username);
	fstrcpy(smb_cli->usr.domain, workgroup);

	ip = ipzero;
	if (have_ip) ip = dest_ip;

	if (cli_set_port(smb_cli, smb_port) == 0)
	{
		return NULL;
	}

	/* set the password cache info */
	if (got_pass)
	{
		if (password[0] == 0)
		{
			pwd_set_nullpwd(&(smb_cli->usr.pwd));
		}
		else
		{
			/* generate 16 byte hashes */
			pwd_make_lm_nt_16(&(smb_cli->usr.pwd), password);
		}
	}
	else 
	{
		pwd_read(&(smb_cli->usr.pwd), "Password:", True);
	}

	/* paranoia: destroy the local copy of the password */
	bzero(password, sizeof(password)); 

	smb_cli->use_ntlmv2 = lp_client_ntlmv2();

	if (!cli_establish_connection(smb_cli, server, &ip, &calling, &called,
	                              share, "?????", False, True) &&
	    !cli_establish_connection(smb_cli, server, &ip,
	                              &calling, &stupid_smbserver_called,
	                              share, "?????", False, True))
	{
		return NULL;
	}
		
	return smb_cli;
}


/****************************************************************************
  process commands from the client
****************************************************************************/
static BOOL process(char *base_directory)
{
	cli = do_connect(desthost, service, port);
	if (!cli) {
		return(False);
	}

	if (*base_directory) do_cd(base_directory);
	
	if (cmdstr) {
		process_command_string(cmdstr);
	} else {
		process_stdin();
	}
  
	cli_shutdown(cli);
	return(True);
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
  DEBUG(0,("Usage: %s service <password> ", pname));

  DEBUG(0,("\nVersion %s\n",VERSION));
  DEBUG(0,("\t-s smb.conf           pathname to smb.conf file\n"));
  DEBUG(0,("\t-B IP addr            broadcast IP address to use\n"));
  DEBUG(0,("\t-O socket_options     socket options to use\n"));
  DEBUG(0,("\t-R name resolve order use these name resolution services only\n"));
  DEBUG(0,("\t-M host               send a winpopup message to the host\n"));
  DEBUG(0,("\t-i scope              use this NetBIOS scope\n"));
  DEBUG(0,("\t-N                    don't ask for a password\n"));
  DEBUG(0,("\t-n netbios name.      Use this name as my netbios name\n"));
  DEBUG(0,("\t-d debuglevel         set the debuglevel\n"));
  DEBUG(0,("\t-P                    connect to service as a printer\n"));
  DEBUG(0,("\t-p port               connect to the specified port\n"));
  DEBUG(0,("\t-l log basename.      Basename for log/debug files\n"));
  DEBUG(0,("\t-h                    Print this help message.\n"));
  DEBUG(0,("\t-I dest IP            use this IP to connect to\n"));
  DEBUG(0,("\t-E                    write messages to stderr instead of stdout\n"));
  DEBUG(0,("\t-U username           set the network username\n"));
  DEBUG(0,("\t-L host               get a list of shares available on a host\n"));
  DEBUG(0,("\t-t terminal code      terminal i/o code {sjis|euc|jis7|jis8|junet|hex}\n"));
  DEBUG(0,("\t-m max protocol       set the max protocol level\n"));
  DEBUG(0,("\t-W workgroup          set the workgroup name\n"));
  DEBUG(0,("\t-T<c|x>IXFqgbNan      command line tar\n"));
  DEBUG(0,("\t-D directory          start from directory\n"));
  DEBUG(0,("\t-c command string     execute semicolon separated commands\n"));
  DEBUG(0,("\n"));
}


/****************************************************************************
get a password from a a file or file descriptor
exit on failure
****************************************************************************/
static void get_password_file(void)
{
	int fd = -1;
	char *p;
	BOOL close_it = False;
	pstring spec;
	char pass[128];
		
	if ((p = getenv("PASSWD_FD")) != NULL) {
		pstrcpy(spec, "descriptor ");
		pstrcat(spec, p);
		sscanf(p, "%d", &fd);
		close_it = False;
	} else if ((p = getenv("PASSWD_FILE")) != NULL) {
		fd = sys_open(p, O_RDONLY, 0);
		pstrcpy(spec, p);
		if (fd < 0) {
			fprintf(stderr, "Error opening PASSWD_FILE %s: %s\n",
				spec, strerror(errno));
			exit(1);
		}
		close_it = True;
	}

	for(p = pass, *p = '\0'; /* ensure that pass is null-terminated */
	    p && p - pass < sizeof(pass);) {
		switch (read(fd, p, 1)) {
		case 1:
			if (*p != '\n' && *p != '\0') {
				*++p = '\0'; /* advance p, and null-terminate pass */
				break;
			}
		case 0:
			if (p - pass) {
				*p = '\0'; /* null-terminate it, just in case... */
				p = NULL; /* then force the loop condition to become false */
				break;
			} else {
				fprintf(stderr, "Error reading password from file %s: %s\n",
					spec, "empty password\n");
				exit(1);
			}
			
		default:
			fprintf(stderr, "Error reading password from file %s: %s\n",
				spec, strerror(errno));
			exit(1);
		}
	}
	pstrcpy(password, pass);
	if (close_it)
		close(fd);
}	



/****************************************************************************
handle a -L query
****************************************************************************/
static int do_host_query(char *query_host, int smb_port)
{
	cli = do_connect(query_host, "IPC$", smb_port);
	if (!cli)
		return 1;

	browse_host(True);
	list_servers(workgroup);

	cli_shutdown(cli);
	
	return(0);
}


/****************************************************************************
handle a tar operation
****************************************************************************/
static int do_tar_op(int smb_port, char *base_directory)
{
	int ret;
	cli = do_connect(desthost, service, smb_port);
	if (!cli)
		return 1;

	recurse=True;

	if (*base_directory) do_cd(base_directory);
	
	ret=process_tar();

	cli_shutdown(cli);

	return(ret);
}

/****************************************************************************
handle a message operation
****************************************************************************/
static int do_message_op(void)
{
	struct in_addr ip;
	struct nmb_name called, calling;

	ip = ipzero;

	make_nmb_name(&calling, global_myname, 0x0);
	make_nmb_name(&called , desthost, name_type);

	ip = ipzero;
	if (have_ip) ip = dest_ip;

	if (!(cli=cli_initialise(NULL)) || !cli_connect(cli, desthost, &ip)) {
		DEBUG(0,("Connection to %s failed\n", desthost));
		return 1;
	}

	if (!cli_session_request(cli, &calling, &called)) {
		DEBUG(0,("session request failed\n"));
		cli_shutdown(cli);
		return 1;
	}

	send_message();
	cli_shutdown(cli);

	return 0;
}


/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	fstring base_directory;
	char *pname = argv[0];
	int opt;
	extern FILE *dbf;
	extern char *optarg;
	extern int optind;
	pstring query_host;
	BOOL message = False;
	BOOL explicit_user = False;
	extern char tar_type;
	static pstring servicesf = CONFIGFILE;
	pstring term_code;
	pstring new_name_resolve_order;
	char *p;

#ifdef KANJI
	pstrcpy(term_code, KANJI);
#else /* KANJI */
	*term_code = 0;
#endif /* KANJI */

	*query_host = 0;
	*base_directory = 0;

	*new_name_resolve_order = 0;

	DEBUGLEVEL = 2;

	setup_logging(pname,True);

	TimeInit();
	charset_initialise();

	in_client = True;   /* Make sure that we tell lp_load we are */

	if (!lp_load(servicesf,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
	}
	
	codepage_initialise(lp_client_code_page());

	interpret_coding_system(term_code);

#ifdef WITH_SSL
	sslutil_init(0);
#endif

	pstrcpy(workgroup,lp_workgroup());

	load_interfaces();
	myumask = umask(0);
	umask(myumask);

	if (getenv("USER")) {
		pstrcpy(username,getenv("USER"));

		/* modification to support userid%passwd syntax in the USER var
		   25.Aug.97, jdblair@uab.edu */

		if ((p=strchr(username,'%'))) {
			*p = 0;
			pstrcpy(password,p+1);
			got_pass = True;
			memset(strchr(getenv("USER"),'%')+1,'X',strlen(password));
		}
		strupper(username);
	}

	/* modification to support PASSWD environmental var
	   25.Aug.97, jdblair@uab.edu */
	if (getenv("PASSWD")) {
		pstrcpy(password,getenv("PASSWD"));
		got_pass = True;
	}

	if (getenv("PASSWD_FD") || getenv("PASSWD_FILE")) {
		get_password_file();
		got_pass = True;
	}

	if (*username == 0 && getenv("LOGNAME")) {
		pstrcpy(username,getenv("LOGNAME"));
		strupper(username);
	}

	if (*username == 0) {
		pstrcpy(username,"GUEST");
	}

	if (argc < 2) {
		usage(pname);
		exit(1);
	}
  
	if (*argv[1] != '-') {
		pstrcpy(service,argv[1]);  
		/* Convert any '/' characters in the service name to '\' characters */
		string_replace( service, '/','\\');
		argc--;
		argv++;
		
		if (count_chars(service,'\\') < 3) {
			usage(pname);
			printf("\n%s: Not enough '\\' characters in service\n",service);
			exit(1);
		}

		if (argc > 1 && (*argv[1] != '-')) {
			got_pass = True;
			pstrcpy(password,argv[1]);  
			memset(argv[1],'X',strlen(argv[1]));
			argc--;
			argv++;
		}
	}

	while ((opt = 
		getopt(argc, argv,"s:B:O:R:M:i:Nn:d:Pp:l:hI:EU:L:t:m:W:T:D:c:")) != EOF) {
		switch (opt) {
		case 's':
			pstrcpy(servicesf, optarg);
			break;
		case 'O':
			pstrcpy(user_socket_options,optarg);
			break;	
		case 'R':
			pstrcpy(new_name_resolve_order, optarg);
			break;
		case 'M':
			name_type = 0x03; /* messages are sent to NetBIOS name type 0x3 */
			pstrcpy(desthost,optarg);
			message = True;
			break;
		case 'i':
			pstrcpy(scope,optarg);
			break;
		case 'N':
			got_pass = True;
			break;
		case 'n':
			pstrcpy(global_myname,optarg);
			break;
		case 'd':
			if (*optarg == 'A')
				DEBUGLEVEL = 10000;
			else
				DEBUGLEVEL = atoi(optarg);
			break;
		case 'P':
			/* not needed anymore */
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'l':
			slprintf(debugf,sizeof(debugf)-1, "%s.client",optarg);
			break;
		case 'h':
			usage(pname);
			exit(0);
			break;
		case 'I':
			{
				dest_ip = *interpret_addr2(optarg);
				if (zero_ip(dest_ip))
					exit(1);
				have_ip = True;
			}
			break;
		case 'E':
			dbf = stderr;
			break;
		case 'U':
			{
				char *lp;
				explicit_user = True;
				pstrcpy(username,optarg);
				if ((lp=strchr(username,'%'))) {
					*lp = 0;
					pstrcpy(password,lp+1);
					got_pass = True;
					memset(strchr(optarg,'%')+1,'X',strlen(password));
				}
			}
			break;
		case 'L':
			pstrcpy(query_host,optarg);
			if(!explicit_user)
				*username = '\0';
			break;
		case 't':
			pstrcpy(term_code, optarg);
			break;
		case 'm':
			/* no longer supported */
			break;
		case 'W':
			pstrcpy(workgroup,optarg);
			break;
		case 'T':
			if (!tar_parseargs(argc, argv, optarg, optind)) {
				usage(pname);
				exit(1);
			}
			break;
		case 'D':
			pstrcpy(base_directory,optarg);
			break;
		case 'c':
			cmdstr = optarg;
			got_pass = True;
			break;
		default:
			usage(pname);
			exit(1);
		}
	}

	get_myname((*global_myname)?NULL:global_myname,NULL);  

	if(*new_name_resolve_order)
		lp_set_name_resolve_order(new_name_resolve_order);

	if (!tar_type && !*query_host && !*service && !message) {
		usage(pname);
		exit(1);
	}

#ifdef HAVE_LIBREADLINE

	/* Initialise GNU Readline */
	
	rl_readline_name = "smbclient";
	rl_attempted_completion_function = completion_fn;
	rl_completion_entry_function = (Function *)complete_cmd_null;
	
	/* Initialise history list */
	
	using_history();

#endif /* HAVE_LIBREADLINE */

	DEBUG( 3, ( "Client started (version %s).\n", VERSION ) );

	if (tar_type) {
		return do_tar_op(port, base_directory);
	}

	if ((p=strchr(query_host,'#'))) {
		*p = 0;
		p++;
		sscanf(p, "%x", &name_type);
	}
  
	if (*query_host) {
		return do_host_query(query_host, port);
	}

	if (message) {
		return do_message_op();
	}

	if (!process(base_directory)) {
		close_sockets();
		return(1);
	}
	close_sockets();

	return(0);
}
