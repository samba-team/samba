/* 
   Unix SMB/CIFS implementation.
   SMB client
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Simo Sorce 2001-2002
   Copyright (C) Jelmer Vernooij 2003
   
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
#include "../client/client_proto.h"
#ifndef REGISTER
#define REGISTER 0
#endif

struct cli_state *cli;
extern BOOL in_client;
static int port = 0;
pstring cur_dir = "\\";
static pstring cd_path = "";
static pstring service;
static pstring desthost;
static pstring username;
static pstring password;
static BOOL use_kerberos;
static BOOL got_pass;
static BOOL grepable=False;
static char *cmdstr = NULL;

static int io_bufsize = 64512;

static int name_type = 0x20;
static int max_protocol = PROTOCOL_NT1;

static int process_tok(pstring tok);
static int cmd_help(void);

/* 30 second timeout on most commands */
#define CLIENT_TIMEOUT (30*1000)
#define SHORT_TIMEOUT (5*1000)

/* value for unused fid field in trans2 secondary request */
#define FID_UNUSED (0xFFFF)

time_t newer_than = 0;
static int archive_level = 0;

static BOOL translation = False;

static BOOL have_ip;

/* clitar bits insert */
extern int blocksize;
extern BOOL tar_inc;
extern BOOL tar_reset;
/* clitar bits end */
 

static BOOL prompt = True;

static int printmode = 1;

static BOOL recurse = False;
BOOL lowercase = False;

static struct in_addr dest_ip;

#define SEPARATORS " \t\n\r"

static BOOL abort_mget = True;

static pstring fileselection = "";

extern file_info def_finfo;

/* timing globals */
SMB_BIG_UINT get_total_size = 0;
unsigned int get_total_time_ms = 0;
static SMB_BIG_UINT put_total_size = 0;
static unsigned int put_total_time_ms = 0;

/* totals globals */
static double dir_total;

#define USENMB

/* some forward declarations */
static struct cli_state *do_connect(const char *server, const char *share);

/****************************************************************************
 Write to a local file with CR/LF->LF translation if appropriate. Return the 
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
 Read from a file with LF->CR/LF translation if appropriate. Return the 
 number read. read approx n bytes.
****************************************************************************/

static int readfile(char *b, int n, XFILE *f)
{
	int i;
	int c;

	if (!translation)
		return x_fread(b,1,n,f);
  
	i = 0;
	while (i < (n - 1) && (i < BUFFER_SIZE)) {
		if ((c = x_getc(f)) == EOF) {
			break;
		}
      
		if (c == '\n') { /* change all LFs to CR/LF */
			b[i++] = '\r';
		}
      
		b[i++] = c;
	}
  
	return(i);
}
 
/****************************************************************************
 Send a message.
****************************************************************************/

static void send_message(void)
{
	int total_len = 0;
	int grp_id;

	if (!cli_message_start(cli, desthost, username, &grp_id)) {
		d_printf("message start: %s\n", cli_errstr(cli));
		return;
	}


	d_printf("Connected. Type your message, ending it with a Control-D\n");

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
			d_printf("SMBsendtxt failed (%s)\n",cli_errstr(cli));
			return;
		}      
		
		total_len += l;
	}

	if (total_len >= 1600)
		d_printf("the message was truncated to 1600 bytes\n");
	else
		d_printf("sent %d bytes\n",total_len);

	if (!cli_message_end(cli, grp_id)) {
		d_printf("SMBsendend failed (%s)\n",cli_errstr(cli));
		return;
	}      
}

/****************************************************************************
 Check the space on a device.
****************************************************************************/

static int do_dskattr(void)
{
	int total, bsize, avail;

	if (!cli_dskattr(cli, &bsize, &total, &avail)) {
		d_printf("Error in dskattr: %s\n",cli_errstr(cli)); 
		return 1;
	}

	d_printf("\n\t\t%d blocks of size %d. %d blocks available\n",
		 total, bsize, avail);

	return 0;
}

/****************************************************************************
 Show cd/pwd.
****************************************************************************/

static int cmd_pwd(void)
{
	d_printf("Current directory is %s",service);
	d_printf("%s\n",cur_dir);
	return 0;
}

/****************************************************************************
 Change directory - inner section.
****************************************************************************/

static int do_cd(char *newdir)
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
			d_printf("cd %s: %s\n", dname, cli_errstr(cli));
			pstrcpy(cur_dir,saved_dir);
		}
	}
	
	pstrcpy(cd_path,cur_dir);

	return 0;
}

/****************************************************************************
 Change directory.
****************************************************************************/

static int cmd_cd(void)
{
	pstring buf;
	int rc = 0;

	if (next_token_nr(NULL,buf,NULL,sizeof(buf)))
		rc = do_cd(buf);
	else
		d_printf("Current directory is %s\n",cur_dir);

	return rc;
}

/*******************************************************************
 Decide if a file should be operated on.
********************************************************************/

static BOOL do_this_one(file_info *finfo)
{
	if (finfo->mode & aDIR)
		return(True);

	if (*fileselection && 
	    !mask_match(finfo->name,fileselection,False)) {
		DEBUG(3,("mask_match %s failed\n", finfo->name));
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
 Display info about a file.
****************************************************************************/

static void display_finfo(file_info *finfo)
{
	if (do_this_one(finfo)) {
		time_t t = finfo->mtime; /* the time is assumed to be passed as GMT */
		d_printf("  %-30s%7.7s %8.0f  %s",
			 finfo->name,
			 attrib_string(finfo->mode),
			 (double)finfo->size,
			 asctime(LocalTime(&t)));
		dir_total += finfo->size;
	}
}

/****************************************************************************
 Accumulate size of a file.
****************************************************************************/

static void do_du(file_info *finfo)
{
	if (do_this_one(finfo)) {
		dir_total += finfo->size;
	}
}

static BOOL do_list_recurse;
static BOOL do_list_dirs;
static char *do_list_queue = 0;
static long do_list_queue_size = 0;
static long do_list_queue_start = 0;
static long do_list_queue_end = 0;
static void (*do_list_fn)(file_info *);

/****************************************************************************
 Functions for do_list_queue.
****************************************************************************/

/*
 * The do_list_queue is a NUL-separated list of strings stored in a
 * char*.  Since this is a FIFO, we keep track of the beginning and
 * ending locations of the data in the queue.  When we overflow, we
 * double the size of the char*.  When the start of the data passes
 * the midpoint, we move everything back.  This is logically more
 * complex than a linked list, but easier from a memory management
 * angle.  In any memory error condition, do_list_queue is reset.
 * Functions check to ensure that do_list_queue is non-NULL before
 * accessing it.
 */

static void reset_do_list_queue(void)
{
	SAFE_FREE(do_list_queue);
	do_list_queue_size = 0;
	do_list_queue_start = 0;
	do_list_queue_end = 0;
}

static void init_do_list_queue(void)
{
	reset_do_list_queue();
	do_list_queue_size = 1024;
	do_list_queue = malloc(do_list_queue_size);
	if (do_list_queue == 0) { 
		d_printf("malloc fail for size %d\n",
			 (int)do_list_queue_size);
		reset_do_list_queue();
	} else {
		memset(do_list_queue, 0, do_list_queue_size);
	}
}

static void adjust_do_list_queue(void)
{
	/*
	 * If the starting point of the queue is more than half way through,
	 * move everything toward the beginning.
	 */
	if (do_list_queue && (do_list_queue_start == do_list_queue_end)) {
		DEBUG(4,("do_list_queue is empty\n"));
		do_list_queue_start = do_list_queue_end = 0;
		*do_list_queue = '\0';
	} else if (do_list_queue_start > (do_list_queue_size / 2)) {
		DEBUG(4,("sliding do_list_queue backward\n"));
		memmove(do_list_queue,
			do_list_queue + do_list_queue_start,
			do_list_queue_end - do_list_queue_start);
		do_list_queue_end -= do_list_queue_start;
		do_list_queue_start = 0;
	}
}

static void add_to_do_list_queue(const char* entry)
{
	char *dlq;
	long new_end = do_list_queue_end + ((long)strlen(entry)) + 1;
	while (new_end > do_list_queue_size) {
		do_list_queue_size *= 2;
		DEBUG(4,("enlarging do_list_queue to %d\n",
			 (int)do_list_queue_size));
		dlq = Realloc(do_list_queue, do_list_queue_size);
		if (! dlq) {
			d_printf("failure enlarging do_list_queue to %d bytes\n",
				 (int)do_list_queue_size);
			reset_do_list_queue();
		} else {
			do_list_queue = dlq;
			memset(do_list_queue + do_list_queue_size / 2,
			       0, do_list_queue_size / 2);
		}
	}
	if (do_list_queue) {
		safe_strcpy_base(do_list_queue + do_list_queue_end, 
				 entry, do_list_queue, do_list_queue_size);
		do_list_queue_end = new_end;
		DEBUG(4,("added %s to do_list_queue (start=%d, end=%d)\n",
			 entry, (int)do_list_queue_start, (int)do_list_queue_end));
	}
}

static char *do_list_queue_head(void)
{
	return do_list_queue + do_list_queue_start;
}

static void remove_do_list_queue_head(void)
{
	if (do_list_queue_end > do_list_queue_start) {
		do_list_queue_start += strlen(do_list_queue_head()) + 1;
		adjust_do_list_queue();
		DEBUG(4,("removed head of do_list_queue (start=%d, end=%d)\n",
			 (int)do_list_queue_start, (int)do_list_queue_end));
	}
}

static int do_list_queue_empty(void)
{
	return (! (do_list_queue && *do_list_queue));
}

/****************************************************************************
 A helper for do_list.
****************************************************************************/

static void do_list_helper(file_info *f, const char *mask, void *state)
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

			if (!f->name[0]) {
				d_printf("Empty dir name returned. Possible server misconfiguration.\n");
				return;
			}

			pstrcpy(mask2, mask);
			p = strrchr_m(mask2,'\\');
			if (!p)
				return;
			p[1] = 0;
			pstrcat(mask2, f->name);
			pstrcat(mask2,"\\*");
			add_to_do_list_queue(mask2);
		}
		return;
	}

	if (do_this_one(f)) {
		do_list_fn(f);
	}
}

/****************************************************************************
 A wrapper around cli_list that adds recursion.
****************************************************************************/

void do_list(const char *mask,uint16 attribute,void (*fn)(file_info *),BOOL rec, BOOL dirs)
{
	static int in_do_list = 0;

	if (in_do_list && rec) {
		fprintf(stderr, "INTERNAL ERROR: do_list called recursively when the recursive flag is true\n");
		exit(1);
	}

	in_do_list = 1;

	do_list_recurse = rec;
	do_list_dirs = dirs;
	do_list_fn = fn;

	if (rec) {
		init_do_list_queue();
		add_to_do_list_queue(mask);
		
		while (! do_list_queue_empty()) {
			/*
			 * Need to copy head so that it doesn't become
			 * invalid inside the call to cli_list.  This
			 * would happen if the list were expanded
			 * during the call.
			 * Fix from E. Jay Berkenbilt (ejb@ql.org)
			 */
			pstring head;
			pstrcpy(head, do_list_queue_head());
			cli_list(cli, head, attribute, do_list_helper, NULL);
			remove_do_list_queue_head();
			if ((! do_list_queue_empty()) && (fn == display_finfo)) {
				char* next_file = do_list_queue_head();
				char* save_ch = 0;
				if ((strlen(next_file) >= 2) &&
				    (next_file[strlen(next_file) - 1] == '*') &&
				    (next_file[strlen(next_file) - 2] == '\\')) {
					save_ch = next_file +
						strlen(next_file) - 2;
					*save_ch = '\0';
				}
				d_printf("\n%s\n",next_file);
				if (save_ch) {
					*save_ch = '\\';
				}
			}
		}
	} else {
		if (cli_list(cli, mask, attribute, do_list_helper, NULL) == -1) {
			d_printf("%s listing %s\n", cli_errstr(cli), mask);
		}
	}

	in_do_list = 0;
	reset_do_list_queue();
}

/****************************************************************************
 Get a directory listing.
****************************************************************************/

static int cmd_dir(void)
{
	uint16 attribute = aDIR | aSYSTEM | aHIDDEN;
	pstring mask;
	pstring buf;
	char *p=buf;
	int rc;
	
	dir_total = 0;
	if (strcmp(cur_dir, "\\") != 0) {
		pstrcpy(mask,cur_dir);
		if(mask[strlen(mask)-1]!='\\')
			pstrcat(mask,"\\");
	} else {
		*mask = '\0';
	}
	
	if (next_token_nr(NULL,buf,NULL,sizeof(buf))) {
		dos_format(p);
		if (*p == '\\')
			pstrcpy(mask,p);
		else
			pstrcat(mask,p);
	} else {
		pstrcat(mask,"*");
	}

	do_list(mask, attribute, display_finfo, recurse, True);

	rc = do_dskattr();

	DEBUG(3, ("Total bytes listed: %.0f\n", dir_total));

	return rc;
}

/****************************************************************************
 Get a directory listing.
****************************************************************************/

static int cmd_du(void)
{
	uint16 attribute = aDIR | aSYSTEM | aHIDDEN;
	pstring mask;
	pstring buf;
	char *p=buf;
	int rc;
	
	dir_total = 0;
	pstrcpy(mask,cur_dir);
	if(mask[strlen(mask)-1]!='\\')
		pstrcat(mask,"\\");
	
	if (next_token_nr(NULL,buf,NULL,sizeof(buf))) {
		dos_format(p);
		if (*p == '\\')
			pstrcpy(mask,p);
		else
			pstrcat(mask,p);
	} else {
		pstrcat(mask,"*");
	}

	do_list(mask, attribute, do_du, recurse, True);

	rc = do_dskattr();

	d_printf("Total number of bytes: %.0f\n", dir_total);

	return rc;
}

/****************************************************************************
 Get a file from rname to lname
****************************************************************************/

static int do_get(char *rname, char *lname, BOOL reget)
{  
	int handle = 0, fnum;
	BOOL newhandle = False;
	char *data;
	struct timeval tp_start;
	int read_size = io_bufsize;
	uint16 attr;
	size_t size;
	off_t start = 0;
	off_t nread = 0;
	int rc = 0;

	GetTimeOfDay(&tp_start);

	if (lowercase) {
		strlower_m(lname);
	}

	fnum = cli_open(cli, rname, O_RDONLY, DENY_NONE);

	if (fnum == -1) {
		d_printf("%s opening remote file %s\n",cli_errstr(cli),rname);
		return 1;
	}

	if(!strcmp(lname,"-")) {
		handle = fileno(stdout);
	} else {
		if (reget) {
			handle = sys_open(lname, O_WRONLY|O_CREAT, 0644);
			if (handle >= 0) {
				start = sys_lseek(handle, 0, SEEK_END);
				if (start == -1) {
					d_printf("Error seeking local file\n");
					return 1;
				}
			}
		} else {
			handle = sys_open(lname, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		}
		newhandle = True;
	}
	if (handle < 0) {
		d_printf("Error opening local file %s\n",lname);
		return 1;
	}


	if (!cli_qfileinfo(cli, fnum, 
			   &attr, &size, NULL, NULL, NULL, NULL, NULL) &&
	    !cli_getattrE(cli, fnum, 
			  &attr, &size, NULL, NULL, NULL)) {
		d_printf("getattrib: %s\n",cli_errstr(cli));
		return 1;
	}

	DEBUG(2,("getting file %s of size %.0f as %s ", 
		 rname, (double)size, lname));

	if(!(data = (char *)malloc(read_size))) { 
		d_printf("malloc fail for size %d\n", read_size);
		cli_close(cli, fnum);
		return 1;
	}

	while (1) {
		int n = cli_read(cli, fnum, data, nread + start, read_size);

		if (n <= 0)
			break;
 
		if (writefile(handle,data, n) != n) {
			d_printf("Error writing local file\n");
			rc = 1;
			break;
		}
      
		nread += n;
	}

	if (nread + start < size) {
		DEBUG (0, ("Short read when getting file %s. Only got %ld bytes.\n",
			    rname, (long)nread));

		rc = 1;
	}

	SAFE_FREE(data);
	
	if (!cli_close(cli, fnum)) {
		d_printf("Error %s closing remote file\n",cli_errstr(cli));
		rc = 1;
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
		
		DEBUG(2,("(%3.1f kb/s) (average %3.1f kb/s)\n",
			 nread / (1.024*this_time + 1.0e-4),
			 get_total_size / (1.024*get_total_time_ms)));
	}
	
	return rc;
}

/****************************************************************************
 Get a file.
****************************************************************************/

static int cmd_get(void)
{
	pstring lname;
	pstring rname;
	char *p;

	pstrcpy(rname,cur_dir);
	pstrcat(rname,"\\");
	
	p = rname + strlen(rname);
	
	if (!next_token_nr(NULL,p,NULL,sizeof(rname)-strlen(rname))) {
		d_printf("get <filename>\n");
		return 1;
	}
	pstrcpy(lname,p);
	dos_clean_name(rname);
	
	next_token_nr(NULL,lname,NULL,sizeof(lname));
	
	return do_get(rname, lname, False);
}

/****************************************************************************
 Do an mget operation on one file.
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
		d_printf("mget aborted\n");
		return;
	}

	if (finfo->mode & aDIR)
		slprintf(quest,sizeof(pstring)-1,
			 "Get directory %s? ",finfo->name);
	else
		slprintf(quest,sizeof(pstring)-1,
			 "Get file %s? ",finfo->name);

	if (prompt && !yesno(quest))
		return;

	if (!(finfo->mode & aDIR)) {
		pstrcpy(rname,cur_dir);
		pstrcat(rname,finfo->name);
		do_get(rname, finfo->name, False);
		return;
	}

	/* handle directories */
	pstrcpy(saved_curdir,cur_dir);

	pstrcat(cur_dir,finfo->name);
	pstrcat(cur_dir,"\\");

	unix_format(finfo->name);
	if (lowercase)
		strlower_m(finfo->name);
	
	if (!directory_exist(finfo->name,NULL) && 
	    mkdir(finfo->name,0777) != 0) {
		d_printf("failed to create directory %s\n",finfo->name);
		pstrcpy(cur_dir,saved_curdir);
		return;
	}
	
	if (chdir(finfo->name) != 0) {
		d_printf("failed to chdir to directory %s\n",finfo->name);
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
 View the file using the pager.
****************************************************************************/

static int cmd_more(void)
{
	pstring rname,lname,pager_cmd;
	char *pager;
	int fd;
	int rc = 0;

	pstrcpy(rname,cur_dir);
	pstrcat(rname,"\\");
	
	slprintf(lname,sizeof(lname)-1, "%s/smbmore.XXXXXX",tmpdir());
	fd = smb_mkstemp(lname);
	if (fd == -1) {
		d_printf("failed to create temporary file for more\n");
		return 1;
	}
	close(fd);

	if (!next_token_nr(NULL,rname+strlen(rname),NULL,sizeof(rname)-strlen(rname))) {
		d_printf("more <filename>\n");
		unlink(lname);
		return 1;
	}
	dos_clean_name(rname);

	rc = do_get(rname, lname, False);

	pager=getenv("PAGER");

	slprintf(pager_cmd,sizeof(pager_cmd)-1,
		 "%s %s",(pager? pager:PAGER), lname);
	system(pager_cmd);
	unlink(lname);
	
	return rc;
}

/****************************************************************************
 Do a mget command.
****************************************************************************/

static int cmd_mget(void)
{
	uint16 attribute = aSYSTEM | aHIDDEN;
	pstring mget_mask;
	pstring buf;
	char *p=buf;

	*mget_mask = 0;

	if (recurse)
		attribute |= aDIR;
	
	abort_mget = False;

	while (next_token_nr(NULL,p,NULL,sizeof(buf))) {
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
	
	return 0;
}

/****************************************************************************
 Make a directory of name "name".
****************************************************************************/

static BOOL do_mkdir(char *name)
{
	if (!cli_mkdir(cli, name)) {
		d_printf("%s making remote directory %s\n",
			 cli_errstr(cli),name);
		return(False);
	}

	return(True);
}

/****************************************************************************
 Show 8.3 name of a file.
****************************************************************************/

static BOOL do_altname(char *name)
{
	pstring altname;
	if (!NT_STATUS_IS_OK(cli_qpathinfo_alt_name(cli, name, altname))) {
		d_printf("%s getting alt name for %s\n",
			 cli_errstr(cli),name);
		return(False);
	}
	d_printf("%s\n", altname);

	return(True);
}

/****************************************************************************
 Exit client.
****************************************************************************/

static int cmd_quit(void)
{
	cli_shutdown(cli);
	exit(0);
	/* NOTREACHED */
	return 0;
}

/****************************************************************************
 Make a directory.
****************************************************************************/

static int cmd_mkdir(void)
{
	pstring mask;
	pstring buf;
	char *p=buf;
  
	pstrcpy(mask,cur_dir);

	if (!next_token_nr(NULL,p,NULL,sizeof(buf))) {
		if (!recurse)
			d_printf("mkdir <dirname>\n");
		return 1;
	}
	pstrcat(mask,p);

	if (recurse) {
		pstring ddir;
		pstring ddir2;
		*ddir2 = 0;
		
		pstrcpy(ddir,mask);
		trim_char(ddir,'.','\0');
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
	
	return 0;
}

/****************************************************************************
 Show alt name.
****************************************************************************/

static int cmd_altname(void)
{
	pstring name;
	pstring buf;
	char *p=buf;
  
	pstrcpy(name,cur_dir);

	if (!next_token_nr(NULL,p,NULL,sizeof(buf))) {
		d_printf("altname <file>\n");
		return 1;
	}
	pstrcat(name,p);

	do_altname(name);

	return 0;
}

/****************************************************************************
 Put a single file.
****************************************************************************/

static int do_put(char *rname, char *lname, BOOL reput)
{
	int fnum;
	XFILE *f;
	size_t start = 0;
	off_t nread = 0;
	char *buf = NULL;
	int maxwrite = io_bufsize;
	int rc = 0;
	
	struct timeval tp_start;
	GetTimeOfDay(&tp_start);

	if (reput) {
		fnum = cli_open(cli, rname, O_RDWR|O_CREAT, DENY_NONE);
		if (fnum >= 0) {
			if (!cli_qfileinfo(cli, fnum, NULL, &start, NULL, NULL, NULL, NULL, NULL) &&
			    !cli_getattrE(cli, fnum, NULL, &start, NULL, NULL, NULL)) {
				d_printf("getattrib: %s\n",cli_errstr(cli));
				return 1;
			}
		}
	} else {
		fnum = cli_open(cli, rname, O_RDWR|O_CREAT|O_TRUNC, DENY_NONE);
	}
  
	if (fnum == -1) {
		d_printf("%s opening remote file %s\n",cli_errstr(cli),rname);
		return 1;
	}

	/* allow files to be piped into smbclient
	   jdblair 24.jun.98

	   Note that in this case this function will exit(0) rather
	   than returning. */
	if (!strcmp(lname, "-")) {
		f = x_stdin;
		/* size of file is not known */
	} else {
		f = x_fopen(lname,O_RDONLY, 0);
		if (f && reput) {
			if (x_tseek(f, start, SEEK_SET) == -1) {
				d_printf("Error seeking local file\n");
				return 1;
			}
		}
	}

	if (!f) {
		d_printf("Error opening local file %s\n",lname);
		return 1;
	}
  
	DEBUG(1,("putting file %s as %s ",lname,
		 rname));
  
	buf = (char *)malloc(maxwrite);
	if (!buf) {
		d_printf("ERROR: Not enough memory!\n");
		return 1;
	}
	while (!x_feof(f)) {
		int n = maxwrite;
		int ret;

		if ((n = readfile(buf,n,f)) < 1) {
			if((n == 0) && x_feof(f))
				break; /* Empty local file. */

			d_printf("Error reading local file: %s\n", strerror(errno));
			rc = 1;
			break;
		}

		ret = cli_write(cli, fnum, 0, buf, nread + start, n);

		if (n != ret) {
			d_printf("Error writing file: %s\n", cli_errstr(cli));
			rc = 1;
			break;
		} 

		nread += n;
	}

	if (!cli_close(cli, fnum)) {
		d_printf("%s closing remote file %s\n",cli_errstr(cli),rname);
		x_fclose(f);
		SAFE_FREE(buf);
		return 1;
	}

	
	if (f != x_stdin) {
		x_fclose(f);
	}

	SAFE_FREE(buf);

	{
		struct timeval tp_end;
		int this_time;
		
		GetTimeOfDay(&tp_end);
		this_time = 
			(tp_end.tv_sec - tp_start.tv_sec)*1000 +
			(tp_end.tv_usec - tp_start.tv_usec)/1000;
		put_total_time_ms += this_time;
		put_total_size += nread;
		
		DEBUG(1,("(%3.1f kb/s) (average %3.1f kb/s)\n",
			 nread / (1.024*this_time + 1.0e-4),
			 put_total_size / (1.024*put_total_time_ms)));
	}

	if (f == x_stdin) {
		cli_shutdown(cli);
		exit(0);
	}
	
	return rc;
}

/****************************************************************************
 Put a file.
****************************************************************************/

static int cmd_put(void)
{
	pstring lname;
	pstring rname;
	pstring buf;
	char *p=buf;
	
	pstrcpy(rname,cur_dir);
	pstrcat(rname,"\\");
  
	if (!next_token_nr(NULL,p,NULL,sizeof(buf))) {
		d_printf("put <filename>\n");
		return 1;
	}
	pstrcpy(lname,p);
  
	if (next_token_nr(NULL,p,NULL,sizeof(buf)))
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
			d_printf("%s does not exist\n",lname);
			return 1;
		}
	}

	return do_put(rname, lname, False);
}

/*************************************
 File list structure.
*************************************/

static struct file_list {
	struct file_list *prev, *next;
	char *file_path;
	BOOL isdir;
} *file_list;

/****************************************************************************
 Free a file_list structure.
****************************************************************************/

static void free_file_list (struct file_list * list)
{
	struct file_list *tmp;
	
	while (list) {
		tmp = list;
		DLIST_REMOVE(list, list);
		SAFE_FREE(tmp->file_path);
		SAFE_FREE(tmp);
	}
}

/****************************************************************************
 Seek in a directory/file list until you get something that doesn't start with
 the specified name.
****************************************************************************/

static BOOL seek_list(struct file_list *list, char *name)
{
	while (list) {
		trim_string(list->file_path,"./","\n");
		if (strncmp(list->file_path, name, strlen(name)) != 0) {
			return(True);
		}
		list = list->next;
	}
      
	return(False);
}

/****************************************************************************
 Set the file selection mask.
****************************************************************************/

static int cmd_select(void)
{
	pstrcpy(fileselection,"");
	next_token_nr(NULL,fileselection,NULL,sizeof(fileselection));

	return 0;
}

/****************************************************************************
  Recursive file matching function act as find
  match must be always set to True when calling this function
****************************************************************************/

static int file_find(struct file_list **list, const char *directory, 
		      const char *expression, BOOL match)
{
	DIR *dir;
	struct file_list *entry;
        struct stat statbuf;
        int ret;
        char *path;
	BOOL isdir;
	const char *dname;

        dir = opendir(directory);
	if (!dir)
		return -1;
	
        while ((dname = readdirname(dir))) {
		if (!strcmp("..", dname))
			continue;
		if (!strcmp(".", dname))
			continue;
		
		if (asprintf(&path, "%s/%s", directory, dname) <= 0) {
			continue;
		}

		isdir = False;
		if (!match || !gen_fnmatch(expression, dname)) {
			if (recurse) {
				ret = stat(path, &statbuf);
				if (ret == 0) {
					if (S_ISDIR(statbuf.st_mode)) {
						isdir = True;
						ret = file_find(list, path, expression, False);
					}
				} else {
					d_printf("file_find: cannot stat file %s\n", path);
				}
				
				if (ret == -1) {
					SAFE_FREE(path);
					closedir(dir);
					return -1;
				}
			}
			entry = (struct file_list *) malloc(sizeof (struct file_list));
			if (!entry) {
				d_printf("Out of memory in file_find\n");
				closedir(dir);
				return -1;
			}
			entry->file_path = path;
			entry->isdir = isdir;
                        DLIST_ADD(*list, entry);
		} else {
			SAFE_FREE(path);
		}
        }

	closedir(dir);
	return 0;
}

/****************************************************************************
 mput some files.
****************************************************************************/

static int cmd_mput(void)
{
	pstring buf;
	char *p=buf;
	
	while (next_token_nr(NULL,p,NULL,sizeof(buf))) {
		int ret;
		struct file_list *temp_list;
		char *quest, *lname, *rname;
	
		file_list = NULL;

		ret = file_find(&file_list, ".", p, True);
		if (ret) {
			free_file_list(file_list);
			continue;
		}
		
		quest = NULL;
		lname = NULL;
		rname = NULL;
				
		for (temp_list = file_list; temp_list; 
		     temp_list = temp_list->next) {

			SAFE_FREE(lname);
			if (asprintf(&lname, "%s/", temp_list->file_path) <= 0)
				continue;
			trim_string(lname, "./", "/");
			
			/* check if it's a directory */
			if (temp_list->isdir) {
				/* if (!recurse) continue; */
				
				SAFE_FREE(quest);
				if (asprintf(&quest, "Put directory %s? ", lname) < 0) break;
				if (prompt && !yesno(quest)) { /* No */
					/* Skip the directory */
					lname[strlen(lname)-1] = '/';
					if (!seek_list(temp_list, lname))
						break;		    
				} else { /* Yes */
	      				SAFE_FREE(rname);
					if(asprintf(&rname, "%s%s", cur_dir, lname) < 0) break;
					dos_format(rname);
					if (!cli_chkpath(cli, rname) && 
					    !do_mkdir(rname)) {
						DEBUG (0, ("Unable to make dir, skipping..."));
						/* Skip the directory */
						lname[strlen(lname)-1] = '/';
						if (!seek_list(temp_list, lname))
							break;
					}
				}
				continue;
			} else {
				SAFE_FREE(quest);
				if (asprintf(&quest,"Put file %s? ", lname) < 0) break;
				if (prompt && !yesno(quest)) /* No */
					continue;
				
				/* Yes */
				SAFE_FREE(rname);
				if (asprintf(&rname, "%s%s", cur_dir, lname) < 0) break;
			}

			dos_format(rname);

			do_put(rname, lname, False);
		}
		free_file_list(file_list);
		SAFE_FREE(quest);
		SAFE_FREE(lname);
		SAFE_FREE(rname);
	}

	return 0;
}

/****************************************************************************
 Cancel a print job.
****************************************************************************/

static int do_cancel(int job)
{
	if (cli_printjob_del(cli, job)) {
		d_printf("Job %d cancelled\n",job);
		return 0;
	} else {
		d_printf("Error cancelling job %d : %s\n",job,cli_errstr(cli));
		return 1;
	}
}

/****************************************************************************
 Cancel a print job.
****************************************************************************/

static int cmd_cancel(void)
{
	pstring buf;
	int job; 

	if (!next_token_nr(NULL,buf,NULL,sizeof(buf))) {
		d_printf("cancel <jobid> ...\n");
		return 1;
	}
	do {
		job = atoi(buf);
		do_cancel(job);
	} while (next_token_nr(NULL,buf,NULL,sizeof(buf)));
	
	return 0;
}

/****************************************************************************
 Print a file.
****************************************************************************/

static int cmd_print(void)
{
	pstring lname;
	pstring rname;
	char *p;

	if (!next_token_nr(NULL,lname,NULL, sizeof(lname))) {
		d_printf("print <filename>\n");
		return 1;
	}

	pstrcpy(rname,lname);
	p = strrchr_m(rname,'/');
	if (p) {
		slprintf(rname, sizeof(rname)-1, "%s-%d", p+1, (int)sys_getpid());
	}

	if (strequal(lname,"-")) {
		slprintf(rname, sizeof(rname)-1, "stdin-%d", (int)sys_getpid());
	}

	return do_put(rname, lname, False);
}

/****************************************************************************
 Show a print queue entry.
****************************************************************************/

static void queue_fn(struct print_job_info *p)
{
	d_printf("%-6d   %-9d    %s\n", (int)p->id, (int)p->size, p->name);
}

/****************************************************************************
 Show a print queue.
****************************************************************************/

static int cmd_queue(void)
{
	cli_print_queue(cli, queue_fn);
	
	return 0;
}

/****************************************************************************
 Delete some files.
****************************************************************************/

static void do_del(file_info *finfo)
{
	pstring mask;

	pstrcpy(mask,cur_dir);
	pstrcat(mask,finfo->name);

	if (finfo->mode & aDIR) 
		return;

	if (!cli_unlink(cli, mask)) {
		d_printf("%s deleting remote file %s\n",cli_errstr(cli),mask);
	}
}

/****************************************************************************
 Delete some files.
****************************************************************************/

static int cmd_del(void)
{
	pstring mask;
	pstring buf;
	uint16 attribute = aSYSTEM | aHIDDEN;

	if (recurse)
		attribute |= aDIR;
	
	pstrcpy(mask,cur_dir);
	
	if (!next_token_nr(NULL,buf,NULL,sizeof(buf))) {
		d_printf("del <filename>\n");
		return 1;
	}
	pstrcat(mask,buf);

	do_list(mask, attribute,do_del,False,False);
	
	return 0;
}

/****************************************************************************
****************************************************************************/

static int cmd_open(void)
{
	pstring mask;
	pstring buf;
	
	pstrcpy(mask,cur_dir);
	
	if (!next_token_nr(NULL,buf,NULL,sizeof(buf))) {
		d_printf("open <filename>\n");
		return 1;
	}
	pstrcat(mask,buf);

	cli_open(cli, mask, O_RDWR, DENY_ALL);

	return 0;
}


/****************************************************************************
 Remove a directory.
****************************************************************************/

static int cmd_rmdir(void)
{
	pstring mask;
	pstring buf;
  
	pstrcpy(mask,cur_dir);
	
	if (!next_token_nr(NULL,buf,NULL,sizeof(buf))) {
		d_printf("rmdir <dirname>\n");
		return 1;
	}
	pstrcat(mask,buf);

	if (!cli_rmdir(cli, mask)) {
		d_printf("%s removing remote directory file %s\n",
			 cli_errstr(cli),mask);
	}
	
	return 0;
}

/****************************************************************************
 UNIX hardlink.
****************************************************************************/

static int cmd_link(void)
{
	pstring oldname,newname;
	pstring buf,buf2;
  
	if (!SERVER_HAS_UNIX_CIFS(cli)) {
		d_printf("Server doesn't support UNIX CIFS calls.\n");
		return 1;
	}

	pstrcpy(oldname,cur_dir);
	pstrcpy(newname,cur_dir);
  
	if (!next_token_nr(NULL,buf,NULL,sizeof(buf)) || 
	    !next_token_nr(NULL,buf2,NULL, sizeof(buf2))) {
		d_printf("link <oldname> <newname>\n");
		return 1;
	}

	pstrcat(oldname,buf);
	pstrcat(newname,buf2);

	if (!cli_unix_hardlink(cli, oldname, newname)) {
		d_printf("%s linking files (%s -> %s)\n", cli_errstr(cli), newname, oldname);
		return 1;
	}  

	return 0;
}

/****************************************************************************
 UNIX symlink.
****************************************************************************/

static int cmd_symlink(void)
{
	pstring oldname,newname;
	pstring buf,buf2;
  
	if (!SERVER_HAS_UNIX_CIFS(cli)) {
		d_printf("Server doesn't support UNIX CIFS calls.\n");
		return 1;
	}

	pstrcpy(oldname,cur_dir);
	pstrcpy(newname,cur_dir);
	
	if (!next_token_nr(NULL,buf,NULL,sizeof(buf)) || 
	    !next_token_nr(NULL,buf2,NULL, sizeof(buf2))) {
		d_printf("symlink <oldname> <newname>\n");
		return 1;
	}

	pstrcat(oldname,buf);
	pstrcat(newname,buf2);

	if (!cli_unix_symlink(cli, oldname, newname)) {
		d_printf("%s symlinking files (%s -> %s)\n",
			cli_errstr(cli), newname, oldname);
		return 1;
	} 

	return 0;
}

/****************************************************************************
 UNIX chmod.
****************************************************************************/

static int cmd_chmod(void)
{
	pstring src;
	mode_t mode;
	pstring buf, buf2;
  
	if (!SERVER_HAS_UNIX_CIFS(cli)) {
		d_printf("Server doesn't support UNIX CIFS calls.\n");
		return 1;
	}

	pstrcpy(src,cur_dir);
	
	if (!next_token_nr(NULL,buf,NULL,sizeof(buf)) || 
	    !next_token_nr(NULL,buf2,NULL, sizeof(buf2))) {
		d_printf("chmod mode file\n");
		return 1;
	}

	mode = (mode_t)strtol(buf, NULL, 8);
	pstrcat(src,buf2);

	if (!cli_unix_chmod(cli, src, mode)) {
		d_printf("%s chmod file %s 0%o\n",
			cli_errstr(cli), src, (unsigned int)mode);
		return 1;
	} 

	return 0;
}

/****************************************************************************
 UNIX chown.
****************************************************************************/

static int cmd_chown(void)
{
	pstring src;
	uid_t uid;
	gid_t gid;
	pstring buf, buf2, buf3;
  
	if (!SERVER_HAS_UNIX_CIFS(cli)) {
		d_printf("Server doesn't support UNIX CIFS calls.\n");
		return 1;
	}

	pstrcpy(src,cur_dir);
	
	if (!next_token_nr(NULL,buf,NULL,sizeof(buf)) || 
	    !next_token_nr(NULL,buf2,NULL, sizeof(buf2)) ||
	    !next_token_nr(NULL,buf3,NULL, sizeof(buf3))) {
		d_printf("chown uid gid file\n");
		return 1;
	}

	uid = (uid_t)atoi(buf);
	gid = (gid_t)atoi(buf2);
	pstrcat(src,buf3);

	if (!cli_unix_chown(cli, src, uid, gid)) {
		d_printf("%s chown file %s uid=%d, gid=%d\n",
			cli_errstr(cli), src, (int)uid, (int)gid);
		return 1;
	} 

	return 0;
}

/****************************************************************************
 Rename some file.
****************************************************************************/

static int cmd_rename(void)
{
	pstring src,dest;
	pstring buf,buf2;
  
	pstrcpy(src,cur_dir);
	pstrcpy(dest,cur_dir);
	
	if (!next_token_nr(NULL,buf,NULL,sizeof(buf)) || 
	    !next_token_nr(NULL,buf2,NULL, sizeof(buf2))) {
		d_printf("rename <src> <dest>\n");
		return 1;
	}

	pstrcat(src,buf);
	pstrcat(dest,buf2);

	if (!cli_rename(cli, src, dest)) {
		d_printf("%s renaming files\n",cli_errstr(cli));
		return 1;
	}
	
	return 0;
}

/****************************************************************************
 Hard link files using the NT call.
****************************************************************************/

static int cmd_hardlink(void)
{
	pstring src,dest;
	pstring buf,buf2;
  
	pstrcpy(src,cur_dir);
	pstrcpy(dest,cur_dir);
	
	if (!next_token_nr(NULL,buf,NULL,sizeof(buf)) || 
	    !next_token_nr(NULL,buf2,NULL, sizeof(buf2))) {
		d_printf("hardlink <src> <dest>\n");
		return 1;
	}

	pstrcat(src,buf);
	pstrcat(dest,buf2);

	if (!cli_nt_hardlink(cli, src, dest)) {
		d_printf("%s doing an NT hard link of files\n",cli_errstr(cli));
		return 1;
	}
	
	return 0;
}

/****************************************************************************
 Toggle the prompt flag.
****************************************************************************/

static int cmd_prompt(void)
{
	prompt = !prompt;
	DEBUG(2,("prompting is now %s\n",prompt?"on":"off"));
	
	return 1;
}

/****************************************************************************
 Set the newer than time.
****************************************************************************/

static int cmd_newer(void)
{
	pstring buf;
	BOOL ok;
	SMB_STRUCT_STAT sbuf;

	ok = next_token_nr(NULL,buf,NULL,sizeof(buf));
	if (ok && (sys_stat(buf,&sbuf) == 0)) {
		newer_than = sbuf.st_mtime;
		DEBUG(1,("Getting files newer than %s",
			 asctime(LocalTime(&newer_than))));
	} else {
		newer_than = 0;
	}

	if (ok && newer_than == 0) {
		d_printf("Error setting newer-than time\n");
		return 1;
	}

	return 0;
}

/****************************************************************************
 Set the archive level.
****************************************************************************/

static int cmd_archive(void)
{
	pstring buf;

	if (next_token_nr(NULL,buf,NULL,sizeof(buf))) {
		archive_level = atoi(buf);
	} else
		d_printf("Archive level is %d\n",archive_level);

	return 0;
}

/****************************************************************************
 Toggle the lowercaseflag.
****************************************************************************/

static int cmd_lowercase(void)
{
	lowercase = !lowercase;
	DEBUG(2,("filename lowercasing is now %s\n",lowercase?"on":"off"));

	return 0;
}

/****************************************************************************
 Toggle the recurse flag.
****************************************************************************/

static int cmd_recurse(void)
{
	recurse = !recurse;
	DEBUG(2,("directory recursion is now %s\n",recurse?"on":"off"));

	return 0;
}

/****************************************************************************
 Toggle the translate flag.
****************************************************************************/

static int cmd_translate(void)
{
	translation = !translation;
	DEBUG(2,("CR/LF<->LF and print text translation now %s\n",
		 translation?"on":"off"));

	return 0;
}

/****************************************************************************
 Do a printmode command.
****************************************************************************/

static int cmd_printmode(void)
{
	fstring buf;
	fstring mode;

	if (next_token_nr(NULL,buf,NULL,sizeof(buf))) {
		if (strequal(buf,"text")) {
			printmode = 0;      
		} else {
			if (strequal(buf,"graphics"))
				printmode = 1;
			else
				printmode = atoi(buf);
		}
	}

	switch(printmode) {
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

	return 0;
}

/****************************************************************************
 Do the lcd command.
 ****************************************************************************/

static int cmd_lcd(void)
{
	pstring buf;
	pstring d;
	
	if (next_token_nr(NULL,buf,NULL,sizeof(buf)))
		chdir(buf);
	DEBUG(2,("the local directory is now %s\n",sys_getwd(d)));

	return 0;
}

/****************************************************************************
 Get a file restarting at end of local file.
 ****************************************************************************/

static int cmd_reget(void)
{
	pstring local_name;
	pstring remote_name;
	char *p;

	pstrcpy(remote_name, cur_dir);
	pstrcat(remote_name, "\\");
	
	p = remote_name + strlen(remote_name);
	
	if (!next_token_nr(NULL, p, NULL, sizeof(remote_name) - strlen(remote_name))) {
		d_printf("reget <filename>\n");
		return 1;
	}
	pstrcpy(local_name, p);
	dos_clean_name(remote_name);
	
	next_token_nr(NULL, local_name, NULL, sizeof(local_name));
	
	return do_get(remote_name, local_name, True);
}

/****************************************************************************
 Put a file restarting at end of local file.
 ****************************************************************************/

static int cmd_reput(void)
{
	pstring local_name;
	pstring remote_name;
	pstring buf;
	char *p = buf;
	SMB_STRUCT_STAT st;
	
	pstrcpy(remote_name, cur_dir);
	pstrcat(remote_name, "\\");
  
	if (!next_token_nr(NULL, p, NULL, sizeof(buf))) {
		d_printf("reput <filename>\n");
		return 1;
	}
	pstrcpy(local_name, p);
  
	if (!file_exist(local_name, &st)) {
		d_printf("%s does not exist\n", local_name);
		return 1;
	}

	if (next_token_nr(NULL, p, NULL, sizeof(buf)))
		pstrcat(remote_name, p);
	else
		pstrcat(remote_name, local_name);
	
	dos_clean_name(remote_name);

	return do_put(remote_name, local_name, True);
}

/****************************************************************************
 List a share name.
 ****************************************************************************/

static void browse_fn(const char *name, uint32 m, 
                      const char *comment, void *state)
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
	/* FIXME: If the remote machine returns non-ascii characters
	   in any of these fields, they can corrupt the output.  We
	   should remove them. */
	if (!grepable) {
		d_printf("\t%-15s %-10.10s%s\n",
               		name,typestr,comment);
	} else {
		d_printf ("%s|%s|%s\n",typestr,name,comment);
	}
}

/****************************************************************************
 Try and browse available connections on a host.
****************************************************************************/

static BOOL browse_host(BOOL sort)
{
	int ret;
	if (!grepable) {
	        d_printf("\n\tSharename       Type      Comment\n");
	        d_printf("\t---------       ----      -------\n");
	}

	if((ret = cli_RNetShareEnum(cli, browse_fn, NULL)) == -1)
		d_printf("Error returning browse list: %s\n", cli_errstr(cli));

	return (ret != -1);
}

/****************************************************************************
 List a server name.
****************************************************************************/

static void server_fn(const char *name, uint32 m, 
                      const char *comment, void *state)
{
	
	if (!grepable){
		d_printf("\t%-16s     %s\n", name, comment);
	} else {
		d_printf("%s|%s|%s\n",(char *)state, name, comment);
	}
}

/****************************************************************************
 Try and browse available connections on a host.
****************************************************************************/

static BOOL list_servers(const char *wk_grp)
{
	if (!cli->server_domain)
		return False;

	if (!grepable) {
        	d_printf("\n\tServer               Comment\n");
        	d_printf("\t---------            -------\n");
	};
	cli_NetServerEnum(cli, cli->server_domain, SV_TYPE_ALL, server_fn,
			  "Server");

	if (!grepable) {
	        d_printf("\n\tWorkgroup            Master\n");
	        d_printf("\t---------            -------\n");
	}; 

	cli_NetServerEnum(cli, cli->server_domain, SV_TYPE_DOMAIN_ENUM,
			  server_fn, "Workgroup");
	return True;
}

/****************************************************************************
 Print or set current VUID
****************************************************************************/

static int cmd_vuid(void)
{
	fstring buf;
	
	if (!next_token_nr(NULL,buf,NULL,sizeof(buf))) {
		d_printf("Current VUID is %d\n", cli->vuid);
		return 0;
	}

	cli->vuid = atoi(buf);
	return 0;
}

/****************************************************************************
 Setup a new VUID, by issuing a session setup
****************************************************************************/

static int cmd_logon(void)
{
	pstring l_username, l_password;
	pstring buf,buf2;
  
	if (!next_token_nr(NULL,buf,NULL,sizeof(buf))) {
		d_printf("logon <username> [<password>]\n");
		return 0;
	}

	pstrcpy(l_username, buf);

	if (!next_token_nr(NULL,buf2,NULL,sizeof(buf))) {
		char *pass = getpass("Password: ");
		if (pass) {
			pstrcpy(l_password, pass);
			got_pass = 1;
		}
	} else {
		pstrcpy(l_password, buf2);
	}

	if (!cli_session_setup(cli, l_username, 
			       l_password, strlen(l_password),
			       l_password, strlen(l_password),
			       lp_workgroup())) {
		d_printf("session setup failed: %s\n", cli_errstr(cli));
		return -1;
	}

	d_printf("Current VUID is %d\n", cli->vuid);
	return 0;
}

/* Some constants for completing filename arguments */

#define COMPL_NONE        0          /* No completions */
#define COMPL_REMOTE      1          /* Complete remote filename */
#define COMPL_LOCAL       2          /* Complete local filename */

/* This defines the commands supported by this client.
 * NOTE: The "!" must be the last one in the list because it's fn pointer
 *       field is NULL, and NULL in that field is used in process_tok()
 *       (below) to indicate the end of the list.  crh
 */
static struct
{
  const char *name;
  int (*fn)(void);
  const char *description;
  char compl_args[2];      /* Completion argument info */
} commands[] = {
  {"?",cmd_help,"[command] give help on a command",{COMPL_NONE,COMPL_NONE}},
  {"altname",cmd_altname,"<file> show alt name",{COMPL_NONE,COMPL_NONE}},
  {"archive",cmd_archive,"<level>\n0=ignore archive bit\n1=only get archive files\n2=only get archive files and reset archive bit\n3=get all files and reset archive bit",{COMPL_NONE,COMPL_NONE}},
  {"blocksize",cmd_block,"blocksize <number> (default 20)",{COMPL_NONE,COMPL_NONE}},
  {"cancel",cmd_cancel,"<jobid> cancel a print queue entry",{COMPL_NONE,COMPL_NONE}},
  {"cd",cmd_cd,"[directory] change/report the remote directory",{COMPL_REMOTE,COMPL_NONE}},
  {"chmod",cmd_chmod,"<src> <mode> chmod a file using UNIX permission",{COMPL_REMOTE,COMPL_REMOTE}},
  {"chown",cmd_chown,"<src> <uid> <gid> chown a file using UNIX uids and gids",{COMPL_REMOTE,COMPL_REMOTE}},
  {"del",cmd_del,"<mask> delete all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"dir",cmd_dir,"<mask> list the contents of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"du",cmd_du,"<mask> computes the total size of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"exit",cmd_quit,"logoff the server",{COMPL_NONE,COMPL_NONE}},
  {"get",cmd_get,"<remote name> [local name] get a file",{COMPL_REMOTE,COMPL_LOCAL}},
  {"hardlink",cmd_hardlink,"<src> <dest> create a Windows hard link",{COMPL_REMOTE,COMPL_REMOTE}},
  {"help",cmd_help,"[command] give help on a command",{COMPL_NONE,COMPL_NONE}},
  {"history",cmd_history,"displays the command history",{COMPL_NONE,COMPL_NONE}},
  {"lcd",cmd_lcd,"[directory] change/report the local current working directory",{COMPL_LOCAL,COMPL_NONE}},
  {"link",cmd_link,"<oldname> <newname> create a UNIX hard link",{COMPL_REMOTE,COMPL_REMOTE}},
  {"lowercase",cmd_lowercase,"toggle lowercasing of filenames for get",{COMPL_NONE,COMPL_NONE}},  
  {"ls",cmd_dir,"<mask> list the contents of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"mask",cmd_select,"<mask> mask all filenames against this",{COMPL_REMOTE,COMPL_NONE}},
  {"md",cmd_mkdir,"<directory> make a directory",{COMPL_NONE,COMPL_NONE}},
  {"mget",cmd_mget,"<mask> get all the matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"mkdir",cmd_mkdir,"<directory> make a directory",{COMPL_NONE,COMPL_NONE}},
  {"more",cmd_more,"<remote name> view a remote file with your pager",{COMPL_REMOTE,COMPL_NONE}},  
  {"mput",cmd_mput,"<mask> put all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"newer",cmd_newer,"<file> only mget files newer than the specified local file",{COMPL_LOCAL,COMPL_NONE}},
  {"open",cmd_open,"<mask> open a file",{COMPL_REMOTE,COMPL_NONE}},
  {"print",cmd_print,"<file name> print a file",{COMPL_NONE,COMPL_NONE}},
  {"printmode",cmd_printmode,"<graphics or text> set the print mode",{COMPL_NONE,COMPL_NONE}},
  {"prompt",cmd_prompt,"toggle prompting for filenames for mget and mput",{COMPL_NONE,COMPL_NONE}},  
  {"put",cmd_put,"<local name> [remote name] put a file",{COMPL_LOCAL,COMPL_REMOTE}},
  {"pwd",cmd_pwd,"show current remote directory (same as 'cd' with no args)",{COMPL_NONE,COMPL_NONE}},
  {"q",cmd_quit,"logoff the server",{COMPL_NONE,COMPL_NONE}},
  {"queue",cmd_queue,"show the print queue",{COMPL_NONE,COMPL_NONE}},
  {"quit",cmd_quit,"logoff the server",{COMPL_NONE,COMPL_NONE}},
  {"rd",cmd_rmdir,"<directory> remove a directory",{COMPL_NONE,COMPL_NONE}},
  {"recurse",cmd_recurse,"toggle directory recursion for mget and mput",{COMPL_NONE,COMPL_NONE}},  
  {"reget",cmd_reget,"<remote name> [local name] get a file restarting at end of local file",{COMPL_REMOTE,COMPL_LOCAL}},
  {"rename",cmd_rename,"<src> <dest> rename some files",{COMPL_REMOTE,COMPL_REMOTE}},
  {"reput",cmd_reput,"<local name> [remote name] put a file restarting at end of remote file",{COMPL_LOCAL,COMPL_REMOTE}},
  {"rm",cmd_del,"<mask> delete all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"rmdir",cmd_rmdir,"<directory> remove a directory",{COMPL_NONE,COMPL_NONE}},
  {"setmode",cmd_setmode,"filename <setmode string> change modes of file",{COMPL_REMOTE,COMPL_NONE}},
  {"symlink",cmd_symlink,"<oldname> <newname> create a UNIX symlink",{COMPL_REMOTE,COMPL_REMOTE}},
  {"tar",cmd_tar,"tar <c|x>[IXFqbgNan] current directory to/from <file name>",{COMPL_NONE,COMPL_NONE}},
  {"tarmode",cmd_tarmode,"<full|inc|reset|noreset> tar's behaviour towards archive bits",{COMPL_NONE,COMPL_NONE}},
  {"translate",cmd_translate,"toggle text translation for printing",{COMPL_NONE,COMPL_NONE}},
  {"vuid",cmd_vuid,"change current vuid",{COMPL_NONE,COMPL_NONE}},
  {"logon",cmd_logon,"establish new logon",{COMPL_NONE,COMPL_NONE}},
  
  /* Yes, this must be here, see crh's comment above. */
  {"!",NULL,"run a shell command on the local system",{COMPL_NONE,COMPL_NONE}},
  {NULL,NULL,NULL,{COMPL_NONE,COMPL_NONE}}
};

/*******************************************************************
 Lookup a command string in the list of commands, including 
 abbreviations.
******************************************************************/

static int process_tok(pstring tok)
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
 Help.
****************************************************************************/

static int cmd_help(void)
{
	int i=0,j;
	pstring buf;
	
	if (next_token_nr(NULL,buf,NULL,sizeof(buf))) {
		if ((i = process_tok(buf)) >= 0)
			d_printf("HELP %s:\n\t%s\n\n",commands[i].name,commands[i].description);
	} else {
		while (commands[i].description) {
			for (j=0; commands[i].description && (j<5); j++) {
				d_printf("%-15s",commands[i].name);
				i++;
			}
			d_printf("\n");
		}
	}
	return 0;
}

/****************************************************************************
 Process a -c command string.
****************************************************************************/

static int process_command_string(char *cmd)
{
	pstring line;
	const char *ptr;
	int rc = 0;

	/* establish the connection if not already */
	
	if (!cli) {
		cli = do_connect(desthost, service);
		if (!cli)
			return 0;
	}
	
	while (cmd[0] != '\0')    {
		char *p;
		pstring tok;
		int i;
		
		if ((p = strchr_m(cmd, ';')) == 0) {
			strncpy(line, cmd, 999);
			line[1000] = '\0';
			cmd += strlen(cmd);
		} else {
			if (p - cmd > 999)
				p = cmd + 999;
			strncpy(line, cmd, p - cmd);
			line[p - cmd] = '\0';
			cmd = p + 1;
		}
		
		/* and get the first part of the command */
		ptr = line;
		if (!next_token_nr(&ptr,tok,NULL,sizeof(tok))) continue;
		
		if ((i = process_tok(tok)) >= 0) {
			rc = commands[i].fn();
		} else if (i == -2) {
			d_printf("%s: command abbreviation ambiguous\n",tok);
		} else {
			d_printf("%s: command not found\n",tok);
		}
	}
	
	return rc;
}	

#define MAX_COMPLETIONS 100

typedef struct {
	pstring dirmask;
	char **matches;
	int count, samelen;
	const char *text;
	int len;
} completion_remote_t;

static void completion_remote_filter(file_info *f, const char *mask, void *state)
{
	completion_remote_t *info = (completion_remote_t *)state;

	if ((info->count < MAX_COMPLETIONS - 1) && (strncmp(info->text, f->name, info->len) == 0) && (strcmp(f->name, ".") != 0) && (strcmp(f->name, "..") != 0)) {
		if ((info->dirmask[0] == 0) && !(f->mode & aDIR))
			info->matches[info->count] = strdup(f->name);
		else {
			pstring tmp;

			if (info->dirmask[0] != 0)
				pstrcpy(tmp, info->dirmask);
			else
				tmp[0] = 0;
			pstrcat(tmp, f->name);
			if (f->mode & aDIR)
				pstrcat(tmp, "/");
			info->matches[info->count] = strdup(tmp);
		}
		if (info->matches[info->count] == NULL)
			return;
		if (f->mode & aDIR)
			smb_readline_ca_char(0);

		if (info->count == 1)
			info->samelen = strlen(info->matches[info->count]);
		else
			while (strncmp(info->matches[info->count], info->matches[info->count-1], info->samelen) != 0)
				info->samelen--;
		info->count++;
	}
}

static char **remote_completion(const char *text, int len)
{
	pstring dirmask;
	int i;
	completion_remote_t info = { "", NULL, 1, 0, NULL, 0 };

	/* can't have non-static intialisation on Sun CC, so do it
	   at run time here */
	info.samelen = len;
	info.text = text;
	info.len = len;
		
	if (len >= PATH_MAX)
		return(NULL);

	info.matches = (char **)malloc(sizeof(info.matches[0])*MAX_COMPLETIONS);
	if (!info.matches) return NULL;
	info.matches[0] = NULL;

	for (i = len-1; i >= 0; i--)
		if ((text[i] == '/') || (text[i] == '\\'))
			break;
	info.text = text+i+1;
	info.samelen = info.len = len-i-1;

	if (i > 0) {
		strncpy(info.dirmask, text, i+1);
		info.dirmask[i+1] = 0;
		pstr_sprintf(dirmask, "%s%*s*", cur_dir, i-1, text);
	} else
		pstr_sprintf(dirmask, "%s*", cur_dir);

	if (cli_list(cli, dirmask, aDIR | aSYSTEM | aHIDDEN, completion_remote_filter, &info) < 0)
		goto cleanup;

	if (info.count == 2)
		info.matches[0] = strdup(info.matches[1]);
	else {
		info.matches[0] = malloc(info.samelen+1);
		if (!info.matches[0])
			goto cleanup;
		strncpy(info.matches[0], info.matches[1], info.samelen);
		info.matches[0][info.samelen] = 0;
	}
	info.matches[info.count] = NULL;
	return info.matches;

cleanup:
	for (i = 0; i < info.count; i++)
		free(info.matches[i]);
	free(info.matches);
	return NULL;
}

static char **completion_fn(const char *text, int start, int end)
{
	smb_readline_ca_char(' ');

	if (start) {
		const char *buf, *sp;
		int i;
		char compl_type;

		buf = smb_readline_get_line_buffer();
		if (buf == NULL)
			return NULL;
		
		sp = strchr(buf, ' ');
		if (sp == NULL)
			return NULL;
		
		for (i = 0; commands[i].name; i++)
			if ((strncmp(commands[i].name, text, sp - buf) == 0) && (commands[i].name[sp - buf] == 0))
				break;
		if (commands[i].name == NULL)
			return NULL;

		while (*sp == ' ')
			sp++;

		if (sp == (buf + start))
			compl_type = commands[i].compl_args[0];
		else
			compl_type = commands[i].compl_args[1];

		if (compl_type == COMPL_REMOTE)
			return remote_completion(text, end - start);
		else /* fall back to local filename completion */
			return NULL;
	} else {
		char **matches;
		int i, len, samelen, count=1;

		matches = (char **)malloc(sizeof(matches[0])*MAX_COMPLETIONS);
		if (!matches) return NULL;
		matches[0] = NULL;

		len = strlen(text);
		for (i=0;commands[i].fn && count < MAX_COMPLETIONS-1;i++) {
			if (strncmp(text, commands[i].name, len) == 0) {
				matches[count] = strdup(commands[i].name);
				if (!matches[count])
					goto cleanup;
				if (count == 1)
					samelen = strlen(matches[count]);
				else
					while (strncmp(matches[count], matches[count-1], samelen) != 0)
						samelen--;
				count++;
			}
		}

		switch (count) {
		case 0:	/* should never happen */
		case 1:
			goto cleanup;
		case 2:
			matches[0] = strdup(matches[1]);
			break;
		default:
			matches[0] = malloc(samelen+1);
			if (!matches[0])
				goto cleanup;
			strncpy(matches[0], matches[1], samelen);
			matches[0][samelen] = 0;
		}
		matches[count] = NULL;
		return matches;

cleanup:
		for (i = 0; i < count; i++)
			free(matches[i]);

		free(matches);
		return NULL;
	}
}

/****************************************************************************
 Make sure we swallow keepalives during idle time.
****************************************************************************/

static void readline_callback(void)
{
	fd_set fds;
	struct timeval timeout;
	static time_t last_t;
	time_t t;

	t = time(NULL);

	if (t - last_t < 5)
		return;

	last_t = t;

 again:

	if (cli->fd == -1)
		return;

	FD_ZERO(&fds);
	FD_SET(cli->fd,&fds);

	timeout.tv_sec = 0;
	timeout.tv_usec = 0;
	sys_select_intr(cli->fd+1,&fds,NULL,NULL,&timeout);
      		
	/* We deliberately use receive_smb instead of
	   client_receive_smb as we want to receive
	   session keepalives and then drop them here.
	*/
	if (FD_ISSET(cli->fd,&fds)) {
		receive_smb(cli->fd,cli->inbuf,0);
		goto again;
	}
      
	cli_chkpath(cli, "\\");
}

/****************************************************************************
 Process commands on stdin.
****************************************************************************/

static void process_stdin(void)
{
	const char *ptr;

	while (1) {
		pstring tok;
		pstring the_prompt;
		char *cline;
		pstring line;
		int i;
		
		/* display a prompt */
		slprintf(the_prompt, sizeof(the_prompt)-1, "smb: %s> ", cur_dir);
		cline = smb_readline(the_prompt, readline_callback, completion_fn);
			
		if (!cline) break;
		
		pstrcpy(line, cline);

		/* special case - first char is ! */
		if (*line == '!') {
			system(line + 1);
			continue;
		}
      
		/* and get the first part of the command */
		ptr = line;
		if (!next_token_nr(&ptr,tok,NULL,sizeof(tok))) continue;

		if ((i = process_tok(tok)) >= 0) {
			commands[i].fn();
		} else if (i == -2) {
			d_printf("%s: command abbreviation ambiguous\n",tok);
		} else {
			d_printf("%s: command not found\n",tok);
		}
	}
}

/***************************************************** 
 Return a connection to a server.
*******************************************************/

static struct cli_state *do_connect(const char *server, const char *share)
{
	struct cli_state *c;
	struct nmb_name called, calling;
	const char *server_n;
	struct in_addr ip;
	pstring servicename;
	char *sharename;
	
	/* make a copy so we don't modify the global string 'service' */
	pstrcpy(servicename, share);
	sharename = servicename;
	if (*sharename == '\\') {
		server = sharename+2;
		sharename = strchr_m(server,'\\');
		if (!sharename) return NULL;
		*sharename = 0;
		sharename++;
	}

	server_n = server;
	
	zero_ip(&ip);

	make_nmb_name(&calling, global_myname(), 0x0);
	make_nmb_name(&called , server, name_type);

 again:
	zero_ip(&ip);
	if (have_ip) ip = dest_ip;

	/* have to open a new connection */
	if (!(c=cli_initialise(NULL)) || (cli_set_port(c, port) != port) ||
	    !cli_connect(c, server_n, &ip)) {
		d_printf("Connection to %s failed\n", server_n);
		return NULL;
	}

	c->protocol = max_protocol;
	c->use_kerberos = use_kerberos;
	cli_setup_signing_state(c, cmdline_auth_info.signing_state);
		

	if (!cli_session_request(c, &calling, &called)) {
		char *p;
		d_printf("session request to %s failed (%s)\n", 
			 called.name, cli_errstr(c));
		cli_shutdown(c);
		if ((p=strchr_m(called.name, '.'))) {
			*p = 0;
			goto again;
		}
		if (strcmp(called.name, "*SMBSERVER")) {
			make_nmb_name(&called , "*SMBSERVER", 0x20);
			goto again;
		}
		return NULL;
	}

	DEBUG(4,(" session request ok\n"));

	if (!cli_negprot(c)) {
		d_printf("protocol negotiation failed\n");
		cli_shutdown(c);
		return NULL;
	}

	if (!got_pass) {
		char *pass = getpass("Password: ");
		if (pass) {
			pstrcpy(password, pass);
			got_pass = 1;
		}
	}

	if (!cli_session_setup(c, username, 
			       password, strlen(password),
			       password, strlen(password),
			       lp_workgroup())) {
		/* if a password was not supplied then try again with a null username */
		if (password[0] || !username[0] || use_kerberos ||
		    !cli_session_setup(c, "", "", 0, "", 0, lp_workgroup())) { 
			d_printf("session setup failed: %s\n", cli_errstr(c));
			if (NT_STATUS_V(cli_nt_error(c)) == 
			    NT_STATUS_V(NT_STATUS_MORE_PROCESSING_REQUIRED))
				d_printf("did you forget to run kinit?\n");
			cli_shutdown(c);
			return NULL;
		}
		d_printf("Anonymous login successful\n");
	}

	if (*c->server_domain) {
		DEBUG(1,("Domain=[%s] OS=[%s] Server=[%s]\n",
			c->server_domain,c->server_os,c->server_type));
	} else if (*c->server_os || *c->server_type){
		DEBUG(1,("OS=[%s] Server=[%s]\n",
			 c->server_os,c->server_type));
	}		
	DEBUG(4,(" session setup ok\n"));

	if (!cli_send_tconX(c, sharename, "?????",
			    password, strlen(password)+1)) {
		d_printf("tree connect failed: %s\n", cli_errstr(c));
		cli_shutdown(c);
		return NULL;
	}

	DEBUG(4,(" tconx ok\n"));

	return c;
}

/****************************************************************************
 Process commands from the client.
****************************************************************************/

static int process(char *base_directory)
{
	int rc = 0;

	cli = do_connect(desthost, service);
	if (!cli) {
		return 1;
	}

	if (*base_directory) do_cd(base_directory);
	
	if (cmdstr) {
		rc = process_command_string(cmdstr);
	} else {
		process_stdin();
	}
  
	cli_shutdown(cli);
	return rc;
}

/****************************************************************************
 Handle a -L query.
****************************************************************************/

static int do_host_query(char *query_host)
{
	cli = do_connect(query_host, "IPC$");
	if (!cli)
		return 1;

	browse_host(True);

	if (port != 139) {

		/* Workgroups simply don't make sense over anything
		   else but port 139... */

		cli_shutdown(cli);
		port = 139;
		cli = do_connect(query_host, "IPC$");
	}

	if (cli == NULL) {
		d_printf("NetBIOS over TCP disabled -- no workgroup available\n");
		return 1;
	}

	list_servers(lp_workgroup());

	cli_shutdown(cli);
	
	return(0);
}


/****************************************************************************
 Handle a tar operation.
****************************************************************************/

static int do_tar_op(char *base_directory)
{
	int ret;

	/* do we already have a connection? */
	if (!cli) {
		cli = do_connect(desthost, service);	
		if (!cli)
			return 1;
	}

	recurse=True;

	if (*base_directory) do_cd(base_directory);
	
	ret=process_tar();

	cli_shutdown(cli);

	return(ret);
}

/****************************************************************************
 Handle a message operation.
****************************************************************************/

static int do_message_op(void)
{
	struct in_addr ip;
	struct nmb_name called, calling;
	fstring server_name;
	char name_type_hex[10];

	make_nmb_name(&calling, global_myname(), 0x0);
	make_nmb_name(&called , desthost, name_type);

	fstrcpy(server_name, desthost);
	snprintf(name_type_hex, sizeof(name_type_hex), "#%X", name_type);
	fstrcat(server_name, name_type_hex);

        zero_ip(&ip);
	if (have_ip) ip = dest_ip;

	if (!(cli=cli_initialise(NULL)) || (cli_set_port(cli, port) != port) ||
	    !cli_connect(cli, server_name, &ip)) {
		d_printf("Connection to %s failed\n", desthost);
		return 1;
	}

	if (!cli_session_request(cli, &calling, &called)) {
		d_printf("session request failed\n");
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
	extern BOOL AllowDebugChange;
	extern BOOL override_logfile;
	pstring base_directory;
	int opt;
	pstring query_host;
	BOOL message = False;
	extern char tar_type;
	pstring term_code;
	static const char *new_name_resolve_order = NULL;
	poptContext pc;
	char *p;
	int rc = 0;
	fstring new_workgroup;
	struct poptOption long_options[] = {
		POPT_AUTOHELP

		{ "name-resolve", 'R', POPT_ARG_STRING, &new_name_resolve_order, 'R', "Use these name resolution services only", "NAME-RESOLVE-ORDER" },
		{ "message", 'M', POPT_ARG_STRING, NULL, 'M', "Send message", "HOST" },
		{ "ip-address", 'I', POPT_ARG_STRING, NULL, 'I', "Use this IP to connect to", "IP" },
		{ "stderr", 'E', POPT_ARG_NONE, NULL, 'E', "Write messages to stderr instead of stdout" },
		{ "list", 'L', POPT_ARG_STRING, NULL, 'L', "Get a list of shares available on a host", "HOST" },
		{ "terminal", 't', POPT_ARG_STRING, NULL, 't', "Terminal I/O code {sjis|euc|jis7|jis8|junet|hex}", "CODE" },
		{ "max-protocol", 'm', POPT_ARG_STRING, NULL, 'm', "Set the max protocol level", "LEVEL" },
		{ "tar", 'T', POPT_ARG_STRING, NULL, 'T', "Command line tar", "<c|x>IXFqgbNan" },
		{ "directory", 'D', POPT_ARG_STRING, NULL, 'D', "Start from directory", "DIR" },
		{ "command", 'c', POPT_ARG_STRING, &cmdstr, 'c', "Execute semicolon separated commands" }, 
		{ "send-buffer", 'b', POPT_ARG_INT, &io_bufsize, 'b', "Changes the transmit/send buffer", "BYTES" },
		{ "port", 'p', POPT_ARG_INT, &port, 'p', "Port to connect to", "PORT" },
		{ "grepable", 'g', POPT_ARG_NONE, NULL, 'g', "Produce grepable output" },
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_TABLEEND
	};
	

#ifdef KANJI
	pstrcpy(term_code, KANJI);
#else /* KANJI */
	*term_code = 0;
#endif /* KANJI */

	*query_host = 0;
	*base_directory = 0;
	
	/* initialize the workgroup name so we can determine whether or 
	   not it was set by a command line option */
	   
	set_global_myworkgroup( "" );

        /* set default debug level to 0 regardless of what smb.conf sets */
	setup_logging( "smbclient", True );
	DEBUGLEVEL_CLASS[DBGC_ALL] = 1;
	dbf = x_stderr;
	x_setbuf( x_stderr, NULL );

	pc = poptGetContext("smbclient", argc, (const char **) argv, long_options, 
				POPT_CONTEXT_KEEP_FIRST);
	poptSetOtherOptionHelp(pc, "service <password>");

	in_client = True;   /* Make sure that we tell lp_load we are */

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'M':
			/* Messages are sent to NetBIOS name type 0x3
			 * (Messenger Service).  Make sure we default
			 * to port 139 instead of port 445. srl,crh
			 */
			name_type = 0x03; 
			pstrcpy(desthost,poptGetOptArg(pc));
			if( 0 == port )
				port = 139;
 			message = True;
 			break;
		case 'I':
			{
				dest_ip = *interpret_addr2(poptGetOptArg(pc));
				if (is_zero_ip(dest_ip))
					exit(1);
				have_ip = True;
			}
			break;
		case 'E':
			dbf = x_stderr;
			display_set_stderr();
			break;

		case 'L':
			pstrcpy(query_host, poptGetOptArg(pc));
			break;
		case 't':
			pstrcpy(term_code, poptGetOptArg(pc));
			break;
		case 'm':
			max_protocol = interpret_protocol(poptGetOptArg(pc), max_protocol);
			break;
		case 'T':
			/* We must use old option processing for this. Find the
			 * position of the -T option in the raw argv[]. */
			{
				int i, optnum;
				for (i = 1; i < argc; i++) {
					if (strncmp("-T", argv[i],2)==0)
						break;
				}
				i++;
				if (!(optnum = tar_parseargs(argc, argv, poptGetOptArg(pc), i))) {
					poptPrintUsage(pc, stderr, 0);
					exit(1);
				}
				/* Now we must eat (optnum - i) options - they have
				 * been processed by tar_parseargs().
				 */
				optnum -= i;
				for (i = 0; i < optnum; i++)
					poptGetOptArg(pc);
			}
			break;
		case 'D':
			pstrcpy(base_directory,poptGetOptArg(pc));
			break;
		case 'g':
			grepable=True;
			break;
		}
	}

	poptGetArg(pc);
	
	/*
	 * Don't load debug level from smb.conf. It should be
	 * set by cmdline arg or remain default (0)
	 */
	AllowDebugChange = False;
	
	/* save the workgroup...
	
	   FIXME!! do we need to do this for other options as well 
	   (or maybe a generic way to keep lp_load() from overwriting 
	   everything)?  */
	
	fstrcpy( new_workgroup, lp_workgroup() );
	
	if ( override_logfile )
		setup_logging( lp_logfile(), False );
	
	if (!lp_load(dyn_CONFIGFILE,True,False,False)) {
		fprintf(stderr, "%s: Can't load %s - run testparm to debug it\n",
			argv[0], dyn_CONFIGFILE);
	}
	
	load_interfaces();
	
	if ( strlen(new_workgroup) != 0 )
		set_global_myworkgroup( new_workgroup );

	if(poptPeekArg(pc)) {
		pstrcpy(service,poptGetArg(pc));  
		/* Convert any '/' characters in the service name to '\' characters */
		string_replace(service, '/','\\');

		if (count_chars(service,'\\') < 3) {
			d_printf("\n%s: Not enough '\\' characters in service\n",service);
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
	}

	if (poptPeekArg(pc) && !cmdline_auth_info.got_pass) { 
		cmdline_auth_info.got_pass = True;
		pstrcpy(cmdline_auth_info.password,poptGetArg(pc));  
	}

	init_names();

	if(new_name_resolve_order)
		lp_set_name_resolve_order(new_name_resolve_order);

	if (!tar_type && !*query_host && !*service && !message) {
		poptPrintUsage(pc, stderr, 0);
		exit(1);
	}

	poptFreeContext(pc);

	pstrcpy(username, cmdline_auth_info.username);
	pstrcpy(password, cmdline_auth_info.password);

	use_kerberos = cmdline_auth_info.use_kerberos;
	got_pass = cmdline_auth_info.got_pass;

	DEBUG(3,("Client started (version %s).\n", SAMBA_VERSION_STRING));

	if (tar_type) {
		if (cmdstr)
			process_command_string(cmdstr);
		return do_tar_op(base_directory);
	}

	if (*query_host) {
		char *qhost = query_host;
		char *slash;

		while (*qhost == '\\' || *qhost == '/')
			qhost++;

		if ((slash = strchr_m(qhost, '/'))
		    || (slash = strchr_m(qhost, '\\'))) {
			*slash = 0;
		}

		if ((p=strchr_m(qhost, '#'))) {
			*p = 0;
			p++;
			sscanf(p, "%x", &name_type);
		}
  
		return do_host_query(qhost);
	}

	if (message) {
		return do_message_op();
	}
	
	if (process(base_directory)) {
		return 1;
	}

	return rc;
}
