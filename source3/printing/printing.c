/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   printing routines
   Copyright (C) Andrew Tridgell 1992-1998
   
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

#include "includes.h"
extern int DEBUGLEVEL;

static BOOL * lpq_cache_reset=NULL;

static int check_lpq_cache(int snum) {
  static int lpq_caches=0;
  
  if (lpq_caches <= snum) {
      BOOL * p;
      p = (BOOL *) Realloc(lpq_cache_reset,(snum+1)*sizeof(BOOL));
      if (p) {
	 lpq_cache_reset=p;
	 lpq_caches = snum+1;
      }
  }
  return lpq_caches;
}

void lpq_reset(int snum)
{
  if (check_lpq_cache(snum) > snum) lpq_cache_reset[snum]=True;
}


/****************************************************************************
Build the print command in the supplied buffer. This means getting the
print command for the service and inserting the printer name and the
print file name. Return NULL on error, else the passed buffer pointer.
****************************************************************************/
static char *build_print_command(connection_struct *conn,
				 char *command, 
				 char *syscmd, char *filename)
{
	int snum = SNUM(conn);
	char *tstr;
  
	/* get the print command for the service. */
	tstr = command;
	if (!syscmd || !tstr) {
		DEBUG(0,("No print command for service `%s'\n", 
			 SERVICE(snum)));
		return (NULL);
	}

	/* copy the command into the buffer for extensive meddling. */
	StrnCpy(syscmd, tstr, sizeof(pstring) - 1);
  
	/* look for "%s" in the string. If there is no %s, we cannot print. */   
	if (!strstr(syscmd, "%s") && !strstr(syscmd, "%f")) {
		DEBUG(2,("WARNING! No placeholder for the filename in the print command for service %s!\n", SERVICE(snum)));
	}
  
	pstring_sub(syscmd, "%s", filename);
	pstring_sub(syscmd, "%f", filename);
  
	/* Does the service have a printername? If not, make a fake
           and empty */
	/* printer name. That way a %p is treated sanely if no printer */
	/* name was specified to replace it. This eventuality is logged.  */
	tstr = PRINTERNAME(snum);
	if (tstr == NULL || tstr[0] == '\0') {
		DEBUG(3,( "No printer name - using %s.\n", SERVICE(snum)));
		tstr = SERVICE(snum);
	}
  
	pstring_sub(syscmd, "%p", tstr);
  
	standard_sub(conn,syscmd);
  
	return (syscmd);
}


/****************************************************************************
print a file - called on closing the file
****************************************************************************/
void print_file(connection_struct *conn, files_struct *file)
{
	pstring syscmd;
	int snum = SNUM(conn);
	char *tempstr;

	*syscmd = 0;

	if (dos_file_size(file->fsp_name) <= 0) {
		DEBUG(3,("Discarding null print job %s\n",file->fsp_name));
		dos_unlink(file->fsp_name);
		return;
	}

	tempstr = build_print_command(conn, 
				      PRINTCOMMAND(snum), 
				      syscmd, file->fsp_name);
	if (tempstr != NULL) {
		int ret = smbrun(syscmd,NULL,False);
		DEBUG(3,("Running the command `%s' gave %d\n",syscmd,ret));
	} else {
		DEBUG(0,("Null print command?\n"));
	}
  
	lpq_reset(snum);
}


/****************************************************************************
get a printer queue
****************************************************************************/
int get_printqueue(int snum, 
		   connection_struct *conn,print_queue_struct **queue,
		   print_status_struct *status)
{
	char *lpq_command = lp_lpqcommand(snum);
	char *printername = PRINTERNAME(snum);
	int ret=0,count=0;
	pstring syscmd;
	fstring outfile;
	pstring line;
	FILE *f;
	SMB_STRUCT_STAT sbuf;
	BOOL dorun=True;
	int cachetime = lp_lpqcachetime();
	
	*line = 0;
	check_lpq_cache(snum);
	
	if (!printername || !*printername) {
		DEBUG(6,("xx replacing printer name with service (snum=(%s,%d))\n",
			 lp_servicename(snum),snum));
		printername = lp_servicename(snum);
	}
    
	if (!lpq_command || !(*lpq_command)) {
		DEBUG(5,("No lpq command\n"));
		return(0);
	}
    
	pstrcpy(syscmd,lpq_command);
	pstring_sub(syscmd,"%p",printername);

	standard_sub(conn,syscmd);

	slprintf(outfile,sizeof(outfile)-1, "%s/lpq.%08x",tmpdir(),str_checksum(syscmd));
  
	if (!lpq_cache_reset[snum] && cachetime && !sys_stat(outfile,&sbuf)) {
		if (time(NULL) - sbuf.st_mtime < cachetime) {
			DEBUG(3,("Using cached lpq output\n"));
			dorun = False;
		}
	}

	if (dorun) {
		ret = smbrun(syscmd,outfile,True);
		DEBUG(3,("Running the command `%s' gave %d\n",syscmd,ret));
	}

	lpq_cache_reset[snum] = False;

	f = sys_fopen(outfile,"r");
	if (!f) {
		return(0);
	}

	if (status) {
		fstrcpy(status->message,"");
		status->status = LPSTAT_OK;
	}
	
	while (fgets(line,sizeof(pstring),f)) {
		DEBUG(6,("QUEUE2: %s\n",line));
		
		*queue = Realloc(*queue,sizeof(print_queue_struct)*(count+1));
		if (! *queue) {
			count = 0;
			break;
		}

		memset((char *)&(*queue)[count],'\0',sizeof(**queue));
	  
		/* parse it */
		if (!parse_lpq_entry(snum,line,
				     &(*queue)[count],status,count==0))
			continue;
		
		count++;
	}	      

	fclose(f);
	
	if (!cachetime) {
		unlink(outfile);
	} else {
		/* we only expect this to succeed on trapdoor systems,
		   on normal systems the file is owned by root */
		chmod(outfile,0666);
	}
	return(count);
}


/****************************************************************************
delete a printer queue entry
****************************************************************************/
void del_printqueue(connection_struct *conn,int snum,int jobid)
{
  char *lprm_command = lp_lprmcommand(snum);
  char *printername = PRINTERNAME(snum);
  pstring syscmd;
  char jobstr[20];
  int ret;

  if (!printername || !*printername)
    {
      DEBUG(6,("replacing printer name with service (snum=(%s,%d))\n",
	    lp_servicename(snum),snum));
      printername = lp_servicename(snum);
    }
    
  if (!lprm_command || !(*lprm_command))
    {
      DEBUG(5,("No lprm command\n"));
      return;
    }
    
  slprintf(jobstr,sizeof(jobstr)-1,"%d",jobid);

  pstrcpy(syscmd,lprm_command);
  pstring_sub(syscmd,"%p",printername);
  pstring_sub(syscmd,"%j",jobstr);
  standard_sub(conn,syscmd);

  ret = smbrun(syscmd,NULL,False);
  DEBUG(3,("Running the command `%s' gave %d\n",syscmd,ret));  
  lpq_reset(snum); /* queue has changed */
}

/****************************************************************************
change status of a printer queue entry
****************************************************************************/
void status_printjob(connection_struct *conn,int snum,int jobid,int status)
{
  char *lpstatus_command = 
    (status==LPQ_PAUSED?lp_lppausecommand(snum):lp_lpresumecommand(snum));
  char *printername = PRINTERNAME(snum);
  pstring syscmd;
  char jobstr[20];
  int ret;

  if (!printername || !*printername)
    {
      DEBUG(6,("replacing printer name with service (snum=(%s,%d))\n",
	    lp_servicename(snum),snum));
      printername = lp_servicename(snum);
    }
    
  if (!lpstatus_command || !(*lpstatus_command))
    {
      DEBUG(5,("No lpstatus command to %s job\n",
	       (status==LPQ_PAUSED?"pause":"resume")));
      return;
    }
    
  slprintf(jobstr,sizeof(jobstr)-1,"%d",jobid);

  pstrcpy(syscmd,lpstatus_command);
  pstring_sub(syscmd,"%p",printername);
  pstring_sub(syscmd,"%j",jobstr);
  standard_sub(conn,syscmd);

  ret = smbrun(syscmd,NULL,False);
  DEBUG(3,("Running the command `%s' gave %d\n",syscmd,ret));  
  lpq_reset(snum); /* queue has changed */
}



/****************************************************************************
we encode print job numbers over the wire so that when we get them back we can
tell not only what print job they are but also what service it belongs to,
this is to overcome the problem that windows clients tend to send the wrong
service number when doing print queue manipulation!
****************************************************************************/
int printjob_encode(int snum, int job)
{
	return ((snum&0xFF)<<8) | (job & 0xFF);
}

/****************************************************************************
and now decode them again ...
****************************************************************************/
void printjob_decode(int jobid, int *snum, int *job)
{
	(*snum) = (jobid >> 8) & 0xFF;
	(*job) = jobid & 0xFF;
}

/****************************************************************************
 Change status of a printer queue
****************************************************************************/

void status_printqueue(connection_struct *conn,int snum,int status)
{
  char *queuestatus_command = (status==LPSTAT_STOPPED ? 
                               lp_queuepausecommand(snum):lp_queueresumecommand(snum));
  char *printername = PRINTERNAME(snum);
  pstring syscmd;
  int ret;

  if (!printername || !*printername) {
    DEBUG(6,("replacing printer name with service (snum=(%s,%d))\n",
          lp_servicename(snum),snum));
    printername = lp_servicename(snum);
  }

  if (!queuestatus_command || !(*queuestatus_command)) {
    DEBUG(5,("No queuestatus command to %s job\n",
          (status==LPSTAT_STOPPED?"pause":"resume")));
    return;
  }

  pstrcpy(syscmd,queuestatus_command);
  pstring_sub(syscmd,"%p",printername);
  standard_sub(conn,syscmd);

  ret = smbrun(syscmd,NULL,False);
  DEBUG(3,("Running the command `%s' gave %d\n",syscmd,ret));
  lpq_reset(snum); /* queue has changed */
}



/***************************************************************************
auto-load printer services
***************************************************************************/
static void add_all_printers(void)
{
	int printers = lp_servicenumber(PRINTERS_NAME);

	if (printers < 0) return;

	pcap_printer_fn(lp_add_one_printer);
}

/***************************************************************************
auto-load some homes and printer services
***************************************************************************/
static void add_auto_printers(void)
{
	char *p;
	int printers;
	char *str = lp_auto_services();

	if (!str) return;

	printers = lp_servicenumber(PRINTERS_NAME);

	if (printers < 0) return;
	
	for (p=strtok(str,LIST_SEP);p;p=strtok(NULL,LIST_SEP)) {
		if (lp_servicenumber(p) >= 0) continue;
		
		if (pcap_printername_ok(p,NULL)) {
			lp_add_printer(p,printers);
		}
	}
}

/***************************************************************************
load automatic printer services
***************************************************************************/
void load_printers(void)
{
	add_auto_printers();
	if (lp_load_printers())
		add_all_printers();
}
