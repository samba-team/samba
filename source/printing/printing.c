/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   printing routines
   Copyright (C) Andrew Tridgell 1992-1995
   
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
extern connection_struct Connections[];
extern files_struct Files[];

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
static char *build_print_command(int cnum, char *command, char *syscmd, char *filename1)
{
  int snum = SNUM(cnum);
  char *tstr;
  pstring filename;
  
  /* get the print command for the service. */
  tstr = command;
  if (!syscmd || !tstr) {
    DEBUG(0,("No print command for service `%s'\n", SERVICE(snum)));
    return (NULL);
  }

  /* copy the command into the buffer for extensive meddling. */
  StrnCpy(syscmd, tstr, sizeof(pstring) - 1);
  
  /* look for "%s" in the string. If there is no %s, we cannot print. */   
  if (!strstr(syscmd, "%s") && !strstr(syscmd, "%f")) {
    DEBUG(2,("WARNING! No placeholder for the filename in the print command for service %s!\n", SERVICE(snum)));
  }
  
  if (strstr(syscmd,"%s")) {
    int iOffset = PTR_DIFF(strstr(syscmd, "%s"),syscmd);
    
    /* construct the full path for the filename, shouldn't be necessary unless
       the subshell causes a "cd" to be executed.
       Only use the full path if there isn't a / preceding the %s */
    if (iOffset==0 || syscmd[iOffset-1] != '/') {
      StrnCpy(filename,Connections[cnum].connectpath,sizeof(filename)-1);
      trim_string(filename,"","/");
      strcat(filename,"/");
      strcat(filename,filename1);
    }
    else
      strcpy(filename,filename1);
    
    string_sub(syscmd, "%s", filename);
  }
  
  string_sub(syscmd, "%f", filename1);
  
  /* Does the service have a printername? If not, make a fake and empty    */
  /* printer name. That way a %p is treated sanely if no printer */
  /* name was specified to replace it. This eventuality is logged.         */
  tstr = PRINTERNAME(snum);
  if (tstr == NULL || tstr[0] == '\0') {
    DEBUG(3,( "No printer name - using %s.\n", SERVICE(snum)));
    tstr = SERVICE(snum);
  }
  
  string_sub(syscmd, "%p", tstr);
  
  standard_sub(cnum,syscmd);
  
  return (syscmd);
}


/****************************************************************************
print a file - called on closing the file
****************************************************************************/
void print_file(int fnum)
{
  pstring syscmd;
  int cnum = Files[fnum].cnum;
  int snum=SNUM(cnum);
  char *tempstr;

  *syscmd = 0;

  if (file_size(Files[fnum].name) <= 0) {
    DEBUG(3,("Discarding null print job %s\n",Files[fnum].name));
    sys_unlink(Files[fnum].name);
    return;
  }

  tempstr = build_print_command(cnum, PRINTCOMMAND(snum), syscmd, Files[fnum].name);
  if (tempstr != NULL)
    {
      int ret = smbrun(syscmd,NULL);
      DEBUG(3,("Running the command `%s' gave %d\n",syscmd,ret));
    }
  else
    DEBUG(0,("Null print command?\n"));
  
  lpq_reset(snum);
}

static char *Months[13] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
			      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", "Err"};


/*******************************************************************
process time fields
********************************************************************/
static time_t EntryTime(string tok[], int ptr, int count, int minimum)
{
  time_t jobtime,jobtime1;

  jobtime = time(NULL);		/* default case: take current time */
  if (count >= minimum) {
    struct tm *t;
    int i, day, hour, min, sec;
    char   *c;

    for (i=0; i<13; i++) if (!strncmp(tok[ptr], Months[i],3)) break; /* Find month */
    if (i<12) {
      t = localtime(&jobtime);
      day = atoi(tok[ptr+1]);
      c=(char *)(tok[ptr+2]);
      *(c+2)=0;
      hour = atoi(c);
      *(c+5)=0;
      min = atoi(c+3);
      if(*(c+6) != 0)sec = atoi(c+6);
      else  sec=0;

      if ((t->tm_mon < i)||
	  ((t->tm_mon == i)&&
	   ((t->tm_mday < day)||
	    ((t->tm_mday == day)&&
	     (t->tm_hour*60+t->tm_min < hour*60+min)))))
	t->tm_year--;		/* last year's print job */

      t->tm_mon = i;
      t->tm_mday = day;
      t->tm_hour = hour;
      t->tm_min = min;
      t->tm_sec = sec;
      jobtime1 = mktime(t);
      if (jobtime1 != (time_t)-1)
	jobtime = jobtime1;
    }
  }
  return jobtime;
}


/****************************************************************************
parse a lpq line

here is an example of lpq output under bsd

Warning: no daemon present
Rank   Owner      Job  Files                                 Total Size
1st    tridge     148  README                                8096 bytes

here is an example of lpq output under osf/1

Warning: no daemon present
Rank   Pri Owner      Job  Files                             Total Size
1st    0   tridge     148  README                            8096 bytes
****************************************************************************/
static BOOL parse_lpq_bsd(char *line,print_queue_struct *buf,BOOL first)
{
#ifdef	OSF1
#define	RANKTOK	0
#define	PRIOTOK 1
#define	USERTOK 2
#define	JOBTOK	3
#define	FILETOK	4
#define	TOTALTOK 5
#define	NTOK	6
#else	/* OSF1 */
#define	RANKTOK	0
#define	USERTOK 1
#define	JOBTOK	2
#define	FILETOK	3
#define	TOTALTOK 4
#define	NTOK	5
#endif	/* OSF1 */

  string tok[NTOK];
  int count=0;

#ifdef	OSF1
  int length;
  length = strlen(line);
  if (line[length-3] == ':')
	return(False);
#endif	/* OSF1 */

  /* handle the case of "(standard input)" as a filename */
  string_sub(line,"standard input","STDIN");
  string_sub(line,"(","\"");
  string_sub(line,")","\"");
  
  for (count=0; count<NTOK && next_token(&line,tok[count],NULL); count++) ;

  /* we must get NTOK tokens */
  if (count < NTOK)
    return(False);

  /* the Job and Total columns must be integer */
  if (!isdigit(*tok[JOBTOK]) || !isdigit(*tok[TOTALTOK])) return(False);

  /* if the fname contains a space then use STDIN */
  if (strchr(tok[FILETOK],' '))
    strcpy(tok[FILETOK],"STDIN");

  /* only take the last part of the filename */
  {
    string tmp;
    char *p = strrchr(tok[FILETOK],'/');
    if (p)
      {
	strcpy(tmp,p+1);
	strcpy(tok[FILETOK],tmp);
      }
  }
	

  buf->job = atoi(tok[JOBTOK]);
  buf->size = atoi(tok[TOTALTOK]);
  buf->status = strequal(tok[RANKTOK],"active")?LPQ_PRINTING:LPQ_QUEUED;
  buf->time = time(NULL);
  StrnCpy(buf->user,tok[USERTOK],sizeof(buf->user)-1);
  StrnCpy(buf->file,tok[FILETOK],sizeof(buf->file)-1);
#ifdef PRIOTOK
  buf->priority = atoi(tok[PRIOTOK]);
#else
  buf->priority = 1;
#endif
  return(True);
}

/*
<magnus@hum.auc.dk>
LPRng_time modifies the current date by inserting the hour and minute from
the lpq output.  The lpq time looks like "23:15:07"
*/
static time_t LPRng_time(string tok[],int pos)
{
  time_t jobtime;
  struct tm *t;
  char tmp_time[9];

  jobtime = time(NULL);         /* default case: take current time */
  t = localtime(&jobtime);
  t->tm_hour = atoi(tok[pos]);
  StrnCpy(tmp_time,tok[pos],sizeof(tmp_time));
  t->tm_min = atoi(tmp_time+3);
  t->tm_sec = atoi(tmp_time+6);
  jobtime = mktime(t);

  return jobtime;
}


/****************************************************************************
  parse a lpq line
  <magnus@hum.auc.dk>
  Most of the code is directly reused from parse_lpq_bsd()

here are two examples of lpq output under lprng (LPRng-2.3.0)

Printer: humprn@hum-fak
  Queue: 1 printable job
  Server: pid 4840 active, Unspooler: pid 4841 active
  Status: job 'cfA659hum-fak', closing device at Fri Jun 21 10:10:21 1996
 Rank  Owner           Class Job Files                           Size Time
active magnus@hum-fak      A 659 /var/spool/smb/Notesblok-ikke-na4024 10:03:31
 
Printer: humprn@hum-fak (printing disabled)
  Queue: 1 printable job
  Warning: no server present
  Status: finished operations at Fri Jun 21 10:10:32 1996
 Rank  Owner           Class Job Files                           Size Time
1      magnus@hum-fak      A 387 /var/spool/smb/netbudget.xls    21230 10:50:53
 
****************************************************************************/
static BOOL parse_lpq_lprng(char *line,print_queue_struct *buf,BOOL first)
{
#define        LPRNG_RANKTOK   0
#define        LPRNG_USERTOK 1
#define        LPRNG_PRIOTOK 2
#define        LPRNG_JOBTOK    3
#define        LPRNG_FILETOK   4
#define        LPRNG_TOTALTOK 5
#define LPRNG_TIMETOK 6
#define        LPRNG_NTOK      7

/****************************************************************************
From lpd_status.c in LPRng source.
0        1         2         3         4         5         6         7
12345678901234567890123456789012345678901234567890123456789012345678901234 
" Rank  Owner           Class Job Files                           Size Time"
                        plp_snprintf( msg, sizeof(msg), "%-6s %-19s %c %03d %-32s",
                                number, line, priority, cfp->number, error );
                                plp_snprintf( msg + len, sizeof(msg)-len, "%4d",
                                        cfp->jobsize );
                                plp_snprintf( msg+len, sizeof(msg)-len, " %s",
                                        Time_str( 1, cfp->statb.st_ctime ) );
****************************************************************************/
  /* The following define's are to be able to adjust the values if the
LPRng source changes.  This is from version 2.3.0.  Magnus  */
#define SPACE_W 1
#define RANK_W 6
#define OWNER_W 19
#define CLASS_W 1
#define JOB_W 3
#define FILE_W 32
/* The JOBSIZE_W is too small for big jobs, so time is pushed to the right */
#define JOBSIZE_W 4
 
#define RANK_POS 0
#define OWNER_POS RANK_POS+RANK_W+SPACE_W
#define CLASS_POS OWNER_POS+OWNER_W+SPACE_W
#define JOB_POS CLASS_POS+CLASS_W+SPACE_W
#define FILE_POS JOB_POS+JOB_W+SPACE_W
#define JOBSIZE_POS FILE_POS+FILE_W

  
  string tok[LPRNG_NTOK];
  int count=0;

/* 
Need to insert one space in front of the size, to be able to use
next_token() unchanged.  I would have liked to be able to insert a
space instead, to prevent losing that one char, but perl has spoiled
me :-\  So I did it the easiest way.

HINT: Use as short a path as possible for the samba spool directory.
A long spool-path will just waste significant chars of the file name.
*/

  line[JOBSIZE_POS-1]=' ';

  /* handle the case of "(stdin)" as a filename */
  string_sub(line,"stdin","STDIN");
  string_sub(line,"(","\"");
  string_sub(line,")","\"");
  
  for (count=0; count<LPRNG_NTOK && next_token(&line,tok[count],NULL); count++) ;

  /* we must get LPRNG_NTOK tokens */
  if (count < LPRNG_NTOK)
    return(False);

  /* the Job and Total columns must be integer */
  if (!isdigit(*tok[LPRNG_JOBTOK]) || !isdigit(*tok[LPRNG_TOTALTOK])) return(False);

  /* if the fname contains a space then use STDIN */
  /* I do not understand how this would be possible. Magnus. */
  if (strchr(tok[LPRNG_FILETOK],' '))
    strcpy(tok[LPRNG_FILETOK],"STDIN");

  /* only take the last part of the filename */
  {
    string tmp;
    char *p = strrchr(tok[LPRNG_FILETOK],'/');
    if (p)
      {
       strcpy(tmp,p+1);
       strcpy(tok[LPRNG_FILETOK],tmp);
      }
  }
       

  buf->job = atoi(tok[LPRNG_JOBTOK]);
  buf->size = atoi(tok[LPRNG_TOTALTOK]);
  buf->status = strequal(tok[LPRNG_RANKTOK],"active")?LPQ_PRINTING:LPQ_QUEUED;
  /*  buf->time = time(NULL); */
  buf->time = LPRng_time(tok,LPRNG_TIMETOK);
DEBUG(3,("Time reported for job %d is %s", buf->job, ctime(&buf->time)));
  StrnCpy(buf->user,tok[LPRNG_USERTOK],sizeof(buf->user)-1);
  StrnCpy(buf->file,tok[LPRNG_FILETOK],sizeof(buf->file)-1);
#ifdef LPRNG_PRIOTOK
  /* Here I try to map the CLASS char to a number, but the number
     is never shown in Print Manager under NT anyway... Magnus. */
  buf->priority = atoi(tok[LPRNG_PRIOTOK-('A'-1)]);
#else
  buf->priority = 1;
#endif
  return(True);
}



/*******************************************************************
parse lpq on an aix system

Queue   Dev   Status    Job Files              User         PP %   Blks  Cp Rnk
------- ----- --------- --- ------------------ ---------- ---- -- ----- --- ---
lazer   lazer READY
lazer   lazer RUNNING   537 6297doc.A          kvintus@IE    0 10  2445   1   1
              QUEUED    538 C.ps               root@IEDVB           124   1   2
              QUEUED    539 E.ps               root@IEDVB            28   1   3
              QUEUED    540 L.ps               root@IEDVB           172   1   4
              QUEUED    541 P.ps               root@IEDVB            22   1   5
********************************************************************/
static BOOL parse_lpq_aix(char *line,print_queue_struct *buf,BOOL first)
{
  string tok[11];
  int count=0;

  /* handle the case of "(standard input)" as a filename */
  string_sub(line,"standard input","STDIN");
  string_sub(line,"(","\"");
  string_sub(line,")","\"");

  for (count=0; count<10 && next_token(&line,tok[count],NULL); count++) ;

  /* we must get 6 tokens */
  if (count < 10)
  {
      if ((count == 7) && (strcmp(tok[0],"QUEUED") == 0))
      {
          /* the 2nd and 5th columns must be integer */
          if (!isdigit(*tok[1]) || !isdigit(*tok[4])) return(False);
          buf->size = atoi(tok[4]) * 1024;
          /* if the fname contains a space then use STDIN */
          if (strchr(tok[2],' '))
            strcpy(tok[2],"STDIN");

          /* only take the last part of the filename */
          {
            string tmp;
            char *p = strrchr(tok[2],'/');
            if (p)
              {
                strcpy(tmp,p+1);
                strcpy(tok[2],tmp);
              }
          }


          buf->job = atoi(tok[1]);
          buf->status = LPQ_QUEUED;
	  buf->priority = 0;
          buf->time = time(NULL);
          StrnCpy(buf->user,tok[3],sizeof(buf->user)-1);
          StrnCpy(buf->file,tok[2],sizeof(buf->file)-1);
      }
      else
      {
          DEBUG(6,("parse_lpq_aix count=%d\n", count));
          return(False);
      }
  }
  else
  {
      /* the 4th and 9th columns must be integer */
      if (!isdigit(*tok[3]) || !isdigit(*tok[8])) return(False);
      buf->size = atoi(tok[8]) * 1024;
      /* if the fname contains a space then use STDIN */
      if (strchr(tok[4],' '))
        strcpy(tok[4],"STDIN");

      /* only take the last part of the filename */
      {
        string tmp;
        char *p = strrchr(tok[4],'/');
        if (p)
          {
            strcpy(tmp,p+1);
            strcpy(tok[4],tmp);
          }
      }


      buf->job = atoi(tok[3]);
      buf->status = strequal(tok[2],"RUNNING")?LPQ_PRINTING:LPQ_QUEUED;
      buf->priority = 0;
      buf->time = time(NULL);
      StrnCpy(buf->user,tok[5],sizeof(buf->user)-1);
      StrnCpy(buf->file,tok[4],sizeof(buf->file)-1);
  }


  return(True);
}


/****************************************************************************
parse a lpq line
here is an example of lpq output under hpux; note there's no space after -o !
$> lpstat -oljplus
ljplus-2153         user           priority 0  Jan 19 08:14 on ljplus
      util.c                                  125697 bytes
      server.c				      110712 bytes
ljplus-2154         user           priority 0  Jan 19 08:14 from client
      (standard input)                          7551 bytes
****************************************************************************/
static BOOL parse_lpq_hpux(char * line, print_queue_struct *buf, BOOL first)
{
  /* must read two lines to process, therefore keep some values static */
  static BOOL header_line_ok=False, base_prio_reset=False;
  static string jobuser;
  static int jobid;
  static int jobprio;
  static time_t jobtime;
  static int jobstat=LPQ_QUEUED;
  /* to store minimum priority to print, lpstat command should be invoked
     with -p option first, to work */
  static int base_prio;
 
  int count;
  char TAB = '\011';  
  string tok[12];

  /* If a line begins with a horizontal TAB, it is a subline type */
  
  if (line[0] == TAB) { /* subline */
    /* check if it contains the base priority */
    if (!strncmp(line,"\tfence priority : ",18)) {
       base_prio=atoi(&line[18]);
       DEBUG(4, ("fence priority set at %d\n", base_prio));
    }
    if (!header_line_ok) return (False); /* incorrect header line */
    /* handle the case of "(standard input)" as a filename */
    string_sub(line,"standard input","STDIN");
    string_sub(line,"(","\"");
    string_sub(line,")","\"");
    
    for (count=0; count<2 && next_token(&line,tok[count],NULL); count++) ;
    /* we must get 2 tokens */
    if (count < 2) return(False);
    
    /* the 2nd column must be integer */
    if (!isdigit(*tok[1])) return(False);
    
    /* if the fname contains a space then use STDIN */
    if (strchr(tok[0],' '))
      strcpy(tok[0],"STDIN");
    
    buf->size = atoi(tok[1]);
    StrnCpy(buf->file,tok[0],sizeof(buf->file)-1);
    
    /* fill things from header line */
    buf->time = jobtime;
    buf->job = jobid;
    buf->status = jobstat;
    buf->priority = jobprio;
    StrnCpy(buf->user,jobuser,sizeof(buf->user)-1);
    
    return(True);
  }
  else { /* header line */
    header_line_ok=False; /* reset it */
    if (first) {
       if (!base_prio_reset) {
	  base_prio=0; /* reset it */
	  base_prio_reset=True;
       }
    }
    else if (base_prio) base_prio_reset=False;
    
    /* handle the dash in the job id */
    string_sub(line,"-"," ");
    
    for (count=0; count<12 && next_token(&line,tok[count],NULL); count++) ;
      
    /* we must get 8 tokens */
    if (count < 8) return(False);
    
    /* first token must be printer name (cannot check ?) */
    /* the 2nd, 5th & 7th column must be integer */
    if (!isdigit(*tok[1]) || !isdigit(*tok[4]) || !isdigit(*tok[6])) return(False);
    jobid = atoi(tok[1]);
    StrnCpy(jobuser,tok[2],sizeof(buf->user)-1);
    jobprio = atoi(tok[4]);
    
    /* process time */
    jobtime=EntryTime(tok, 5, count, 8);
    if (jobprio < base_prio) {
       jobstat = LPQ_PAUSED;
       DEBUG (4, ("job %d is paused: prio %d < %d; jobstat=%d\n", jobid, jobprio, base_prio, jobstat));
    }
    else {
       jobstat = LPQ_QUEUED;
       if ((count >8) && (((strequal(tok[8],"on")) ||
			   ((strequal(tok[8],"from")) && 
			    ((count > 10)&&(strequal(tok[10],"on")))))))
	 jobstat = LPQ_PRINTING;
    }
    
    header_line_ok=True; /* information is correct */
    return(False); /* need subline info to include into queuelist */
  }
}


/****************************************************************************
parse a lpq line

here is an example of "lpstat -o dcslw" output under sysv

dcslw-896               tridge            4712   Dec 20 10:30:30 on dcslw
dcslw-897               tridge            4712   Dec 20 10:30:30 being held

****************************************************************************/
static BOOL parse_lpq_sysv(char *line,print_queue_struct *buf,BOOL first)
{
  string tok[9];
  int count=0;
  char *p;

  /* handle the dash in the job id */
  string_sub(line,"-"," ");
  
  for (count=0; count<9 && next_token(&line,tok[count],NULL); count++) ;

  /* we must get 7 tokens */
  if (count < 7)
    return(False);

  /* the 2nd and 4th, 6th columns must be integer */
  if (!isdigit(*tok[1]) || !isdigit(*tok[3])) return(False);
  if (!isdigit(*tok[5])) return(False);

  /* if the user contains a ! then trim the first part of it */  
  if ((p=strchr(tok[2],'!')))
    {
      string tmp;
      strcpy(tmp,p+1);
      strcpy(tok[2],tmp);
    }
    

  buf->job = atoi(tok[1]);
  buf->size = atoi(tok[3]);
  if (count > 7 && strequal(tok[7],"on"))
    buf->status = LPQ_PRINTING;
  else if (count > 8 && strequal(tok[7],"being") && strequal(tok[8],"held"))
    buf->status = LPQ_PAUSED;
  else
    buf->status = LPQ_QUEUED;
  buf->priority = 0;
  buf->time = EntryTime(tok, 4, count, 7);
  StrnCpy(buf->user,tok[2],sizeof(buf->user)-1);
  StrnCpy(buf->file,tok[2],sizeof(buf->file)-1);
  return(True);
}

/****************************************************************************
parse a lpq line

here is an example of lpq output under qnx
Spooler: /qnx/spooler, on node 1
Printer: txt        (ready) 
0000:     root	[job #1    ]   active 1146 bytes	/etc/profile
0001:     root	[job #2    ]    ready 2378 bytes	/etc/install
0002:     root	[job #3    ]    ready 1146 bytes	-- standard input --
****************************************************************************/
static BOOL parse_lpq_qnx(char *line,print_queue_struct *buf,BOOL first)
{
  string tok[7];
  int count=0;

  DEBUG(0,("antes [%s]\n", line));

  /* handle the case of "-- standard input --" as a filename */
  string_sub(line,"standard input","STDIN");
  DEBUG(0,("despues [%s]\n", line));
  string_sub(line,"-- ","\"");
  string_sub(line," --","\"");
  DEBUG(0,("despues 1 [%s]\n", line));

  string_sub(line,"[job #","");
  string_sub(line,"]","");
  DEBUG(0,("despues 2 [%s]\n", line));

  
  
  for (count=0; count<7 && next_token(&line,tok[count],NULL); count++) ;

  /* we must get 7 tokens */
  if (count < 7)
    return(False);

  /* the 3rd and 5th columns must be integer */
  if (!isdigit(*tok[2]) || !isdigit(*tok[4])) return(False);

  /* only take the last part of the filename */
  {
    string tmp;
    char *p = strrchr(tok[6],'/');
    if (p)
      {
	strcpy(tmp,p+1);
	strcpy(tok[6],tmp);
      }
  }
	

  buf->job = atoi(tok[2]);
  buf->size = atoi(tok[4]);
  buf->status = strequal(tok[3],"active")?LPQ_PRINTING:LPQ_QUEUED;
  buf->priority = 0;
  buf->time = time(NULL);
  StrnCpy(buf->user,tok[1],sizeof(buf->user)-1);
  StrnCpy(buf->file,tok[6],sizeof(buf->file)-1);
  return(True);
}


/****************************************************************************
  parse a lpq line for the plp printing system
  Bertrand Wallrich <Bertrand.Wallrich@loria.fr>

redone by tridge. Here is a sample queue:

Local  Printer 'lp2' (fjall):
  Printing (started at Jun 15 13:33:58, attempt 1).
    Rank Owner       Pr Opt  Job Host        Files           Size     Date
  active tridge      X  -    6   fjall       /etc/hosts      739      Jun 15 13:33
     3rd tridge      X  -    7   fjall       /etc/hosts      739      Jun 15 13:33

****************************************************************************/
static BOOL parse_lpq_plp(char *line,print_queue_struct *buf,BOOL first)
{
  string tok[11];
  int count=0;

  /* handle the case of "(standard input)" as a filename */
  string_sub(line,"stdin","STDIN");
  string_sub(line,"(","\"");
  string_sub(line,")","\"");
  
  for (count=0; count<11 && next_token(&line,tok[count],NULL); count++) ;

  /* we must get 11 tokens */
  if (count < 11)
    return(False);

  /* the first must be "active" or begin with an integer */
  if (strcmp(tok[0],"active") && !isdigit(tok[0][0]))
    return(False);

  /* the 5th and 8th must be integer */
  if (!isdigit(*tok[4]) || !isdigit(*tok[7])) 
    return(False);

  /* if the fname contains a space then use STDIN */
  if (strchr(tok[6],' '))
    strcpy(tok[6],"STDIN");

  /* only take the last part of the filename */
  {
    string tmp;
    char *p = strrchr(tok[6],'/');
    if (p)
      {
        strcpy(tmp,p+1);
        strcpy(tok[6],tmp);
      }
  }


  buf->job = atoi(tok[4]);

  buf->size = atoi(tok[7]);
  if (strchr(tok[7],'K'))
    buf->size *= 1024;
  if (strchr(tok[7],'M'))
    buf->size *= 1024*1024;

  buf->status = strequal(tok[0],"active")?LPQ_PRINTING:LPQ_QUEUED;
  buf->priority = 0;
  buf->time = time(NULL);
  StrnCpy(buf->user,tok[1],sizeof(buf->user)-1);
  StrnCpy(buf->file,tok[6],sizeof(buf->file)-1);
  return(True);
}



char *stat0_strings[] = { "enabled", "online", "idle", "no entries", "free", "ready", NULL };
char *stat1_strings[] = { "offline", "disabled", "down", "off", "waiting", "no daemon", NULL };
char *stat2_strings[] = { "jam", "paper", "error", "responding", "not accepting", "not running", "turned off", NULL };

/****************************************************************************
parse a lpq line. Choose printing style
****************************************************************************/
static BOOL parse_lpq_entry(int snum,char *line,
			    print_queue_struct *buf,
			    print_status_struct *status,BOOL first)
{
  BOOL ret;

  switch (lp_printing())
    {
    case PRINT_SYSV:
      ret = parse_lpq_sysv(line,buf,first);
      break;
    case PRINT_AIX:      
      ret = parse_lpq_aix(line,buf,first);
      break;
    case PRINT_HPUX:
      ret = parse_lpq_hpux(line,buf,first);
      break;
    case PRINT_QNX:
      ret = parse_lpq_qnx(line,buf,first);
      break;
    case PRINT_LPRNG:
      ret = parse_lpq_lprng(line,buf,first);
      break;
    case PRINT_PLP:
      ret = parse_lpq_plp(line,buf,first);
      break;
    default:
      ret = parse_lpq_bsd(line,buf,first);
      break;
    }

#ifdef LPQ_GUEST_TO_USER
  if (ret) {
    extern pstring sesssetup_user;
    /* change guest entries to the current logged in user to make
       them appear deletable to windows */
    if (sesssetup_user[0] && strequal(buf->user,lp_guestaccount(snum)))
      strcpy(buf->user,sesssetup_user);
  }
#endif

  /* We don't want the newline in the status message. */
  {
    char *p = strchr(line,'\n');
    if (p) *p = 0;
  }

  if (status && !ret)
    {
      /* a few simple checks to see if the line might be a
         printer status line: 
	 handle them so that most severe condition is shown */
      int i;
      strlower(line);
      
      switch (status->status) {
      case LPSTAT_OK:
	for (i=0; stat0_strings[i]; i++)
	  if (strstr(line,stat0_strings[i])) {
	    StrnCpy(status->message,line,sizeof(status->message)-1);
	    status->status=LPSTAT_OK;
	  }
      case LPSTAT_STOPPED:
	for (i=0; stat1_strings[i]; i++)
	  if (strstr(line,stat1_strings[i])) {
	    StrnCpy(status->message,line,sizeof(status->message)-1);
	    status->status=LPSTAT_STOPPED;
	  }
      case LPSTAT_ERROR:
	for (i=0; stat2_strings[i]; i++)
	  if (strstr(line,stat2_strings[i])) {
	    StrnCpy(status->message,line,sizeof(status->message)-1);
	    status->status=LPSTAT_ERROR;
	  }
	break;
      }
    }

  return(ret);
}

/****************************************************************************
get a printer queue
****************************************************************************/
int get_printqueue(int snum,int cnum,print_queue_struct **queue,
		   print_status_struct *status)
{
  char *lpq_command = lp_lpqcommand(snum);
  char *printername = PRINTERNAME(snum);
  int ret=0,count=0;
  pstring syscmd;
  fstring outfile;
  pstring line;
  FILE *f;
  struct stat sbuf;
  BOOL dorun=True;
  int cachetime = lp_lpqcachetime();
  int lfd = -1;

  *line = 0;
  check_lpq_cache(snum);
  
  if (!printername || !*printername)
    {
      DEBUG(6,("replacing printer name with service (snum=(%s,%d))\n",
	    lp_servicename(snum),snum));
      printername = lp_servicename(snum);
    }
    
  if (!lpq_command || !(*lpq_command))
    {
      DEBUG(5,("No lpq command\n"));
      return(0);
    }
    
  strcpy(syscmd,lpq_command);
  string_sub(syscmd,"%p",printername);

  standard_sub(cnum,syscmd);

  sprintf(outfile,"/tmp/lpq.%08x",str_checksum(syscmd));
  
  if (!lpq_cache_reset[snum] && cachetime && !stat(outfile,&sbuf)) 
    {
      if (time(NULL) - sbuf.st_mtime < cachetime) {
	DEBUG(3,("Using cached lpq output\n"));
	dorun = False;
      }

      if (dorun) {
	lfd = file_lock(outfile,LPQ_LOCK_TIMEOUT);
	if (lfd<0 || 
	    (!fstat(lfd,&sbuf) && (time(NULL) - sbuf.st_mtime)<cachetime)) {
	  DEBUG(3,("Using cached lpq output\n"));
	  dorun = False;
	  file_unlock(lfd); lfd = -1;
	}
      }
    }

  if (dorun) {
    ret = smbrun(syscmd,outfile);
    DEBUG(3,("Running the command `%s' gave %d\n",syscmd,ret));
  }

  lpq_cache_reset[snum] = False;

  f = fopen(outfile,"r");
  if (!f) {
    if (lfd >= 0) file_unlock(lfd);
    return(0);
  }

  if (status) {
    strcpy(status->message,"");
    status->status = LPSTAT_OK;
  }
      
  while (fgets(line,sizeof(pstring),f))
    {
      DEBUG(6,("QUEUE2: %s\n",line));

      *queue = Realloc(*queue,sizeof(print_queue_struct)*(count+1));
      if (! *queue)
	{
	  count = 0;
	  break;
	}

      bzero((char *)&(*queue)[count],sizeof(**queue));
	  
      /* parse it */
      if (!parse_lpq_entry(snum,line,&(*queue)[count],status,count==0))
	continue;
	  
      count++;
    }	      

  fclose(f);

  if (lfd >= 0) file_unlock(lfd);

  if (!cachetime) 
    unlink(outfile);
  else
    chmod(outfile,0666);
  return(count);
}


/****************************************************************************
delete a printer queue entry
****************************************************************************/
void del_printqueue(int cnum,int snum,int jobid)
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
    
  sprintf(jobstr,"%d",jobid);

  strcpy(syscmd,lprm_command);
  string_sub(syscmd,"%p",printername);
  string_sub(syscmd,"%j",jobstr);
  standard_sub(cnum,syscmd);

  ret = smbrun(syscmd,NULL);
  DEBUG(3,("Running the command `%s' gave %d\n",syscmd,ret));  
  lpq_reset(snum); /* queue has changed */
}

/****************************************************************************
change status of a printer queue entry
****************************************************************************/
void status_printjob(int cnum,int snum,int jobid,int status)
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
    
  sprintf(jobstr,"%d",jobid);

  strcpy(syscmd,lpstatus_command);
  string_sub(syscmd,"%p",printername);
  string_sub(syscmd,"%j",jobstr);
  standard_sub(cnum,syscmd);

  ret = smbrun(syscmd,NULL);
  DEBUG(3,("Running the command `%s' gave %d\n",syscmd,ret));  
  lpq_reset(snum); /* queue has changed */
}


