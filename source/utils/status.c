/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   status reporting
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

   Revision History:

   12 aug 96: Erik.Devriendt@te6.siemens.be
   added support for shared memory implementation of share mode locking
*/

/*
 * This program reports current SMB connections
 */

#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

struct connect_record crec;

struct session_record{
  int pid;
  int uid;
  char machine[31];
  time_t start;
  struct session_record *next;
} *srecs;

extern int DEBUGLEVEL;
extern FILE *dbf;
extern pstring myhostname;

static pstring Ucrit_username = "";                   /* added by OH */
int            Ucrit_pid[100];  /* Ugly !!! */        /* added by OH */
int            Ucrit_MaxPid=0;                        /* added by OH */
unsigned int   Ucrit_IsActive = 0;                    /* added by OH */

/* we need these because we link to locking*.o */
 void become_root(BOOL save_dir) {}
 void unbecome_root(BOOL restore_dir) {}
connection_struct Connections[MAX_CONNECTIONS];
files_struct Files[MAX_OPEN_FILES];
struct current_user current_user;


static void print_share_mode(share_mode_entry *e, char *fname)
{
	static int count;
	if (count==0) {
		printf("Locked files:\n");
		printf("Pid    DenyMode   R/W        Oplock           Name\n");
		printf("--------------------------------------------------\n");
	}
	count++;

	printf("%-5d  ",e->pid);
	switch ((e->share_mode>>4)&0xF) {
	case DENY_NONE: printf("DENY_NONE  "); break;
	case DENY_ALL:  printf("DENY_ALL   "); break;
	case DENY_DOS:  printf("DENY_DOS   "); break;
	case DENY_READ: printf("DENY_READ  "); break;
	case DENY_WRITE:printf("DENY_WRITE "); break;
	}
	switch (e->share_mode&0xF) {
	case 0: printf("RDONLY     "); break;
	case 1: printf("WRONLY     "); break;
	case 2: printf("RDWR       "); break;
	}

	if((e->op_type & 
	    (EXCLUSIVE_OPLOCK|BATCH_OPLOCK)) == 
	   (EXCLUSIVE_OPLOCK|BATCH_OPLOCK))
		printf("EXCLUSIVE+BATCH ");
	else if (e->op_type & EXCLUSIVE_OPLOCK)
		printf("EXCLUSIVE       ");
	else if (e->op_type & BATCH_OPLOCK)
		printf("BATCH           ");
	else
		printf("NONE            ");

	printf(" %s   %s",fname,asctime(LocalTime((time_t *)&e->time.tv_sec)));
}



 int main(int argc, char *argv[])
{
  FILE *f;
  pstring fname;
  int uid, c;
  static pstring servicesf = CONFIGFILE;
  extern char *optarg;
  int verbose = 0, brief =0;
  BOOL processes_only=False;
  int last_pid=0;
  struct session_record *ptr;


  TimeInit();
  setup_logging(argv[0],True);

  charset_initialise();

  DEBUGLEVEL = 0;
  dbf = fopen("/dev/null","w");

  if (getuid() != geteuid()) {
    printf("smbstatus should not be run setuid\n");
    return(1);
  }

  while ((c = getopt(argc, argv, "pds:u:b")) != EOF) {
    switch (c) {
    case 'b':
      brief = 1;
      break;
    case 'd':
      verbose = 1;
      break;
    case 'p':
      processes_only = 1;
      break;
    case 's':
      pstrcpy(servicesf, optarg);
      break;
    case 'u':                                       /* added by OH */
      Ucrit_addUsername(optarg);                    /* added by OH */
      break;
    default:
      fprintf(stderr, "Usage: %s [-d] [-p] [-s configfile] [-u username]\n", *argv); /* changed by OH */
      return (-1);
    }
  }

  get_myname(myhostname, NULL);

  if (!lp_load(servicesf,False)) {
    fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
    return (-1);
  }

  if (verbose) {
    printf("using configfile = %s\n", servicesf);
    printf("lockdir = %s\n", *lp_lockdir() ? lp_lockdir() : "NULL");
  }

  pstrcpy(fname,lp_lockdir());
  standard_sub_basic(fname);
  trim_string(fname,"","/");
  pstrcat(fname,"/STATUS..LCK");

  f = fopen(fname,"r");
  if (!f) {
    printf("Couldn't open status file %s\n",fname);
    if (!lp_status(-1))
      printf("You need to have status=yes in your smb config file\n");
    return(0);
  }
  else if (verbose) {
    printf("Opened status file %s\n", fname);
  }

  uid = getuid();

  if (!processes_only) {
    printf("\nSamba version %s\n",VERSION);

    if (brief)
    {
      printf("PID     Username  Machine                       Time logged in\n");
      printf("-------------------------------------------------------------------\n");
    }
    else
    {
      printf("Service      uid      gid      pid     machine\n");
      printf("----------------------------------------------\n");
    }
  }

  while (!feof(f))
    {
      if (fread(&crec,sizeof(crec),1,f) != 1)
	break;
      if ( crec.magic == 0x280267 && process_exists(crec.pid) 
           && Ucrit_checkUsername(uidtoname(crec.uid))                      /* added by OH */
         )
      {
        if (brief)
        {
	  ptr=srecs;
	  while (ptr!=NULL)
	  {
	    if ((ptr->pid==crec.pid)&&(strncmp(ptr->machine,crec.machine,30)==0)) 
	    {
	      if (ptr->start > crec.start)
		ptr->start=crec.start;
	      break;
	    }
	    ptr=ptr->next;
	  }
	  if (ptr==NULL)
	  {
	    ptr=(struct session_record *) malloc(sizeof(struct session_record));
	    ptr->uid=crec.uid;
	    ptr->pid=crec.pid;
	    ptr->start=crec.start;
	    strncpy(ptr->machine,crec.machine,30);
	    ptr->machine[30]='\0';
	    ptr->next=srecs;
	    srecs=ptr;
	  }
        }
        else
        {
	  Ucrit_addPid(crec.pid);                                             /* added by OH */
	  if (processes_only) {
	    if (last_pid != crec.pid)
	      printf("%d\n",crec.pid);
	    last_pid = crec.pid; /* XXXX we can still get repeats, have to
				    add a sort at some time */
	  }
	  else	  
	    printf("%-10.10s   %-8s %-8s %5d   %-8s (%s) %s",
		   crec.name,uidtoname(crec.uid),gidtoname(crec.gid),crec.pid,
		   crec.machine,crec.addr,
		   asctime(LocalTime(&crec.start)));
        }
      }
    }
  fclose(f);

  if (processes_only) exit(0);
  
  if (brief)
  {
    ptr=srecs;
    while (ptr!=NULL)
    {
      printf("%-8d%-10.10s%-30.30s%s",ptr->pid,uidtoname(ptr->uid),ptr->machine,asctime(LocalTime(&(ptr->start))));
    ptr=ptr->next;
    }
    printf("\n");
    exit(0);
  }

  printf("\n");

  locking_init(1);

  if (share_mode_forall(print_share_mode) <= 0)
    printf("No locked files\n");

  printf("\n");

  share_status(stdout);

  locking_end();

  return (0);
}

/* added by OH */
void Ucrit_addUsername(pstring username)
{
  pstrcpy(Ucrit_username, username);
  if(strlen(Ucrit_username) > 0)
    Ucrit_IsActive = 1;
}

unsigned int Ucrit_checkUsername(pstring username)
{
  if ( !Ucrit_IsActive) return 1;
  if (strcmp(Ucrit_username,username) ==0) return 1;
  return 0;
}

void Ucrit_addPid(int pid)
{
  int i;
  if ( !Ucrit_IsActive) return;
  for (i=0;i<Ucrit_MaxPid;i++)
    if( pid == Ucrit_pid[i] ) return;
  Ucrit_pid[Ucrit_MaxPid++] = pid;
}

unsigned int   Ucrit_checkPid(int pid)
{
  int i;
  if ( !Ucrit_IsActive) return 1;
  for (i=0;i<Ucrit_MaxPid;i++)
    if( pid == Ucrit_pid[i] ) return 1;
  return 0;
}

