/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   status reporting
   Copyright (C) Andrew Tridgell 1994-1995
   
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
extern int DEBUGLEVEL;
extern FILE *dbf;
extern pstring myhostname;

static pstring Ucrit_username = "";                   /* added by OH */
int            Ucrit_pid[100];  /* Ugly !!! */        /* added by OH */
int            Ucrit_MaxPid=0;                        /* added by OH */
unsigned int   Ucrit_IsActive = 0;                    /* added by OH */

 int main(int argc, char *argv[])
{
  FILE *f;
  pstring fname;
  int uid, c;
  static pstring servicesf = CONFIGFILE;
  extern char *optarg;
  int verbose = 0;
  BOOL firstopen=True;
  BOOL processes_only=False;
  int last_pid=0;
#if FAST_SHARE_MODES
  pstring shmem_file_name;
  share_mode_record *scanner_p;
  share_mode_record *prev_p;
  int bytes_free, bytes_used, bytes_overhead, bytes_total;
#else
  int n;
  void *dir;
  char *s;
#endif


  TimeInit();
  setup_logging(argv[0],True);

  charset_initialise();

  DEBUGLEVEL = 0;
  dbf = fopen("/dev/null","w");

  if (getuid() != geteuid()) {
    printf("smbstatus should not be run setuid\n");
    return(1);
  }

  while ((c = getopt(argc, argv, "pds:u:")) != EOF) {
    switch (c) {
    case 'd':
      verbose = 1;
      break;
    case 'p':
      processes_only = 1;
      break;
    case 's':
      strcpy(servicesf, optarg);
      break;
    case 'u':                                       /* added by OH */
      Ucrit_addUsername(optarg);                    /* added by OH */
      break;
    default:
      fprintf(stderr, "Usage: %s [-d] [-p] [-s configfile] [-u username]\n", *argv); /* changed by OH */
      return (-1);
    }
  }

  if (!lp_load(servicesf,False)) {
    fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
    return (-1);
  }

  get_myname(myhostname, NULL);

  if (verbose) {
    printf("using configfile = %s\n", servicesf);
    printf("lockdir = %s\n", *lp_lockdir() ? lp_lockdir() : "NULL");
  }

  strcpy(fname,lp_lockdir());
  standard_sub_basic(fname);
  trim_string(fname,"","/");
  strcat(fname,"/STATUS..LCK");

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

    printf("Service      uid      gid      pid     machine\n");
    printf("----------------------------------------------\n");
  }

  while (!feof(f))
    {
      if (fread(&crec,sizeof(crec),1,f) != 1)
	break;
      if ( crec.magic == 0x280267 && process_exists(crec.pid) 
           && Ucrit_checkUsername(uidtoname(crec.uid))                      /* added by OH */
         )
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
  fclose(f);

  if (processes_only) exit(0);

  printf("\n");

#if FAST_SHARE_MODES
  /*******************************************************************
  initialize the shared memory for share_mode management 
  ******************************************************************/

   
  strcpy(shmem_file_name,lp_lockdir());
  trim_string(shmem_file_name,"","/");
  if (!*shmem_file_name) exit(-1);
  strcat(shmem_file_name, "/SHARE_MEM_FILE");
  if(!shm_open(shmem_file_name, SHMEM_SIZE)) exit(-1);
  
  if(!shm_lock())
  {
     shm_close();
     exit (-1);
  }

  scanner_p = (share_mode_record *)shm_offset2addr(shm_get_userdef_off());
  prev_p = scanner_p;
  while(scanner_p)
  {
     int pid,mode;
     time_t t;
     
     pid = scanner_p->pid;
     
     if ( !Ucrit_checkPid(pid) )
     {
	prev_p = scanner_p ;
	scanner_p = (share_mode_record *)shm_offset2addr(scanner_p->next_offset);
	continue;
     }
     
     if( (scanner_p->locking_version != LOCKING_VERSION) || !process_exists(pid))
     {
	DEBUG(2,("Deleting stale share mode record"));
	if(prev_p == scanner_p)
	{
	   shm_set_userdef_off(scanner_p->next_offset);
	   shm_free(shm_addr2offset(scanner_p));
           scanner_p = (share_mode_record *)shm_offset2addr(shm_get_userdef_off());
           prev_p = scanner_p;
	}
	else
	{
	   prev_p->next_offset = scanner_p->next_offset;
  	   shm_free(shm_addr2offset(scanner_p));
           scanner_p = (share_mode_record *)shm_offset2addr(prev_p->next_offset);
	}
	continue;
     }
     t = scanner_p->time;
     mode = scanner_p->share_mode;
     strcpy(fname, scanner_p->file_name);
#else
     dir = opendir(lp_lockdir());
     if (!dir) return(0);
     while ((s=readdirname(dir))) {
       char buf[16];
       int pid,mode;
       time_t t;
       int fd;
       pstring lname;
       int dev,inode;
       
       if (sscanf(s,"share.%d.%d",&dev,&inode)!=2) continue;
       
       strcpy(lname,lp_lockdir());
       trim_string(lname,NULL,"/");
       strcat(lname,"/");
       strcat(lname,s);
       
       fd = open(lname,O_RDONLY,0);
       if (fd < 0) continue;
       if (read(fd,buf,16) != 16) continue;
       n = read(fd,fname,sizeof(fname));
       fname[MAX(n,0)]=0;
       close(fd);
       
       t = IVAL(buf,0);
       mode = IVAL(buf,4);
       pid = IVAL(buf,8);
       
       if ( !Ucrit_checkPid(pid) )             /* added by OH */
	 continue;
       
       if (IVAL(buf,12) != LOCKING_VERSION || !process_exists(pid)) {
	 if (unlink(lname)==0)
	   printf("Deleted stale share file %s\n",s);
	 continue;
       }
#endif

    fname[sizeof(fname)-1] = 0;

    if (firstopen) {
      firstopen=False;
      printf("Locked files:\n");
      printf("Pid    DenyMode   R/W     Name\n");
      printf("------------------------------\n");
    }


    printf("%-5d  ",pid);
    switch ((mode>>4)&0xF)
      {
      case DENY_NONE: printf("DENY_NONE  "); break;
      case DENY_ALL:  printf("DENY_ALL   "); break;
      case DENY_DOS:  printf("DENY_DOS   "); break;
      case DENY_READ: printf("DENY_READ  "); break;
      case DENY_WRITE:printf("DENY_WRITE "); break;
      }
    switch (mode&0xF) 
      {
      case 0: printf("RDONLY "); break;
      case 1: printf("WRONLY "); break;
      case 2: printf("RDWR   "); break;
      }
    printf(" %s   %s",fname,asctime(LocalTime(&t)));

#if FAST_SHARE_MODES
     prev_p = scanner_p ;
     scanner_p = (share_mode_record *)shm_offset2addr(scanner_p->next_offset);
  } /* end while */

  shm_get_usage(&bytes_free, &bytes_used, &bytes_overhead);
  bytes_total = bytes_free + bytes_used + bytes_overhead;
  shm_unlock();

  /*******************************************************************
  deinitialize the shared memory for share_mode management 
  ******************************************************************/
  shm_close();

#else
  } /* end while */
  closedir(dir);

#endif
  if (firstopen)
    printf("No locked files\n");
#if FAST_SHARE_MODES
  printf("\nShare mode memory usage (bytes):\n");
  printf("   %d(%d%%) free + %d(%d%%) used + %d(%d%%) overhead = %d(100%%) total\n",
	 bytes_free, (bytes_free * 100)/bytes_total,
	 bytes_used, (bytes_used * 100)/bytes_total,
	 bytes_overhead, (bytes_overhead * 100)/bytes_total,
	 bytes_total);
  
#endif

  return (0);
}

/* added by OH */
void Ucrit_addUsername(pstring username)
{
  strcpy(Ucrit_username, username);
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

