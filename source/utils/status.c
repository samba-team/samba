/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   status reporting
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

#ifndef FAST_SHARE_MODES
static char *read_share_file(int fd, char *fname, char *progname)
{
  struct stat sb;
  char *buf;
  int size;

  if(fstat(fd, &sb) != 0)
  {
    printf("%s: ERROR: read_share_file: Failed to do stat on share file %s (%s)\n",
                  progname, fname, strerror(errno));
    return 0;
  }

  if(sb.st_size == 0)
  {
     return 0;
  }

  /* Allocate space for the file */
  if((buf = (char *)malloc(sb.st_size)) == NULL)
  {
    printf("%s: read_share_file: malloc for file size %d fail !\n", 
              progname, (int)sb.st_size);
    return 0;
  }

  if(lseek(fd, 0, SEEK_SET) != 0)
  {
    printf("%s: ERROR: read_share_file: Failed to reset position to 0 \
for share file %s (%s)\n", progname, fname, strerror(errno));
    if(buf)
      free(buf);
    return 0;
  }

  if (read(fd,buf,sb.st_size) != sb.st_size)
  {
    printf("%s: ERROR: read_share_file: Failed to read share file %s (%s)\n",
               progname, fname, strerror(errno));
    if(buf)
      free(buf);
    return 0;
  }

  if (IVAL(buf,0) != LOCKING_VERSION) {
    printf("%s: ERROR: read_share_file: share file %s has incorrect \
locking version (was %d, should be %d).\n",fname, 
              progname, IVAL(buf,0), LOCKING_VERSION);
    if(buf)
      free(buf);
    return 0;
  }

  /* Sanity check for file contents */
  size = sb.st_size;
  size -= 10; /* Remove the header */

  /* Remove the filename component. */
  size -= SVAL(buf, 8);

  /* The remaining size must be a multiple of 16 - error if not. */
  if((size % 16) != 0)
  {
    printf("%s: ERROR: read_share_file: share file %s is an incorrect length.\n", 
             progname, fname);
    if(buf)
      free(buf);
    return 0;
  }

  return buf;
}
#endif /* FAST_SHARE_MODES */

 int main(int argc, char *argv[])
{
  FILE *f;
  pstring fname;
  int uid, c;
  static pstring servicesf = CONFIGFILE;
  extern char *optarg;
  int verbose = 0, brief =0;
  BOOL firstopen=True;
  BOOL processes_only=False;
  int last_pid=0;
#ifdef FAST_SHARE_MODES
  pstring shmem_file_name;
  share_mode_record *file_scanner_p;
  smb_shm_offset_t *mode_array;
  int bytes_free, bytes_used, bytes_overhead, bytes_total;
#else /* FAST_SHARE_MODES */
  void *dir;
  char *s;
#endif /* FAST_SHARE_MODES */
  int i;
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

  get_myname(myhostname, NULL);

  if (!lp_load(servicesf,False)) {
    fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
    return (-1);
  }

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

#ifdef FAST_SHARE_MODES 
  /*******************************************************************
  initialize the shared memory for share_mode management 
  ******************************************************************/
   
  strcpy(shmem_file_name,lp_lockdir());
  trim_string(shmem_file_name,"","/");
  if (!*shmem_file_name) exit(-1);
  strcat(shmem_file_name, "/SHARE_MEM_FILE");
  if(!smb_shm_open(shmem_file_name, lp_shmem_size())) exit(-1);
  
  mode_array = (smb_shm_offset_t *)smb_shm_offset2addr(smb_shm_get_userdef_off());
  if(mode_array == NULL)
  {
    printf("%s: base of shared memory hash array == 0! Exiting.\n", argv[0]);
    smb_shm_close();
    exit(-1);
  }

  for( i = 0; i < lp_shmem_hash_size(); i++)
  {
    smb_shm_lock_hash_entry(i);
    if(mode_array[i] == NULL_OFFSET)
    {
      smb_shm_unlock_hash_entry(i);
      continue;
    }
    file_scanner_p = (share_mode_record *)smb_shm_offset2addr(mode_array[i]);
    while((file_scanner_p != 0) && (file_scanner_p->num_share_mode_entries != 0))
    {
      share_mode_entry *entry_scanner_p = 
                 (share_mode_entry *)smb_shm_offset2addr(
                                       file_scanner_p->share_mode_entries);

      while(entry_scanner_p != 0)
      {
        struct timeval t;
        int pid = entry_scanner_p->pid;
        int mode = entry_scanner_p->share_mode;
     
        t.tv_sec = entry_scanner_p->time.tv_sec;
        t.tv_usec = entry_scanner_p->time.tv_usec;
        strcpy(fname, file_scanner_p->file_name);
#else /* FAST_SHARE_MODES */

     /* For slow share modes go through all the files in
        the share mode directory and read the entries in
        each.
      */

     dir = opendir(lp_lockdir());
     if (!dir) 
     {
       printf("%s: Unable to open lock directory %s.\n", argv[0], lp_lockdir());
       return(0);
     }
     while ((s=readdirname(dir))) {
       char *buf;
       char *base;
       int fd;
       pstring lname;
       uint32 dev,inode;
       
       if (sscanf(s,"share.%u.%u",&dev,&inode)!=2) continue;
       
       strcpy(lname,lp_lockdir());
       trim_string(lname,NULL,"/");
       strcat(lname,"/");
       strcat(lname,s);
       
       fd = open(lname,O_RDWR,0);
       if (fd < 0) 
       {
         printf("%s: Unable to open share file %s.\n", argv[0], lname);
         continue;
       }

       /* Lock the share mode file while we read it. */
       if(fcntl_lock(fd, F_SETLKW, 0, 1, F_WRLCK) == False)
       {
         printf("%s: Unable to lock open share file %s.\n", argv[0], lname);
         close(fd);
         continue;
       }

       if(( buf = read_share_file( fd, lname, argv[0] )) == NULL)
       {
         close(fd);
         continue;
       } 
       strcpy( fname, &buf[10]);
       close(fd);
      
       base = buf + 10 + SVAL(buf,8); 
       for( i = 0; i < IVAL(buf, 4); i++)
       {
         char *p = base + (i*16);
         struct timeval t;
         int pid = IVAL(p,12);
         int mode = IVAL(p,8);
     
         t.tv_sec = IVAL(p,0);
         t.tv_usec = IVAL(p,4);
#endif /* FAST_SHARE_MODES */

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
    printf(" %s   %s",fname,asctime(LocalTime((time_t *)&t.tv_sec)));

#ifdef FAST_SHARE_MODES

        entry_scanner_p = (share_mode_entry *)smb_shm_offset2addr(
                                    entry_scanner_p->next_share_mode_entry);
      } /* end while entry_scanner_p */
     file_scanner_p = (share_mode_record *)smb_shm_offset2addr(
                                    file_scanner_p->next_offset);
    } /* end while file_scanner_p */
    smb_shm_unlock_hash_entry(i);
  } /* end for */

  smb_shm_get_usage(&bytes_free, &bytes_used, &bytes_overhead);
  bytes_total = bytes_free + bytes_used + bytes_overhead;

  /*******************************************************************
  deinitialize the shared memory for share_mode management 
  ******************************************************************/
  smb_shm_close();

#else /* FAST_SHARE_MODES */
    } /* end for i */

    if(buf)
      free(buf);
    base = 0;
  } /* end while */
  closedir(dir);

#endif /* FAST_SHARE_MODES */
  if (firstopen)
    printf("No locked files\n");
#ifdef FAST_SHARE_MODES
  printf("\nShare mode memory usage (bytes):\n");
  printf("   %d(%d%%) free + %d(%d%%) used + %d(%d%%) overhead = %d(100%%) total\n",
	 bytes_free, (bytes_free * 100)/bytes_total,
	 bytes_used, (bytes_used * 100)/bytes_total,
	 bytes_overhead, (bytes_overhead * 100)/bytes_total,
	 bytes_total);
  
#endif /* FAST_SHARE_MODES */

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

