/* Copyright (C) 1995-1998 Samba-Team */
/* Copyright (C) 1998 John H Terpstra <jht@aquasoft.com.au> */

/* local definitions for file server */
#ifndef _LOCAL_H
#define _LOCAL_H

/* The default workgroup - usually overridden in smb.conf */
#ifndef DEFAULT_WORKGROUP
#define DEFAULT_WORKGROUP "WORKGROUP"
#endif

/* the maximum debug level to compile into the code. This assumes a good 
   optimising compiler that can remove unused code 
   for embedded or low-memory systems set this to a value like 2 to get
   only important messages. This gives *much* smaller binaries
*/
#ifndef MAX_DEBUG_LEVEL
#define MAX_DEBUG_LEVEL 1000
#endif

/* This defines the section name in the configuration file that will contain */
/* global parameters - that is, parameters relating to the whole server, not */
/* just services. This name is then reserved, and may not be used as a       */
/* a service name. It will default to "global" if not defined here.          */
#define GLOBAL_NAME "global"
#define GLOBAL_NAME2 "globals"

/* define what facility to use for syslog */
#ifndef SYSLOG_FACILITY
#define SYSLOG_FACILITY LOG_DAEMON
#endif

/* separators for lists */
#define LIST_SEP " \t,\n\r"

/* what default type of filesystem do we want this to show up as in a
   NT file manager window? */
#define FSTYPE_STRING "NTFS"

/* user to test password server with as invalid in security=server mode. */
#ifndef INVALID_USER_PREFIX
#define INVALID_USER_PREFIX "sambatest"
#endif

/* the default pager to use for the client "more" command. Users can
   override this with the PAGER environment variable */
#ifndef PAGER
#define PAGER "more"
#endif

/*
 * Default passwd chat script.
 */
#define DEFAULT_PASSWD_CHAT "*new*password* %n\\n *new*password* %n\\n *changed*"

/* Max number of jobs per print queue. */
#define PRINT_MAX_JOBID 10000

#endif
