/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 *
 * static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
 * static char SccsId[] = "@(#)@(#)popper.h	2.2  2.2 4/2/91";
 *
 */

/*  LINTLIBRARY */

/* 
 *  Header file for the POP programs
 */

#include <syslog.h>
#include "version.h"

#ifdef KERBEROS
#include <krb.h>
#else
/* Portable file locking */
#define k_flock(fd, operation) flock((fd), (operation))
#define   K_LOCK_SH   LOCK_SH         /* Shared lock */
#define   K_LOCK_EX   LOCK_EX         /* Exclusive lock */
#define   K_LOCK_NB   LOCK_NB         /* Don't block when locking */
#define   K_LOCK_UN   LOCK_UN         /* Unlock */
#endif

#define NULLCP          ((char *) 0)
#define SPACE           32
#define TAB             9
#define TRUE            1
#define FALSE           0
#define NEWLINE         '\n'

#define MAXHOSTNAMELEN  256
#define MAXUSERNAMELEN  65
#define MAXDROPLEN      64
#define MAXLINELEN      1024
#define MAXMSGLINELEN   1024
#define MAXCMDLEN       4
#define MAXPARMCOUNT    5
#define MAXPARMLEN      10
#define ALLOC_MSGS  20
#define MAIL_COMMAND    "/usr/lib/sendmail"

#define POP_FACILITY    LOG_LOCAL0
#define POP_PRIORITY    LOG_NOTICE
#define POP_DEBUG       LOG_DEBUG
#define POP_LOGOPTS     0
#define POP_MAILDIR     "/usr/spool/mail"
#define POP_DROP        "/usr/spool/mail/.%s.pop"
	/* POP_TMPSIZE needs to be big enough to hold the string
	 * defined by POP_TMPDROP.  POP_DROP and POP_TMPDROP
	 * must be in the same filesystem.
	 */
#define POP_TMPDROP     "/usr/spool/mail/tmpXXXXXX"
#define POP_TMPSIZE	256
#define POP_TMPXMIT     "/tmp/xmitXXXXXX"
#define POP_OK          "+OK"
#define POP_ERR         "-ERR"
#define POP_SUCCESS     1
#define POP_FAILURE     0
#define POP_TERMINATE   '.'

extern int              errno;
extern int              sys_nerr;
extern char         *   sys_errlist[];
extern char         *   sys_siglist[];

#define pop_command         pop_parm[0]     /*  POP command is first token */
#define pop_subcommand      pop_parm[1]     /*  POP XTND subcommand is the 
                                                second token */

typedef enum {                              /*  POP processing states */
    auth1,                                  /*  Authorization: waiting for 
                                                USER command */
    auth2,                                  /*  Authorization: waiting for 
                                                PASS command */
    trans,                                  /*  Transaction */
    update,                                 /*  Update:  session ended, 
                                                process maildrop changes */
    halt,                                   /*  (Halt):  stop processing 
                                                and exit */
    error                                   /*  (Error): something really 
                                                bad happened */
} state;

typedef struct {                                /*  State information for 
                                                    each POP command */
    state       ValidCurrentState;              /*  The operating state of 
                                                    the command */
    char   *    command;                        /*  The POP command */
    int         min_parms;                      /*  Minimum number of parms 
                                                    for the command */
    int         max_parms;                      /*  Maximum number of parms 
                                                    for the command */
    int         (*function) ();                 /*  The function that process 
                                                    the command */
    state       result[2];                      /*  The resulting state after 
                                                    command processing */
#define success_state   result[0]               /*  State when a command 
                                                    succeeds */
} state_table;

typedef struct {                                /*  Table of extensions */
    char   *    subcommand;                     /*  The POP XTND subcommand */
    int         min_parms;                      /*  Minimum number of parms for
                                                    the subcommand */
    int         max_parms;                      /*  Maximum number of parms for
                                                    the subcommand */
    int         (*function) ();                 /*  The function that processes 
                                                    the subcommand */
} xtnd_table;

typedef struct {                                /*  Message information */
    int         number;                         /*  Message number relative to 
                                                    the beginning of list */
    long        length;                         /*  Length of message in 
                                                    bytes */
    int         lines;                          /*  Number of (null-terminated)                                                     lines in the message */
    long        offset;                         /*  Offset from beginning of 
                                                    file */
    int         del_flag;                       /*  Flag indicating if message 
                                                    is marked for deletion */
    int         retr_flag;                      /*  Flag indicating if message 
                                                    was retrieved */
} MsgInfoList;

typedef struct  {                               /*  POP parameter block */
    int                 debug;                  /*  Debugging requested */
    char            *   myname;                 /*  The name of this POP 
                                                    daemon program */
    char                myhost[MAXHOSTNAMELEN]; /*  The name of our host 
                                                    computer */
    char            *   client;                 /*  Canonical name of client 
                                                    computer */
    char            *   ipaddr;                 /*  Dotted-notation format of 
                                                    client IP address */
    unsigned short      ipport;                 /*  Client port for privileged 
                                                    operations */
    char                user[MAXUSERNAMELEN];   /*  Name of the POP user */
    state               CurrentState;           /*  The current POP operational                                                     state */
    MsgInfoList     *   mlp;                    /*  Message information list */
    int                 msg_count;              /*  Number of messages in 
                                                    the maildrop */
    int                 msgs_deleted;           /*  Number of messages flagged 
                                                    for deletion */
    int                 last_msg;               /*  Last message touched by 
                                                    the user */
    long                bytes_deleted;          /*  Number of maildrop bytes 
                                                    flagged for deletion */
    char                drop_name[MAXDROPLEN];  /*  The name of the user's 
                                                    maildrop */
    char                temp_drop[MAXDROPLEN];  /*  The name of the user's 
                                                    temporary maildrop */
    long                drop_size;              /*  Size of the maildrop in
                                                    bytes */
    FILE            *   drop;                   /*  (Temporary) mail drop */
    FILE            *   input;                  /*  Input TCP/IP communication 
                                                    stream */
    FILE            *   output;                 /*  Output TCP/IP communication                                                     stream */
    FILE            *   trace;                  /*  Debugging trace file */
    char            *   pop_parm[MAXPARMCOUNT]; /*  Parse POP parameter list */
    int                 parm_count;             /*  Number of parameters in 
                                                    parsed list */
} POP;

extern int  pop_dele();
extern int  pop_last();
extern int  pop_list();
extern int  pop_pass();
extern int  pop_quit();
extern int  pop_rset();
extern int  pop_send();
extern int  pop_stat();
extern int  pop_updt();
extern int  pop_user();
extern int  pop_xtnd();
extern int  pop_xmit();

