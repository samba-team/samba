/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <popper.h>
RCSID("$Id$");

static
int
krb_authenticate(POP *p, struct sockaddr_in *addr)
{

#ifdef KERBEROS
    Key_schedule schedule;
    KTEXT_ST ticket;
    char instance[INST_SZ];  
    char version[9];
    int auth;
  
    strcpy(instance, "*");
    auth = krb_recvauth(0L, 0, &ticket, "pop", instance,
                        addr, (struct sockaddr_in *) NULL,
                        &p->kdata, "", schedule, version);
    
    if (auth != KSUCCESS) {
        pop_msg(p, POP_FAILURE, "Kerberos authentication failure: %s", 
                krb_get_err_text(auth));
        pop_log(p, POP_FAILURE, "%s: (%s.%s@%s) %s", p->client, 
                p->kdata.pname, p->kdata.pinst, p->kdata.prealm,
		krb_get_err_text(auth));
        exit (1);
    }

#ifdef DEBUG
    pop_log(p, POP_DEBUG, "%s.%s@%s (%s): ok", p->kdata.pname, 
            p->kdata.pinst, p->kdata.prealm, inet_ntoa(addr->sin_addr));
#endif /* DEBUG */

#endif /* KERBEROS */

    return(POP_SUCCESS);
}

static
int
plain_authenticate (POP *p, struct sockaddr_in *addr)
{
    return(POP_SUCCESS);
}

/* 
 *  init:   Start a Post Office Protocol session
 */

int
pop_init(POP *p,int argcount,char **argmessage)
{

    struct sockaddr_in      cs;                 /*  Communication parameters */
    struct hostent      *   ch;                 /*  Client host information */
    int                     errflag = 0;
    int                     c;
    int                     len;
    int                     options = 0;
    int                     sp = 0;             /*  Socket pointer */
    char                *   trace_file_name = "/tmp/popper-trace";
    int			    inetd = 0;

    /*  Initialize the POP parameter block */
    memset (p,0, sizeof(POP));

    /*  Save my name in a global variable */
    p->myname = argmessage[0];

    /*  Get the name of our host */
    k_gethostname(p->myhost,MaxHostNameLen);

    /*  Open the log file */
    openlog(p->myname,POP_LOGOPTS,POP_FACILITY);

    /*  Process command line arguments */
    while ((c = getopt(argcount,argmessage,
#ifdef KERBEROS
		       "k"
#endif
		       "dit:")) != EOF)
        switch (c) {

            /*  Debugging requested */
            case 'd':
                p->debug++;
                options |= SO_DEBUG;
                break;

            /*  Debugging trace file specified */
            case 't':
                p->debug++;
                if ((p->trace = fopen(optarg,"a+")) == NULL) {
                    pop_log(p,POP_PRIORITY,
                        "Unable to open trace file \"%s\", err = %d",
                            optarg,errno);
                    exit (1);
                }
                trace_file_name = optarg;
                break;

#ifdef KERBEROS
	    /* Use kerberos version of POP3 protocol */
	    case 'k':
		p->kerberosp = 1;
		break;
#endif

            /*  Timeout value passed.  Default changed */
            case 'T':
                pop_timeout = atoi(optarg);
                break;

	    /*  Fake inetd */
	    case 'i':
		inetd = 1;
		break;
            /*  Unknown option received */
            default:
                errflag++;
        }

    /*  Exit if bad options specified */
    if (errflag) {
        fprintf(stderr,
		"Usage: %s [-T timeout] [-d] [-k] [-i]\n",
		argmessage[0]);
        exit (1);
    }

    /* Fake inetd */
    if (inetd)
	mini_inetd (p->kerberosp ?
		    k_getportbyname("kpop", "tcp", htons(1109)) :
		    k_getportbyname("pop", "tcp", htons(110)));

    /*  Get the address and socket of the client to whom I am speaking */
    len = sizeof(cs);
    if (getpeername(sp,(struct sockaddr *)&cs,&len) < 0){
        pop_log(p,POP_PRIORITY,
            "Unable to obtain socket and address of client, err = %d",errno);
        exit (1);
    }

    /*  Save the dotted decimal form of the client's IP address 
        in the POP parameter block */
    strncpy (p->ipaddr, inet_ntoa(cs.sin_addr), sizeof(p->ipaddr));
    p->ipaddr[sizeof(p->ipaddr) - 1] = '\0';

    /*  Save the client's port */
    p->ipport = ntohs(cs.sin_port);

    /*  Get the canonical name of the host to whom I am speaking */
    ch = gethostbyaddr((char *) &cs.sin_addr, sizeof(cs.sin_addr), AF_INET);
    if (ch == NULL){
        pop_log(p,POP_PRIORITY,
            "Unable to get canonical name of client, err = %d",errno);
	strcpy (p->client, p->ipaddr);
    }
    /*  Save the cannonical name of the client host in 
        the POP parameter block */
    else {
        /*  Distrust distant nameservers */
        struct hostent      *   ch_again;
        char            *   *   addrp;

        /*  See if the name obtained for the client's IP 
            address returns an address */
        if ((ch_again = gethostbyname(ch->h_name)) == NULL) {
            pop_log(p,POP_PRIORITY,
                "Client at \"%s\" resolves to an unknown host name \"%s\"",
                    p->ipaddr,ch->h_name);
	    strcpy (p->client, p->ipaddr);
        }
        else {
            /*  Save the host name (the previous value was 
                destroyed by gethostbyname) */
	    strncpy (p->client, ch_again->h_name, sizeof(p->client));
	    p->client[sizeof(p->client) - 1] = '\0';

            /*  Look for the client's IP address in the list returned 
                for its name */
            for (addrp=ch_again->h_addr_list; *addrp; ++addrp)
	        if (memcmp(*addrp, &cs.sin_addr, sizeof(cs.sin_addr))
		    == 0)
		  break;

            if (!*addrp) {
                pop_log (p,POP_PRIORITY,
                    "Client address \"%s\" not listed for its host name \"%s\"",
                        p->ipaddr,ch->h_name);
		strcpy (p->client, p->ipaddr);
            }
        }
    }

    /*  Create input file stream for TCP/IP communication */
    if ((p->input = fdopen(sp,"r")) == NULL){
        pop_log(p,POP_PRIORITY,
            "Unable to open communication stream for input, err = %d",errno);
        exit (1);
    }

    /*  Create output file stream for TCP/IP communication */
    if ((p->output = fdopen(sp,"w")) == NULL){
        pop_log(p,POP_PRIORITY,
            "Unable to open communication stream for output, err = %d",errno);
        exit (1);
    }

    pop_log(p,POP_PRIORITY,
        "(v%s) Servicing request from \"%s\" at %s\n",
            VERSION,p->client,p->ipaddr);

#ifdef DEBUG
    if (p->trace)
        pop_log(p,POP_PRIORITY,
            "Tracing session and debugging information in file \"%s\"",
                trace_file_name);
    else if (p->debug)
        pop_log(p,POP_PRIORITY,"Debugging turned on");
#endif /* DEBUG */

    return((p->kerberosp ? krb_authenticate : plain_authenticate)(p, &cs));
}
