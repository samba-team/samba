/*
 USAGE
   sockspy desthost destservice

You install this program in /etc/inetd.conf and /etc/services

For example I have used these entries:

/etc/services:
spy		8001/tcp	spy port

/etc/inetd.conf:
spy stream tcp nowait tridge /usr/local/smb/sockspy sockspy fjall netbios-ssn

This means any connection to port 8001 will be redirected to
netbios-ssn on fjall. By playing with these parameters you can easily
spy on most of the tcp protocols. All packets traversing the link will
be captured.

NOTE: This program is totally unsupported. I haven't used it for 2
years, and don't intend to fix the obvious bugs/limitations. I will,
however, accept contributed patches - or even a total rewrite :-)
*/

#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/dir.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>

#include <signal.h>

#include <errno.h>
#include <sysexits.h>

int trans_num = 0;

#ifndef LOGIN
#define LOGIN "/tmp/spy.in"
#endif

#ifndef LOGOUT
#define LOGOUT "/tmp/spy.out"
#endif

#ifndef LOGCMD
#define LOGCMD "/tmp/spy.cmd"
#endif

FILE *cmd = NULL;
FILE *login = NULL;
FILE *logout = NULL;

#define      STREQL(a, b)        (strcmp(a, b) == 0)
#define      NIL                 (0)

char      DestHost[256];    /* Remote system to connect to         */
char      DestObj[256];     /* Remote object/service to connect to */

/* Signal handler for SIGPIPE (write on a disconnected socket) */
abort()
{
  if (cmd)
    {
      fprintf(cmd,"writing to disconnected socket!\n");
      fflush(cmd);
    }
    exit(1);
}


main(argc, argv)
int    argc;           /* # of command line arguments */
char   *argv[];        /* the command line arguments  */
{
  int      client,       /* Socket connected to client  */
  server;       /* Socket to use for server    */

  trans_num = 0;
#ifndef NOLOG
  login = fopen(LOGIN,"w");
  logout = fopen(LOGOUT,"w");
  cmd = fopen(LOGCMD,"w");
#endif

  if (cmd)
    {
      fprintf(cmd,"Started server\n");
      fflush(cmd);
    }

  /* Check usage */
  if(argc != 3)
    return;

  strcpy(DestHost,argv[1]);
  strcpy(DestObj,argv[2]);
  
  /* Time to attempt the connection */
  server = inet_conn(DestHost, DestObj);

  if( server < 0 ) {
    exit(EX_CANTCREAT);
  }

  /* Just to make the code more readable */
  client = 0;
  
  /* We will abort gracefully when the client or remote system 
     goes away */
  signal(SIGPIPE, abort);
  
  /* Now just go and move raw data between client and 
     remote system */
  dowork(client, server);
  /* ... NEVER RETURNS ... */
}

dowork(client, server)
     int    client, server;      
{
  
  /* select(2) masks for client and remote */
  int      ClientMask, ServerMask;
  
  /* Combined ClientMask and ServerMask */
  int      ReadMask;

  /* Initialize select(2) masks */
  ClientMask = 1<<client;
  ServerMask = 1<<server;
  
  ReadMask = ClientMask | ServerMask;
  
  /* Now move raw data for the rest of our life between 
     client and remote */
  for( ; ; ) {
    /* Local Variables */
    int  SelectReadMask;/* select(2) mask modifiable by select(2) */
    int  nready;        /* status return from select(2)           */
    
    do {
      /* Intialize select(2) mask everytime
	 as select(2) always modifies it */
      SelectReadMask = ReadMask;
      
      /* Wait for data to be present to be moved */
      errno = 0;
      nready = select(32,&SelectReadMask,(int *)0,(int *)0,NIL);
    } while( nready < 0  &&  errno == EINTR );

    /* select(2) failed, shouldn't happen.  Exit abnormally */
    if( nready < 0 )
      exit(EX_SOFTWARE);
    
    /* Favor the client (for no particular reason) 
       if s/he is has data */
    if( SelectReadMask & ClientMask )      
      {
	if (cmd)
	  fprintf(cmd,"client %d\n",nready);
	xfer(client, server,login);
      }
    
    /* Then check on the other guy */
    if( SelectReadMask & ServerMask )
      {
	if (cmd)
	  fprintf(cmd,"server %d\n",nready);
	xfer(server, client,logout);
      }
  }

    /* NEVER REACHED */
}

#define      BUFSIZE        20000 /* Max bytes to move at a time */

xfer(from, to,file)
     int      from, to;        /* Move data from "from" to "to" */
     FILE *file;
{
  static char buf[BUFSIZE];      /* Buffer data to be moved      */
  int      nready;               /* # bytes readable             */
  int      got;                  /* # bytes actually being moved */
  int ret;
  
  /* Query the system how many bytes are ready to be read */
  ioctl(from, FIONREAD, &nready);
  
  if (cmd)
    fprintf(cmd,"nready = %d\n",nready);
  
  /* Only try to get the smaller of nready and BUFSIZE */
  got = read(from, buf, nready < BUFSIZE ? nready : BUFSIZE);

  /* Zero bytes returned indicates end of stream, exit gracefully */
  if( got == 0 )
    {
      if (cmd)
	{
	  fprintf(cmd,"read 0 bytes exiting\n");
	  fflush(cmd);
	}
      if (login)
	fclose(login);
      if (logout)
	fclose(logout);
      if (cmd)
	fclose(cmd);
      exit(EX_OK);
    }
  
  
  if (file)
    {
      fprintf(file,"\nTransaction %d\n",trans_num);
      fwrite(buf,got,1,file);
      fflush(file);
    }
  trans_num++;
  
  /* Now send it accross to the other side */
  ret = write(to, buf, got);
  
  if (cmd)
    {
      fprintf(cmd,"wrote %d\n",ret);
      if (ret < 0)
	fprintf(cmd,"error = %s\n",strerror(errno));
    }
}

int
inet_conn(host, port)
    char *host;
    char *port;
{
  /* Local Vars */
  int                sock;      /* Socket to use for the connection */
  struct hostent     *hostent;  /* Destination host entry           */
  struct servent     *servent;  /* Destination service entry        */
  struct sockaddr_in addr;      /* Formated destination for connect */
  
  /* Fetch the requested host and service entries */
  hostent = gethostbyname(host);
  if (isdigit(*port))
    servent = getservbyport(80, "tcp");
  else
    servent = getservbyname(port, "tcp");

  
  if (cmd)
    {
      fprintf(cmd,"inet_conn %s %s\n",host,port);
  
      if (servent == NULL)
	fprintf(cmd,"servent is NIL\n");
      if (hostent == NULL)
	fprintf(cmd,"hostent is NIL\n");
      if (hostent->h_addrtype != AF_INET)
	fprintf(cmd,"not inet type\n");
      fflush(cmd);
    }


  /* No host entry, no service entry, or host is not 
     Internet, error! */
  if( servent == NIL || 
     hostent == NIL || 
     hostent->h_addrtype != AF_INET )
    return -1;
  
  /* Get a socket from the system to use for the connection */
  if( (sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    return -1;
  
  /* Make sure we start with a clean address structure ... */
  bzero(&addr, sizeof(addr));
  
  /* ... then fill in the required fields */
  addr.sin_family = AF_INET;
  addr.sin_port   = servent->s_port;
  bcopy(hostent->h_addr, &addr.sin_addr, hostent->h_length);
  
  /* Now try to connection to the destination */
  if( connect(sock, &addr, sizeof(addr)) < 0 ) {
    /* No go, release the socket, and then return error! */
    close(sock);
    return -1;
  }
  
  /* Success.  Return the connected socket descriptor */
  if (cmd)
    fprintf(cmd,"returning %d\n",sock);
  return sock;
}


