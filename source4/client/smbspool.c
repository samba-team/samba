/* 
   Unix SMB/CIFS implementation.
   SMB backend for the Common UNIX Printing System ("CUPS")
   Copyright 1999 by Easy Software Products
   Copyright Andrew Tridgell 1994-1998
   Copyright Andrew Bartlett 2002
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"

/*
 * Local functions...
 */

static void		list_devices(void);
static struct smbcli_state	*smb_connect(const char *, const char *, const char **, const char *, const char *, const char *);
static int		smb_print(struct smbcli_state *, char *, FILE *);


/*
 * 'main()' - Main entry for SMB backend.
 */

 int				/* O - Exit status */
 main(int  argc,			/* I - Number of command-line arguments */
     char *argv[])		/* I - Command-line arguments */
{
  int		i;		/* Looping var */
  int		copies;		/* Number of copies */
  char		uri[1024],	/* URI */
		*sep,		/* Pointer to separator */
		*password;	/* Password */
  const char	*username,	/* Username */
		*server,	/* Server name */
		*printer;	/* Printer name */
  const char	*workgroup;	/* Workgroup */
  FILE		*fp;		/* File to print */
  int		status=0;		/* Status of LPD job */
  struct smbcli_state *cli;	/* SMB interface */
  struct loadparm_context *lp_ctx;

  /* we expect the URI in argv[0]. Detect the case where it is in argv[1] and cope */
  if (argc > 2 && strncmp(argv[0],"smb://", 6) && !strncmp(argv[1],"smb://", 6)) {
	  argv++;
	  argc--;
  }

  if (argc == 1)
  {
   /*
    * NEW!  In CUPS 1.1 the backends are run with no arguments to list the
    *       available devices.  These can be devices served by this backend
    *       or any other backends (i.e. you can have an SNMP backend that
    *       is only used to enumerate the available network printers... :)
    */

    list_devices();
    return (0);
  }

  if (argc < 6 || argc > 7)
  {
    fprintf(stderr, "Usage: %s [DEVICE_URI] job-id user title copies options [file]\n",
            argv[0]);
    fputs("       The DEVICE_URI environment variable can also contain the\n", stderr);
    fputs("       destination printer:\n", stderr);
    fputs("\n", stderr);
    fputs("           smb://[username:password@][workgroup/]server/printer\n", stderr);
    return (1);
  }

 /*
  * If we have 7 arguments, print the file named on the command-line.
  * Otherwise, print data from stdin...
  */

  if (argc == 6)
  {
   /*
    * Print from Copy stdin to a temporary file...
    */

    fp     = stdin;
    copies = 1;
  }
  else if ((fp = fopen(argv[6], "rb")) == NULL)
  {
    perror("ERROR: Unable to open print file");
    return (1);
  }
  else
    copies = atoi(argv[4]);

 /*
  * Find the URI...
  */

  if (strncmp(argv[0], "smb://", 6) == 0)
    strncpy(uri, argv[0], sizeof(uri) - 1);
  else if (getenv("DEVICE_URI") != NULL)
    strncpy(uri, getenv("DEVICE_URI"), sizeof(uri) - 1);
  else
  {
    fputs("ERROR: No device URI found in argv[0] or DEVICE_URI environment variable!\n", stderr);
    return (1);
  }

  uri[sizeof(uri) - 1] = '\0';

 /*
  * Extract the destination from the URI...
  */

  if ((sep = strrchr_m(uri, '@')) != NULL)
  {
    username = uri + 6;
    *sep++ = '\0';

    server = sep;

   /*
    * Extract password as needed...
    */

    if ((password = strchr_m(username, ':')) != NULL)
      *password++ = '\0';
    else
      password = "";
  }
  else
  {
    username = "";
    password = "";
    server   = uri + 6;
  }

  if ((sep = strchr_m(server, '/')) == NULL)
  {
    fputs("ERROR: Bad URI - need printer name!\n", stderr);
    return (1);
  }

  *sep++ = '\0';
  printer = sep;

  if ((sep = strchr_m(printer, '/')) != NULL)
  {
   /*
    * Convert to smb://[username:password@]workgroup/server/printer...
    */

    *sep++ = '\0';

    workgroup = server;
    server    = printer;
    printer   = sep;
  }
  else
    workgroup = NULL;

 /*
  * Setup the SAMBA server state...
  */

  setup_logging(argv[0], DEBUG_STDOUT);

  lp_ctx = loadparm_init(talloc_autofree_context());

  if (!lp_load(lp_ctx, dyn_CONFIGFILE)) {
	  fprintf(stderr, "ERROR: Can't load %s - run testparm to debug it\n", lp_config_file());
	  return (1);
  }

  if (workgroup == NULL)
    workgroup = lp_workgroup(lp_ctx);

  do
  {
    if ((cli = smb_connect(workgroup, server, lp_smb_ports(lp_ctx), printer, username, password)) == NULL)
    {
      if (getenv("CLASS") == NULL)
      {
        fprintf(stderr, "ERROR: Unable to connect to SAMBA host, will retry in 60 seconds...");
        sleep (60);
      }
      else
      {
        fprintf(stderr, "ERROR: Unable to connect to SAMBA host, trying next printer...");
        return (1);
      }
    }
  }
  while (cli == NULL);

 /*
  * Now that we are connected to the server, ignore SIGTERM so that we
  * can finish out any page data the driver sends (e.g. to eject the
  * current page...  Only ignore SIGTERM if we are printing data from
  * stdin (otherwise you can't cancel raw jobs...)
  */

  if (argc < 7)
    CatchSignal(SIGTERM, SIG_IGN);

 /*
  * Queue the job...
  */

  for (i = 0; i < copies; i ++)
    if ((status = smb_print(cli, argv[3] /* title */, fp)) != 0)
      break;

  talloc_free(cli);

 /*
  * Return the queue status...
  */

  return (status);
}


/*
 * 'list_devices()' - List the available printers seen on the network...
 */

static void
list_devices(void)
{
 /*
  * Eventually, search the local workgroup for available hosts and printers.
  */

  puts("network smb \"Unknown\" \"Windows Printer via SAMBA\"");
}


/*
 * 'smb_connect()' - Return a connection to a server.
 */

static struct smbcli_state *		/* O - SMB connection */
smb_connect(const char *workgroup,		/* I - Workgroup */
            const char *server,		/* I - Server */
	    const char **ports,           /* I - Ports */
            const char *share,		/* I - Printer */
            const char *username,		/* I - Username */
            const char *password)		/* I - Password */
{
  struct smbcli_state	*c;		/* New connection */
  char *myname;		/* Client name */
  NTSTATUS nt_status;

 /*
  * Get the names and addresses of the client and server...
  */

  myname = get_myname(NULL);
  	
  nt_status = smbcli_full_connection(NULL, &c, myname, server, ports, share, 
				     NULL, username, workgroup, password, NULL);
  
  talloc_free(myname);
  if (!NT_STATUS_IS_OK(nt_status)) {
	  fprintf(stderr, "ERROR:  Connection failed with error %s\n", nt_errstr(nt_status));
	  return NULL;
  }

  /*
   * Return the new connection...
   */
  
  return (c);
}


/*
 * 'smb_print()' - Queue a job for printing using the SMB protocol.
 */

static int				/* O - 0 = success, non-0 = failure */
smb_print(struct smbcli_state *cli,	/* I - SMB connection */
          char             *title,	/* I - Title/job name */
          FILE             *fp)		/* I - File to print */
{
  int	fnum;		/* File number */
  int	nbytes,		/* Number of bytes read */
	tbytes;		/* Total bytes read */
  char	buffer[8192],	/* Buffer for copy */
	*ptr;		/* Pointer into tile */


 /*
  * Sanitize the title...
  */

  for (ptr = title; *ptr; ptr ++)
    if (!isalnum((int)*ptr) && !isspace((int)*ptr))
      *ptr = '_';

 /*
  * Open the printer device...
  */

  if ((fnum = smbcli_open(cli, title, O_RDWR | O_CREAT | O_TRUNC, DENY_NONE)) == -1)
  {
    fprintf(stderr, "ERROR: %s opening remote file %s\n",
            smbcli_errstr(cli), title);
    return (1);
  }

 /*
  * Copy the file to the printer...
  */

  if (fp != stdin)
    rewind(fp);

  tbytes = 0;

  while ((nbytes = fread(buffer, 1, sizeof(buffer), fp)) > 0)
  {
    if (smbcli_write(cli, fnum, 0, buffer, tbytes, nbytes) != nbytes)
    {
      fprintf(stderr, "ERROR: Error writing file: %s\n", smbcli_errstr(cli));
      break;
    }

    tbytes += nbytes;
  } 

  if (!smbcli_close(cli, fnum))
  {
    fprintf(stderr, "ERROR: %s closing remote file %s\n",
            smbcli_errstr(cli), title);
    return (1);
  }
  else
    return (0);
}
