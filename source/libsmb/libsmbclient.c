/* 
   Unix SMB/Netbios implementation.
   SMB client library implementation
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Richard Sharpe 2000, 2002
   Copyright (C) John Terpstra 2000
   Copyright (C) Tom Jansen (Ninja ISD) 2002 
   Copyright (C) Derrell Lipman 2003
   
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

#include "../include/libsmb_internal.h"

/*
 * Internal flags for extended attributes
 */

/* internal mode values */
#define SMBC_XATTR_MODE_ADD          1
#define SMBC_XATTR_MODE_REMOVE       2
#define SMBC_XATTR_MODE_REMOVE_ALL   3
#define SMBC_XATTR_MODE_SET          4
#define SMBC_XATTR_MODE_CHOWN        5
#define SMBC_XATTR_MODE_CHGRP        6

#define CREATE_ACCESS_READ      READ_CONTROL_ACCESS

/*We should test for this in configure ... */
#ifndef ENOTSUP
#define ENOTSUP EOPNOTSUPP
#endif

/*
 * Functions exported by libsmb_cache.c that we need here
 */
int smbc_default_cache_functions(SMBCCTX *context);

/* 
 * check if an element is part of the list. 
 * FIXME: Does not belong here !  
 * Can anyone put this in a macro in dlinklist.h ?
 * -- Tom
 */
static int DLIST_CONTAINS(SMBCFILE * list, SMBCFILE *p) {
	if (!p || !list) return False;
	do {
		if (p == list) return True;
		list = list->next;
	} while (list);
	return False;
}

extern BOOL in_client;

/*
 * Is the logging working / configfile read ? 
 */
static int smbc_initialized = 0;

static int 
hex2int( unsigned int _char )
{
    if ( _char >= 'A' && _char <='F')
	return _char - 'A' + 10;
    if ( _char >= 'a' && _char <='f')
	return _char - 'a' + 10;
    if ( _char >= '0' && _char <='9')
	return _char - '0';
    return -1;
}

static void 
decode_urlpart(char *segment, size_t sizeof_segment)
{
    int old_length = strlen(segment);
    int new_length = 0;
    int new_length2 = 0;
    int i = 0;
    pstring new_segment;
    char *new_usegment = 0;

    if ( !old_length ) {
	return;
    }

    /* make a copy of the old one */
    new_usegment = (char*)malloc( old_length * 3 + 1 );

    while( i < old_length ) {
	int bReencode = False;
	unsigned char character = segment[ i++ ];
	if ((character <= ' ') || (character > 127))
	    bReencode = True;

	new_usegment [ new_length2++ ] = character;
	if (character == '%' ) {
	    int a = i+1 < old_length ? hex2int( segment[i] ) : -1;
	    int b = i+1 < old_length ? hex2int( segment[i+1] ) : -1;
	    if ((a == -1) || (b == -1)) { /* Only replace if sequence is valid */
		/* Contains stray %, make sure to re-encode! */
		bReencode = True;
	    } else {
		/* Valid %xx sequence */
		character = a * 16 + b; /* Replace with value of %dd */
		if (!character)
		    break; /* Stop at %00 */

		new_usegment [ new_length2++ ] = (unsigned char) segment[i++];
		new_usegment [ new_length2++ ] = (unsigned char) segment[i++];
	    }
	}
	if (bReencode) {
	    unsigned int c = character / 16;
	    new_length2--;
	    new_usegment [ new_length2++ ] = '%';

	    c += (c > 9) ? ('A' - 10) : '0';
	    new_usegment[ new_length2++ ] = c;

	    c = character % 16;
	    c += (c > 9) ? ('A' - 10) : '0';
	    new_usegment[ new_length2++ ] = c;
	}

	new_segment [ new_length++ ] = character;
    }
    new_segment [ new_length ] = 0;

    free(new_usegment);

    /* realloc it with unix charset */
    pull_utf8_allocate(&new_usegment, new_segment);

    /* this assumes (very safely) that removing %aa sequences
       only shortens the string */
    strncpy(segment, new_usegment, sizeof_segment);

    free(new_usegment);
}

/*
 * Function to parse a path and turn it into components
 *
 * The general format of an SMB URI is explain in Christopher Hertel's CIFS
 * book, at http://ubiqx.org/cifs/Appendix-D.html.  We accept a subset of the
 * general format ("smb:" only; we do not look for "cifs:"), and expand on
 * what he calls "context", herein called "options" to avoid conflict with the
 * SMBCCTX context used throughout this library.  We add the "mb" keyword
 * which applies as follows:
 *
 *
 * We accept:
 *  smb://[[[domain;]user[:password@]]server[/share[/path[/file]]]][?options]
 *
 * Meaning of URLs:
 *
 * smb://           show all workgroups known by the first master browser found
 * smb://?mb=.any   same as smb:// (i.e. without any options)
 *
 * smb://?mb=.all   show all workgroups known by every master browser found.
 *                  Why might you want this?  In an "appliance" application
 *                  where the workgroup/domain being used on the local network
 *                  is not known ahead of time, but where one wanted to
 *                  provide network services via samba, a unique workgroup
 *                  could be used.  However, when the appliance is first
 *                  started, the local samba instance's master browser has not
 *                  synchronized with the other master browser(s) on the
 *                  network (and might not synchronize for 12 minutes) and
 *                  therefore is not aware of the workgroup/ domain names
 *                  available on the network.  This option may be used to
 *                  overcome the problem of a libsmbclient application
 *                  arbitrarily selecting the local (still ignorant) master
 *                  browser to obtain its list of workgroups/domains and
 *                  getting back a practically emmpty list.  By requesting
 *                  the list of workgroups/domains from each found master
 *                  browser on the local network, a complete list of
 *                  workgroups/domains can be built.
 *
 * smb://?mb=name   NOT YET IMPLEMENTED -- show all workgroups known by the
 *                  master browser whose name is "name"
 *
 * smb://name/      if name<1D> or name<1B> exists, list servers in
 *                  workgroup, else, if name<20> exists, list all shares
 *                  for server ...
 *
 * If "options" are provided, this function returns the entire option list as
 * a string, for later parsing by the caller.
 */

static const char *smbc_prefix = "smb:";

static int
smbc_parse_path(SMBCCTX *context,
                const char *fname,
                char *server, int server_len,
                char *share, int share_len,
                char *path, int path_len,
		char *user, int user_len,
                char *password, int password_len,
                char *options, int options_len)
{
	static pstring s;
	pstring userinfo;
	const char *p;
	char *q, *r;
	int len;

	server[0] = share[0] = path[0] = user[0] = password[0] = (char)0;
        if (options != NULL && options_len > 0) {
                options[0] = (char)0;
        }
	pstrcpy(s, fname);

	/* see if it has the right prefix */
	len = strlen(smbc_prefix);
	if (strncmp(s,smbc_prefix,len) || (s[len] != '/' && s[len] != 0)) {
                return -1; /* What about no smb: ? */
        }

	p = s + len;

	/* Watch the test below, we are testing to see if we should exit */

	if (strncmp(p, "//", 2) && strncmp(p, "\\\\", 2)) {

                DEBUG(1, ("Invalid path (does not begin with smb://"));
		return -1;

	}

	p += 2;  /* Skip the double slash */

        /* See if any options were specified */
        if ( (q = strrchr(p, '?')) != NULL ) {
                /* There are options.  Null terminate here and point to them */
                *q++ = '\0';
                
                DEBUG(4, ("Found options '%s'", q));

                /* Copy the options */
                if (options != NULL && options_len > 0) {
                        safe_strcpy(options, q, options_len - 1);
                }
        }

	if (*p == (char)0)
	    goto decoding;

	if (*p == '/') {

		strncpy(server, context->workgroup, 
			(strlen(context->workgroup) < 16)?strlen(context->workgroup):16);
		return 0;
		
	}

	/*
	 * ok, its for us. Now parse out the server, share etc. 
	 *
	 * However, we want to parse out [[domain;]user[:password]@] if it
	 * exists ...
	 */

	/* check that '@' occurs before '/', if '/' exists at all */
	q = strchr_m(p, '@');
	r = strchr_m(p, '/');
	if (q && (!r || q < r)) {
		pstring username, passwd, domain;
		const char *u = userinfo;

		next_token(&p, userinfo, "@", sizeof(fstring));

		username[0] = passwd[0] = domain[0] = 0;

		if (strchr_m(u, ';')) {
      
			next_token(&u, domain, ";", sizeof(fstring));

		}

		if (strchr_m(u, ':')) {

			next_token(&u, username, ":", sizeof(fstring));

			pstrcpy(passwd, u);

		}
		else {

			pstrcpy(username, u);

		}

		if (username[0])
			strncpy(user, username, user_len);  /* FIXME, domain */

		if (passwd[0])
			strncpy(password, passwd, password_len);

	}

	if (!next_token(&p, server, "/", sizeof(fstring))) {

		return -1;

	}

	if (*p == (char)0) goto decoding;  /* That's it ... */
  
	if (!next_token(&p, share, "/", sizeof(fstring))) {

		return -1;

	}

        safe_strcpy(path, p, path_len - 1);

	all_string_sub(path, "/", "\\", 0);

 decoding:
	decode_urlpart(path, path_len);
	decode_urlpart(server, server_len);
	decode_urlpart(share, share_len);
	decode_urlpart(user, user_len);
	decode_urlpart(password, password_len);

	return 0;
}

/*
 * Verify that the options specified in a URL are valid
 */
static int smbc_check_options(char *server, char *share, char *path, char *options)
{
        DEBUG(4, ("smbc_check_options(): server='%s' share='%s' path='%s' options='%s'\n", server, share, path, options));

        /* No options at all is always ok */
        if (! *options) return 0;

        /*
         * For right now, we only support a very few options possibilities.
         * No options are supported if server, share, or path are not empty.
         * If all are empty, then we support the following two choices right
         * now:
         *
         *   mb=.any
         *   mb=.all
         */
        if ((*server || *share || *path) && *options) {
                /* Invalid: options provided with server, share, or path */
                DEBUG(1, ("Found unsupported options (%s) with non-empty server, share, or path\n", options));
                return -1;
        }

        if (strcmp(options, "mb=.any") != 0 &&
            strcmp(options, "mb=.all") != 0) {
                DEBUG(1, ("Found unsupported options (%s)\n", options));
                return -1;
        }

        return 0;
}

/*
 * Convert an SMB error into a UNIX error ...
 */
static int smbc_errno(SMBCCTX *context, struct cli_state *c)
{
	int ret = cli_errno(c);
	
        if (cli_is_dos_error(c)) {
                uint8 eclass;
                uint32 ecode;

                cli_dos_error(c, &eclass, &ecode);
                
                DEBUG(3,("smbc_error %d %d (0x%x) -> %d\n", 
                         (int)eclass, (int)ecode, (int)ecode, ret));
        } else {
                NTSTATUS status;

                status = cli_nt_error(c);

                DEBUG(3,("smbc errno %s -> %d\n",
                         nt_errstr(status), ret));
        }

	return ret;
}

/* 
 * Check a server_fd.
 * returns 0 if the server is in shape. Returns 1 on error 
 * 
 * Also useable outside libsmbclient to enable external cache
 * to do some checks too.
 */
int smbc_check_server(SMBCCTX * context, SMBCSRV * server) 
{
	if ( send_keepalive(server->cli.fd) == False )
		return 1;

	/* connection is ok */
	return 0;
}

/* 
 * Remove a server from the cached server list it's unused.
 * On success, 0 is returned. 1 is returned if the server could not be removed.
 * 
 * Also useable outside libsmbclient
 */
int smbc_remove_unused_server(SMBCCTX * context, SMBCSRV * srv)
{
	SMBCFILE * file;

	/* are we being fooled ? */
	if (!context || !context->internal ||
	    !context->internal->_initialized || !srv) return 1;

	
	/* Check all open files/directories for a relation with this server */
	for (file = context->internal->_files; file; file=file->next) {
		if (file->srv == srv) {
			/* Still used */
			DEBUG(3, ("smbc_remove_usused_server: %p still used by %p.\n", 
				  srv, file));
			return 1;
		}
	}

	DLIST_REMOVE(context->internal->_servers, srv);

	cli_shutdown(&srv->cli);

	DEBUG(3, ("smbc_remove_usused_server: %p removed.\n", srv));

	context->callbacks.remove_cached_srv_fn(context, srv);
	
	SAFE_FREE(srv);
	
	return 0;
}

SMBCSRV *find_server(SMBCCTX *context,
                     const char *server,
                     const char *share,
                     fstring workgroup,
                     fstring username,
                     fstring password)
{
        SMBCSRV *srv;
        int auth_called = 0;
        
 check_server_cache:

	srv = context->callbacks.get_cached_srv_fn(context, server, share, 
						   workgroup, username);
	
	if (!auth_called && !srv && (!username[0] || !password[0])) {
		context->callbacks.auth_fn(server, share,
                                           workgroup, sizeof(fstring),
                                           username, sizeof(fstring),
                                           password, sizeof(fstring));
		/*
                 * However, smbc_auth_fn may have picked up info relating to
                 * an existing connection, so try for an existing connection
                 * again ...
                 */
		auth_called = 1;
		goto check_server_cache;
		
	}
	
	if (srv) {
		if (context->callbacks.check_server_fn(context, srv)) {
			/*
                         * This server is no good anymore 
                         * Try to remove it and check for more possible
                         * servers in the cache
                         */
			if (context->callbacks.remove_unused_server_fn(context,
                                                                       srv)) { 
                                /*
                                 * We could not remove the server completely,
                                 * remove it from the cache so we will not get
                                 * it again. It will be removed when the last
                                 * file/dir is closed.
                                 */
				context->callbacks.remove_cached_srv_fn(context,
                                                                        srv);
			}
			
			/*
                         * Maybe there are more cached connections to this
                         * server
                         */
			goto check_server_cache; 
		}
		return srv;
 	}

        return NULL;
}

/*
 * Connect to a server, possibly on an existing connection
 *
 * Here, what we want to do is: If the server and username
 * match an existing connection, reuse that, otherwise, establish a 
 * new connection.
 *
 * If we have to create a new connection, call the auth_fn to get the
 * info we need, unless the username and password were passed in.
 */

SMBCSRV *smbc_server(SMBCCTX *context,
		     const char *server, const char *share, 
		     fstring workgroup, fstring username, 
		     fstring password)
{
	SMBCSRV *srv=NULL;
	struct cli_state c;
	struct nmb_name called, calling;
	const char *server_n = server;
	pstring ipenv;
	struct in_addr ip;
	int tried_reverse = 0;
  
	zero_ip(&ip);
	ZERO_STRUCT(c);

	if (server[0] == 0) {
		errno = EPERM;
		return NULL;
	}

        srv = find_server(context, server, share,
                          workgroup, username, password);
        if (srv)
                return srv;

	make_nmb_name(&calling, context->netbios_name, 0x0);
	make_nmb_name(&called , server, 0x20);

	DEBUG(4,("smbc_server: server_n=[%s] server=[%s]\n", server_n, server));
  
#if 0 /* djl: obsolete code?  neither group nor p is used beyond here */
	if ((p=strchr_m(server_n,'#')) && 
	    (strcmp(p+1,"1D")==0 || strcmp(p+1,"01")==0)) {
    
		fstrcpy(group, server_n);
		p = strchr_m(group,'#');
		*p = 0;
		
	}
#endif

	DEBUG(4,(" -> server_n=[%s] server=[%s]\n", server_n, server));

 again:
	slprintf(ipenv,sizeof(ipenv)-1,"HOST_%s", server_n);

	zero_ip(&ip);

	/* have to open a new connection */
	if (!cli_initialise(&c)) {
		errno = ENOMEM;
		return NULL;
	}

	c.timeout = context->timeout;

        /* Force use of port 139 for first try, so browse lists can work */
        c.port = 139;

	if (!cli_connect(&c, server_n, &ip)) {
                /*
                 * Port 139 connection failed.  Try port 445 to handle
                 * connections to newer (e.g. XP) hosts with NetBIOS disabled.
                 */
                c.port = 445;
                if (!cli_connect(&c, server_n, &ip)) {
                        errno = ENETUNREACH;
                        return NULL;
                }
 	}

	if (!cli_session_request(&c, &calling, &called)) {
		cli_shutdown(&c);
		if (strcmp(called.name, "*SMBSERVER")) {
			make_nmb_name(&called , "*SMBSERVER", 0x20);
			goto again;
		}
		else {  /* Try one more time, but ensure we don't loop */

		  /* Only try this if server is an IP address ... */

		  if (is_ipaddress(server) && !tried_reverse) {
		    fstring remote_name;
		    struct in_addr rem_ip;

		    if ((rem_ip.s_addr=inet_addr(server)) == INADDR_NONE) {
		      DEBUG(4, ("Could not convert IP address %s to struct in_addr\n", server));
		      errno = ENOENT;
		      return NULL;
		    }

		    tried_reverse++; /* Yuck */

		    if (name_status_find("*", 0, 0, rem_ip, remote_name)) {
		      make_nmb_name(&called, remote_name, 0x20);
		      goto again;
		    }


		  }
		}
		errno = ENOENT;
		return NULL;
	}
  
	DEBUG(4,(" session request ok\n"));
  
	if (!cli_negprot(&c)) {
		cli_shutdown(&c);
		errno = ENOENT;
		return NULL;
	}

	if (!cli_session_setup(&c, username, 
			       password, strlen(password),
			       password, strlen(password),
			       workgroup) &&
	    /* try an anonymous login if it failed */
	    !cli_session_setup(&c, "", "", 1,"", 0, workgroup)) {
		cli_shutdown(&c);
		errno = EPERM;
		return NULL;
	}

	DEBUG(4,(" session setup ok\n"));

	if (!cli_send_tconX(&c, share, "?????",
			    password, strlen(password)+1)) {
		errno = smbc_errno(context, &c);
		cli_shutdown(&c);
		return NULL;
	}
  
	DEBUG(4,(" tconx ok\n"));
  
	/*
	 * Ok, we have got a nice connection
	 * Let's find a free server_fd 
	 */

	srv = (SMBCSRV *)malloc(sizeof(*srv));
	if (!srv) {
		errno = ENOMEM;
		goto failed;
	}

	ZERO_STRUCTP(srv);
	srv->cli = c;
	srv->dev = (dev_t)(str_checksum(server) ^ str_checksum(share));

	/* now add it to the cache (internal or external) */
	if (context->callbacks.add_cached_srv_fn(context, srv, server, share, workgroup, username)) {
		DEBUG(3, (" Failed to add server to cache\n"));
		goto failed;
	}

	
	DEBUG(2, ("Server connect ok: //%s/%s: %p\n", 
		  server, share, srv));

	DLIST_ADD(context->internal->_servers, srv);
	return srv;

 failed:
	cli_shutdown(&c);
	if (!srv) return NULL;
  
	SAFE_FREE(srv);
	return NULL;
}

/*
 * Connect to a server for getting/setting attributes, possibly on an existing
 * connection.  This works similarly to smbc_server().
 */
SMBCSRV *smbc_attr_server(SMBCCTX *context,
                          const char *server, const char *share, 
                          fstring workgroup,
                          fstring username, fstring password,
                          POLICY_HND *pol)
{
        struct in_addr ip;
	struct cli_state *ipc_cli;
        NTSTATUS nt_status;
	SMBCSRV *ipc_srv=NULL;

        /*
         * See if we've already created this special connection.  Reference
         * our "special" share name 'IPC$$'.
         */
        ipc_srv = find_server(context, server, "IPC$$",
                              workgroup, username, password);
        if (!ipc_srv) {

                /* We didn't find a cached connection.  Get the password */
                if (*password == '\0') {
                        /* ... then retrieve it now. */
                        context->callbacks.auth_fn(server, share,
                                                   workgroup, sizeof(fstring),
                                                   username, sizeof(fstring),
                                                   password, sizeof(fstring));
                }
        
                zero_ip(&ip);
                nt_status = cli_full_connection(&ipc_cli,
                                                global_myname(), server, 
                                                &ip, 0, "IPC$", "?????",  
                                                username, workgroup,
                                                password, 0,
                                                Undefined, NULL);
                if (! NT_STATUS_IS_OK(nt_status)) {
                        DEBUG(1,("cli_full_connection failed! (%s)\n",
                                 nt_errstr(nt_status)));
                        errno = ENOTSUP;
                        return NULL;
                }

                if (!cli_nt_session_open(ipc_cli, PI_LSARPC)) {
                        DEBUG(1, ("cli_nt_session_open fail!\n"));
                        errno = ENOTSUP;
                        cli_shutdown(ipc_cli);
                        return NULL;
                }

                /* Some systems don't support SEC_RIGHTS_MAXIMUM_ALLOWED,
                   but NT sends 0x2000000 so we might as well do it too. */
        
                nt_status = cli_lsa_open_policy(ipc_cli,
                                                ipc_cli->mem_ctx,
                                                True, 
                                                GENERIC_EXECUTE_ACCESS,
                                                pol);
        
                if (!NT_STATUS_IS_OK(nt_status)) {
                        errno = smbc_errno(context, ipc_cli);
                        cli_shutdown(ipc_cli);
                        return NULL;
                }

                ipc_srv = (SMBCSRV *)malloc(sizeof(*ipc_srv));
                if (!ipc_srv) {
                        errno = ENOMEM;
                        cli_shutdown(ipc_cli);
                        return NULL;
                }

                ZERO_STRUCTP(ipc_srv);
                ipc_srv->cli = *ipc_cli;

                free(ipc_cli);

                /* now add it to the cache (internal or external) */

                errno = 0;      /* let cache function set errno if it likes */
                if (context->callbacks.add_cached_srv_fn(context, ipc_srv,
                                                         server,
                                                         "IPC$$",
                                                         workgroup,
                                                         username)) {
                        DEBUG(3, (" Failed to add server to cache\n"));
                        if (errno == 0) {
                                errno = ENOMEM;
                        }
                        cli_shutdown(&ipc_srv->cli);
                        free(ipc_srv);
                        return NULL;
                }

                DLIST_ADD(context->internal->_servers, ipc_srv);
        }

        return ipc_srv;
}

/*
 * Routine to open() a file ...
 */

static SMBCFILE *smbc_open_ctx(SMBCCTX *context, const char *fname, int flags, mode_t mode)
{
	fstring server, share, user, password, workgroup;
	pstring path;
	SMBCSRV *srv   = NULL;
	SMBCFILE *file = NULL;
	int fd;

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;  /* Best I can think of ... */
		return NULL;

	}

	if (!fname) {

		errno = EINVAL;
		return NULL;

	}

	if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0)) {
                errno = EINVAL;
                return NULL;
        }

	if (user[0] == (char)0) fstrcpy(user, context->user);

	fstrcpy(workgroup, context->workgroup);

	srv = smbc_server(context, server, share, workgroup, user, password);

	if (!srv) {

		if (errno == EPERM) errno = EACCES;
		return NULL;  /* smbc_server sets errno */
    
	}

	/* Hmmm, the test for a directory is suspect here ... FIXME */

	if (strlen(path) > 0 && path[strlen(path) - 1] == '\\') {
    
		fd = -1;

	}
	else {
	  
		file = malloc(sizeof(SMBCFILE));

		if (!file) {

			errno = ENOMEM;
			return NULL;

		}

		ZERO_STRUCTP(file);

		if ((fd = cli_open(&srv->cli, path, flags, DENY_NONE)) < 0) {

			/* Handle the error ... */

			SAFE_FREE(file);
			errno = smbc_errno(context, &srv->cli);
			return NULL;

		}

		/* Fill in file struct */

		file->cli_fd  = fd;
		file->fname   = strdup(fname);
		file->srv     = srv;
		file->offset  = 0;
		file->file    = True;

		DLIST_ADD(context->internal->_files, file);
		return file;

	}

	/* Check if opendir needed ... */

	if (fd == -1) {
		int eno = 0;

		eno = smbc_errno(context, &srv->cli);
		file = context->opendir(context, fname);
		if (!file) errno = eno;
		return file;

	}

	errno = EINVAL; /* FIXME, correct errno ? */
	return NULL;

}

/*
 * Routine to create a file 
 */

static int creat_bits = O_WRONLY | O_CREAT | O_TRUNC; /* FIXME: Do we need this */

static SMBCFILE *smbc_creat_ctx(SMBCCTX *context, const char *path, mode_t mode)
{

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;
		return NULL;

	}

	return smbc_open_ctx(context, path, creat_bits, mode);
}

/*
 * Routine to read() a file ...
 */

static ssize_t smbc_read_ctx(SMBCCTX *context, SMBCFILE *file, void *buf, size_t count)
{
	int ret;

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;

	}

	DEBUG(4, ("smbc_read(%p, %d)\n", file, (int)count));

	if (!file || !DLIST_CONTAINS(context->internal->_files, file)) {

		errno = EBADF;
		return -1;

	}

	/* Check that the buffer exists ... */

	if (buf == NULL) {

		errno = EINVAL;
		return -1;

	}

	ret = cli_read(&file->srv->cli, file->cli_fd, buf, file->offset, count);

	if (ret < 0) {

		errno = smbc_errno(context, &file->srv->cli);
		return -1;

	}

	file->offset += ret;

	DEBUG(4, ("  --> %d\n", ret));

	return ret;  /* Success, ret bytes of data ... */

}

/*
 * Routine to write() a file ...
 */

static ssize_t smbc_write_ctx(SMBCCTX *context, SMBCFILE *file, void *buf, size_t count)
{
	int ret;

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;

	}

	if (!file || !DLIST_CONTAINS(context->internal->_files, file)) {

		errno = EBADF;
		return -1;
    
	}

	/* Check that the buffer exists ... */

	if (buf == NULL) {

		errno = EINVAL;
		return -1;

	}

	ret = cli_write(&file->srv->cli, file->cli_fd, 0, buf, file->offset, count);

	if (ret <= 0) {

		errno = smbc_errno(context, &file->srv->cli);
		return -1;

	}

	file->offset += ret;

	return ret;  /* Success, 0 bytes of data ... */
}
 
/*
 * Routine to close() a file ...
 */

static int smbc_close_ctx(SMBCCTX *context, SMBCFILE *file)
{
        SMBCSRV *srv; 

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;

	}

	if (!file || !DLIST_CONTAINS(context->internal->_files, file)) {
   
		errno = EBADF;
		return -1;

	}

	/* IS a dir ... */
	if (!file->file) {
		
		return context->closedir(context, file);

	}

	if (!cli_close(&file->srv->cli, file->cli_fd)) {

		DEBUG(3, ("cli_close failed on %s. purging server.\n", 
			  file->fname));
		/* Deallocate slot and remove the server 
		 * from the server cache if unused */
		errno = smbc_errno(context, &file->srv->cli);  
		srv = file->srv;
		DLIST_REMOVE(context->internal->_files, file);
		SAFE_FREE(file->fname);
		SAFE_FREE(file);
		context->callbacks.remove_unused_server_fn(context, srv);

		return -1;

	}

	DLIST_REMOVE(context->internal->_files, file);
	SAFE_FREE(file->fname);
	SAFE_FREE(file);

	return 0;
}

/*
 * Get info from an SMB server on a file. Use a qpathinfo call first
 * and if that fails, use getatr, as Win95 sometimes refuses qpathinfo
 */
static BOOL smbc_getatr(SMBCCTX * context, SMBCSRV *srv, char *path, 
		 uint16 *mode, size_t *size, 
		 time_t *c_time, time_t *a_time, time_t *m_time,
		 SMB_INO_T *ino)
{

	if (!context || !context->internal ||
	    !context->internal->_initialized) {
 
		errno = EINVAL;
 		return -1;
 
 	}

	DEBUG(4,("smbc_getatr: sending qpathinfo\n"));
  
	if (!srv->no_pathinfo2 &&
	    cli_qpathinfo2(&srv->cli, path, c_time, a_time, m_time, NULL,
			   size, mode, ino)) return True;

	/* if this is NT then don't bother with the getatr */
	if (srv->cli.capabilities & CAP_NT_SMBS) {
                errno = EPERM;
                return False;
        }

	if (cli_getatr(&srv->cli, path, mode, size, m_time)) {
		a_time = c_time = m_time;
		srv->no_pathinfo2 = True;
		return True;
	}

        errno = EPERM;
	return False;

}

/*
 * Routine to unlink() a file
 */

static int smbc_unlink_ctx(SMBCCTX *context, const char *fname)
{
	fstring server, share, user, password, workgroup;
	pstring path;
	SMBCSRV *srv = NULL;

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;  /* Best I can think of ... */
		return -1;

	}

	if (!fname) {

		errno = EINVAL;
		return -1;

	}

	if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0)) {
                errno = EINVAL;
                return -1;
        }

	if (user[0] == (char)0) fstrcpy(user, context->user);

	fstrcpy(workgroup, context->workgroup);

	srv = smbc_server(context, server, share, workgroup, user, password);

	if (!srv) {

		return -1;  /* smbc_server sets errno */

	}

	/*  if (strncmp(srv->cli.dev, "LPT", 3) == 0) {

    int job = smbc_stat_printjob(srv, path, NULL, NULL);
    if (job == -1) {

      return -1;

    }
    if ((err = cli_printjob_del(&srv->cli, job)) != 0) {

    
      return -1;

    }
    } else */

	if (!cli_unlink(&srv->cli, path)) {

		errno = smbc_errno(context, &srv->cli);

		if (errno == EACCES) { /* Check if the file is a directory */

			int saverr = errno;
			size_t size = 0;
			uint16 mode = 0;
			time_t m_time = 0, a_time = 0, c_time = 0;
			SMB_INO_T ino = 0;

			if (!smbc_getatr(context, srv, path, &mode, &size,
					 &c_time, &a_time, &m_time, &ino)) {

				/* Hmmm, bad error ... What? */

				errno = smbc_errno(context, &srv->cli);
				return -1;

			}
			else {

				if (IS_DOS_DIR(mode))
					errno = EISDIR;
				else
					errno = saverr;  /* Restore this */

			}
		}

		return -1;

	}

	return 0;  /* Success ... */

}

/*
 * Routine to rename() a file
 */

static int smbc_rename_ctx(SMBCCTX *ocontext, const char *oname, 
			   SMBCCTX *ncontext, const char *nname)
{
	fstring server1, share1, server2, share2, user1, user2, password1, password2, workgroup;
	pstring path1, path2;
	SMBCSRV *srv = NULL;

	if (!ocontext || !ncontext || 
	    !ocontext->internal || !ncontext->internal ||
	    !ocontext->internal->_initialized || 
	    !ncontext->internal->_initialized) {

		errno = EINVAL;  /* Best I can think of ... */
		return -1;

	}
	
	if (!oname || !nname) {

		errno = EINVAL;
		return -1;

	}
	
	DEBUG(4, ("smbc_rename(%s,%s)\n", oname, nname));

	smbc_parse_path(ocontext, oname,
                        server1, sizeof(server1),
                        share1, sizeof(share1),
                        path1, sizeof(path1),
                        user1, sizeof(user1),
                        password1, sizeof(password1),
                        NULL, 0);

	if (user1[0] == (char)0) fstrcpy(user1, ocontext->user);

	smbc_parse_path(ncontext, nname,
                        server2, sizeof(server2),
                        share2, sizeof(share2),
                        path2, sizeof(path2),
                        user2, sizeof(user2),
                        password2, sizeof(password2),
                        NULL, 0);

	if (user2[0] == (char)0) fstrcpy(user2, ncontext->user);

	if (strcmp(server1, server2) || strcmp(share1, share2) ||
	    strcmp(user1, user2)) {

		/* Can't rename across file systems, or users?? */

		errno = EXDEV;
		return -1;

	}

	fstrcpy(workgroup, ocontext->workgroup);
	/* HELP !!! Which workgroup should I use ? Or are they always the same -- Tom */ 
	srv = smbc_server(ocontext, server1, share1, workgroup, user1, password1);
	if (!srv) {

		return -1;

	}

	if (!cli_rename(&srv->cli, path1, path2)) {
		int eno = smbc_errno(ocontext, &srv->cli);

		if (eno != EEXIST ||
		    !cli_unlink(&srv->cli, path2) ||
		    !cli_rename(&srv->cli, path1, path2)) {

			errno = eno;
			return -1;

		}
	}

	return 0; /* Success */

}

/*
 * A routine to lseek() a file
 */

static off_t smbc_lseek_ctx(SMBCCTX *context, SMBCFILE *file, off_t offset, int whence)
{
	size_t size;

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;
		
	}

	if (!file || !DLIST_CONTAINS(context->internal->_files, file)) {

		errno = EBADF;
		return -1;

	}

	if (!file->file) {

		errno = EINVAL;
		return -1;      /* Can't lseek a dir ... */

	}

	switch (whence) {
	case SEEK_SET:
		file->offset = offset;
		break;

	case SEEK_CUR:
		file->offset += offset;
		break;

	case SEEK_END:
		if (!cli_qfileinfo(&file->srv->cli, file->cli_fd, NULL, &size, NULL, NULL,
				   NULL, NULL, NULL)) 
		{
		    SMB_BIG_UINT b_size = size;
		    if (!cli_getattrE(&file->srv->cli, file->cli_fd, NULL, &b_size, NULL, NULL,
				      NULL)) 
		    {
			errno = EINVAL;
			return -1;
		    } else
			size = b_size;
		}
		file->offset = size + offset;
		break;

	default:
		errno = EINVAL;
		break;

	}

	return file->offset;

}

/* 
 * Generate an inode number from file name for those things that need it
 */

static
ino_t smbc_inode(SMBCCTX *context, const char *name)
{

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;

	}

	if (!*name) return 2; /* FIXME, why 2 ??? */
	return (ino_t)str_checksum(name);

}

/*
 * Routine to put basic stat info into a stat structure ... Used by stat and
 * fstat below.
 */

static
int smbc_setup_stat(SMBCCTX *context, struct stat *st, char *fname, size_t size, int mode)
{
	
	st->st_mode = 0;

	if (IS_DOS_DIR(mode)) {
		st->st_mode = SMBC_DIR_MODE;
	} else {
		st->st_mode = SMBC_FILE_MODE;
	}

	if (IS_DOS_ARCHIVE(mode)) st->st_mode |= S_IXUSR;
	if (IS_DOS_SYSTEM(mode)) st->st_mode |= S_IXGRP;
	if (IS_DOS_HIDDEN(mode)) st->st_mode |= S_IXOTH;
	if (!IS_DOS_READONLY(mode)) st->st_mode |= S_IWUSR;

	st->st_size = size;
#ifdef HAVE_STAT_ST_BLKSIZE
	st->st_blksize = 512;
#endif
#ifdef HAVE_STAT_ST_BLOCKS
	st->st_blocks = (size+511)/512;
#endif
	st->st_uid = getuid();
	st->st_gid = getgid();

	if (IS_DOS_DIR(mode)) {
		st->st_nlink = 2;
	} else {
		st->st_nlink = 1;
	}

	if (st->st_ino == 0) {
		st->st_ino = smbc_inode(context, fname);
	}
	
	return True;  /* FIXME: Is this needed ? */

}

/*
 * Routine to stat a file given a name
 */

static int smbc_stat_ctx(SMBCCTX *context, const char *fname, struct stat *st)
{
	SMBCSRV *srv;
	fstring server, share, user, password, workgroup;
	pstring path;
	time_t m_time = 0, a_time = 0, c_time = 0;
	size_t size = 0;
	uint16 mode = 0;
	SMB_INO_T ino = 0;

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;  /* Best I can think of ... */
		return -1;
    
	}

	if (!fname) {

		errno = EINVAL;
		return -1;

	}
  
	DEBUG(4, ("smbc_stat(%s)\n", fname));

	if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0)) {
                errno = EINVAL;
                return -1;
        }

	if (user[0] == (char)0) fstrcpy(user, context->user);

	fstrcpy(workgroup, context->workgroup);

	srv = smbc_server(context, server, share, workgroup, user, password);

	if (!srv) {
		return -1;  /* errno set by smbc_server */
	}

	if (!smbc_getatr(context, srv, path, &mode, &size, 
			 &c_time, &a_time, &m_time, &ino)) {

		errno = smbc_errno(context, &srv->cli);
		return -1;
		
	}

	st->st_ino = ino;

	smbc_setup_stat(context, st, path, size, mode);

	st->st_atime = a_time;
	st->st_ctime = c_time;
	st->st_mtime = m_time;
	st->st_dev   = srv->dev;

	return 0;

}

/*
 * Routine to stat a file given an fd
 */

static int smbc_fstat_ctx(SMBCCTX *context, SMBCFILE *file, struct stat *st)
{
	time_t c_time, a_time, m_time;
	size_t size;
	uint16 mode;
	SMB_INO_T ino = 0;

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;

	}

	if (!file || !DLIST_CONTAINS(context->internal->_files, file)) {

		errno = EBADF;
		return -1;

	}

	if (!file->file) {

		return context->fstatdir(context, file, st);

	}

	if (!cli_qfileinfo(&file->srv->cli, file->cli_fd,
			   &mode, &size, &c_time, &a_time, &m_time, NULL, &ino)) {
	    SMB_BIG_UINT b_size = size;
	    if (!cli_getattrE(&file->srv->cli, file->cli_fd,
			  &mode, &b_size, &c_time, &a_time, &m_time)) {

		errno = EINVAL;
		return -1;
	    } else
		size = b_size;

	}

	st->st_ino = ino;

	smbc_setup_stat(context, st, file->fname, size, mode);

	st->st_atime = a_time;
	st->st_ctime = c_time;
	st->st_mtime = m_time;
	st->st_dev = file->srv->dev;

	return 0;

}

/*
 * Routine to open a directory
 * We accept the URL syntax explained in smbc_parse_path(), above.
 */

static void smbc_remove_dir(SMBCFILE *dir)
{
	struct smbc_dir_list *d,*f;

	d = dir->dir_list;
	while (d) {

		f = d; d = d->next;

		SAFE_FREE(f->dirent);
		SAFE_FREE(f);

	}

	dir->dir_list = dir->dir_end = dir->dir_next = NULL;

}

static int add_dirent(SMBCFILE *dir, const char *name, const char *comment, uint32 type)
{
	struct smbc_dirent *dirent;
	int size;
	char *u_name = NULL, *u_comment = NULL;
	size_t u_name_len = 0, u_comment_len = 0;

	if (name)
	    u_name_len = push_utf8_allocate(&u_name, name);
	if (comment)
	    u_comment_len = push_utf8_allocate(&u_comment, comment);

	/*
	 * Allocate space for the dirent, which must be increased by the 
	 * size of the name and the comment and 1 for the null on the comment.
	 * The null on the name is already accounted for.
	 */

	size = sizeof(struct smbc_dirent) + u_name_len + u_comment_len + 1;
    
	dirent = malloc(size);

	if (!dirent) {

		dir->dir_error = ENOMEM;
		return -1;

	}

	ZERO_STRUCTP(dirent);

	if (dir->dir_list == NULL) {

		dir->dir_list = malloc(sizeof(struct smbc_dir_list));
		if (!dir->dir_list) {

			SAFE_FREE(dirent);
			dir->dir_error = ENOMEM;
			return -1;

		}
		ZERO_STRUCTP(dir->dir_list);

		dir->dir_end = dir->dir_next = dir->dir_list;
	}
	else {

		dir->dir_end->next = malloc(sizeof(struct smbc_dir_list));
		
		if (!dir->dir_end->next) {
			
			SAFE_FREE(dirent);
			dir->dir_error = ENOMEM;
			return -1;

		}
		ZERO_STRUCTP(dir->dir_end->next);

		dir->dir_end = dir->dir_end->next;
	}

	dir->dir_end->next = NULL;
	dir->dir_end->dirent = dirent;
	
	dirent->smbc_type = type;
	dirent->namelen = u_name_len;
	dirent->commentlen = u_comment_len;
	dirent->dirlen = size;
  
	strncpy(dirent->name, (u_name?u_name:""), dirent->namelen + 1);

	dirent->comment = (char *)(&dirent->name + dirent->namelen + 1);
	strncpy(dirent->comment, (u_comment?u_comment:""), dirent->commentlen + 1);
	
	SAFE_FREE(u_comment);
	SAFE_FREE(u_name);

	return 0;

}

static void
list_unique_wg_fn(const char *name, uint32 type, const char *comment, void *state)
{
	SMBCFILE *dir = (SMBCFILE *)state;
        struct smbc_dir_list *dir_list;
        struct smbc_dirent *dirent;
	int dirent_type;
        int remove = 0;

	dirent_type = dir->dir_type;

	if (add_dirent(dir, name, comment, dirent_type) < 0) {

		/* An error occurred, what do we do? */
		/* FIXME: Add some code here */
	}

        /* Point to the one just added */
        dirent = dir->dir_end->dirent;

        /* See if this was a duplicate */
        for (dir_list = dir->dir_list;
             dir_list != dir->dir_end;
             dir_list = dir_list->next) {
                if (! remove &&
                    strcmp(dir_list->dirent->name, dirent->name) == 0) {
                        /* Duplicate.  End end of list need to be removed. */
                        remove = 1;
                }

                if (remove && dir_list->next == dir->dir_end) {
                        /* Found the end of the list.  Remove it. */
                        dir->dir_end = dir_list;
                        free(dir_list->next);
                        dir_list->next = NULL;
                        break;
                }
        }
}

static void
list_fn(const char *name, uint32 type, const char *comment, void *state)
{
	SMBCFILE *dir = (SMBCFILE *)state;
	int dirent_type;

	/* We need to process the type a little ... */

	if (dir->dir_type == SMBC_FILE_SHARE) {
		
		switch (type) {
		case 0: /* Directory tree */
			dirent_type = SMBC_FILE_SHARE;
			break;

		case 1:
			dirent_type = SMBC_PRINTER_SHARE;
			break;

		case 2:
			dirent_type = SMBC_COMMS_SHARE;
			break;

		case 3:
			dirent_type = SMBC_IPC_SHARE;
			break;

		default:
			dirent_type = SMBC_FILE_SHARE; /* FIXME, error? */
			break;
		}
	}
	else dirent_type = dir->dir_type;

	if (add_dirent(dir, name, comment, dirent_type) < 0) {

		/* An error occurred, what do we do? */
		/* FIXME: Add some code here */

	}
}

static void
dir_list_fn(file_info *finfo, const char *mask, void *state)
{

	if (add_dirent((SMBCFILE *)state, finfo->name, "", 
		       (finfo->mode&aDIR?SMBC_DIR:SMBC_FILE)) < 0) {

		/* Handle an error ... */

		/* FIXME: Add some code ... */

	} 

}

static SMBCFILE *smbc_opendir_ctx(SMBCCTX *context, const char *fname)
{
	fstring server, share, user, password, options;
	pstring workgroup;
	pstring path;
	SMBCSRV *srv  = NULL;
	SMBCFILE *dir = NULL;
	struct in_addr rem_ip;

	if (!context || !context->internal ||
	    !context->internal->_initialized) {
	        DEBUG(4, ("no valid context\n"));
		errno = EINVAL;
		return NULL;

	}

	if (!fname) {
		DEBUG(4, ("no valid fname\n"));
		errno = EINVAL;
		return NULL;
	}

	if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(path),
                            password, sizeof(password),
                            options, sizeof(options))) {
	        DEBUG(4, ("no valid path\n"));
		errno = EINVAL;
		return NULL;
	}

	DEBUG(4, ("parsed path: fname='%s' server='%s' share='%s' path='%s' options='%s'\n", fname, server, share, path, options));

        /* Ensure the options are valid */
        if (smbc_check_options(server, share, path, options)) {
                DEBUG(4, ("unacceptable options (%s)\n", options));
                errno = EINVAL;
                return NULL;
        }

	if (user[0] == (char)0) fstrcpy(user, context->user);

	pstrcpy(workgroup, context->workgroup);

	dir = malloc(sizeof(*dir));

	if (!dir) {

		errno = ENOMEM;
		return NULL;

	}

	ZERO_STRUCTP(dir);

	dir->cli_fd   = 0;
	dir->fname    = strdup(fname);
	dir->srv      = NULL;
	dir->offset   = 0;
	dir->file     = False;
	dir->dir_list = dir->dir_next = dir->dir_end = NULL;

	if (server[0] == (char)0 &&
            (! *options || strcmp(options, "mb=.any") == 0)) {
                struct in_addr server_ip;
		if (share[0] != (char)0 || path[0] != (char)0) {

			errno = EINVAL;
			if (dir) {
				SAFE_FREE(dir->fname);
				SAFE_FREE(dir);
			}
			return NULL;
		}

		/*
                 * We have server and share and path empty ... so list the
                 * workgroups first try to get the LMB for our workgroup, and
                 * if that fails, try the DMB
                 */

		pstrcpy(workgroup, lp_workgroup());

		if (!find_master_ip(workgroup, &server_ip)) {
		    struct user_auth_info u_info;
		    struct cli_state *cli;

		    DEBUG(4, ("Unable to find master browser for workgroup %s\n", 
			      workgroup));

		    /* find the name of the server ... */
		    pstrcpy(u_info.username, user);
		    pstrcpy(u_info.password, password);

		    if (!(cli = get_ipc_connect_master_ip_bcast(workgroup, &u_info))) {
			DEBUG(4, ("Unable to find master browser by "
				  "broadcast\n"));
			errno = ENOENT;
			return NULL;
		    }

		    fstrcpy(server, cli->desthost);

		    cli_shutdown(cli);
		} else {
                    /*
                     * Do a name status query to find out the name of the
                     * master browser.  We use <01><02>__MSBROWSE__<02>#01 if
                     * *#00 fails because a domain master browser will not
                     * respond to a wildcard query (or, at least, an NT4
                     * server acting as the domain master browser will not).
                     *
                     * We might be able to use ONLY the query on MSBROWSE, but
                     * that's not yet been tested with all Windows versions,
                     * so until it is, leave the original wildcard query as
                     * the first choice and fall back to MSBROWSE if the
                     * wildcard query fails.
                     */
		    if (!name_status_find("*", 0, 0x1d, server_ip, server) &&
                        !name_status_find(MSBROWSE, 1, 0x1d, server_ip, server)) {
			errno = ENOENT;
			return NULL;
		    }
		}	

		DEBUG(4, ("using workgroup %s %s\n", workgroup, server));

                /*
                 * Get a connection to IPC$ on the server if we do not already
                 * have one
                 */
                
		srv = smbc_server(context, server, "IPC$", workgroup, user, password);
                if (!srv) {
                    
                    if (dir) {
                        SAFE_FREE(dir->fname);
                        SAFE_FREE(dir);
                    }
                    return NULL;
                }
                
		dir->srv = srv;
		dir->dir_type = SMBC_WORKGROUP;

		/* Now, list the stuff ... */

		if (!cli_NetServerEnum(&srv->cli, workgroup, SV_TYPE_DOMAIN_ENUM, list_fn,
				       (void *)dir)) {

                        DEBUG(1, ("Could not enumerate domains using '%s'\n", workgroup));
			if (dir) {
				SAFE_FREE(dir->fname);
				SAFE_FREE(dir);
			}
			errno = cli_errno(&srv->cli);

			return NULL;

		}
        } else if (server[0] == (char)0 &&
                   (! *options || strcmp(options, "mb=.all") == 0)) {

                int i;
                int count;
                struct ip_service *ip_list;
                struct ip_service server_addr;
                struct user_auth_info u_info;
                struct cli_state *cli;

		if (share[0] != (char)0 || path[0] != (char)0) {

			errno = EINVAL;
			if (dir) {
				SAFE_FREE(dir->fname);
				SAFE_FREE(dir);
			}
			return NULL;
		}

                pstrcpy(u_info.username, user);
                pstrcpy(u_info.password, password);

		/*
                 * We have server and share and path empty but options
                 * requesting that we scan all master browsers for their list
                 * of workgroups/domains.  This implies that we must first try
                 * broadcast queries to find all master browsers, and if that
                 * doesn't work, then try our other methods which return only
                 * a single master browser.
                 */

                if (!name_resolve_bcast(MSBROWSE, 1, &ip_list, &count)) {
                        if (!find_master_ip(workgroup, &server_addr.ip)) {

                                errno = ENOENT;
                                return NULL;
                        }

                        ip_list = &server_addr;
                        count = 1;
                }

                for (i = 0; i < count; i++) {
                        DEBUG(99, ("Found master browser %s\n", inet_ntoa(ip_list[i].ip)));
                        
                        cli = get_ipc_connect_master_ip(&ip_list[i], workgroup, &u_info);
                        fstrcpy(server, cli->desthost);
                        cli_shutdown(cli);

                        DEBUG(4, ("using workgroup %s %s\n", workgroup, server));

                        /*
                         * For each returned master browser IP address, get a
                         * connection to IPC$ on the server if we do not
                         * already have one, and determine the
                         * workgroups/domains that it knows about.
                         */
                
                        srv = smbc_server(context, server,
                                          "IPC$", workgroup, user, password);
                        if (!srv) {
                                
                                if (dir) {
                                        SAFE_FREE(dir->fname);
                                        SAFE_FREE(dir);
                                }
                                return NULL;
                        }
                
                        dir->srv = srv;
                        dir->dir_type = SMBC_WORKGROUP;

                        /* Now, list the stuff ... */
                        
                        if (!cli_NetServerEnum(&srv->cli, workgroup, SV_TYPE_DOMAIN_ENUM, list_unique_wg_fn,
                                               (void *)dir)) {
                                
                                if (dir) {
                                        SAFE_FREE(dir->fname);
                                        SAFE_FREE(dir);
                                }
                                errno = cli_errno(&srv->cli);
                                
                                return NULL;
                                
                        }
                }
        } else { 
                /*
                 * Server not an empty string ... Check the rest and see what
                 * gives
                 */
		if (share[0] == (char)0) {

			if (path[0] != (char)0) { /* Should not have empty share with path */

				errno = EINVAL;
				if (dir) {
					SAFE_FREE(dir->fname);
					SAFE_FREE(dir);
				}
				return NULL;
	
			}

			/* Check to see if <server><1D>, <server><1B>, or <server><20> translates */
			/* However, we check to see if <server> is an IP address first */

			if (!is_ipaddress(server) &&  /* Not an IP addr so check next */
			    (resolve_name(server, &rem_ip, 0x1d) ||   /* Found LMB */
                                    resolve_name(server, &rem_ip, 0x1b) )) { /* Found DMB */
				fstring buserver;

				dir->dir_type = SMBC_SERVER;

				/*
				 * Get the backup list ...
				 */


				if (!name_status_find(server, 0, 0, rem_ip, buserver)) {

					DEBUG(0, ("Could not get name of local/domain master browser for server %s\n", server));
					errno = EPERM;  /* FIXME, is this correct */
					return NULL;

				}

				/*
				 * Get a connection to IPC$ on the server if we do not already have one
				 */

				srv = smbc_server(context, buserver, "IPC$", workgroup, user, password);

				if (!srv) {
				        DEBUG(0, ("got no contact to IPC$\n"));
					if (dir) {
						SAFE_FREE(dir->fname);
						SAFE_FREE(dir);
					}
					return NULL;

				}

				dir->srv = srv;

				/* Now, list the servers ... */

				if (!cli_NetServerEnum(&srv->cli, server, 0x0000FFFE, list_fn,
						       (void *)dir)) {

					if (dir) {
						SAFE_FREE(dir->fname);
						SAFE_FREE(dir);
					}
					errno = cli_errno(&srv->cli);
					return NULL;
					
				}
			}
			else {

				if (resolve_name(server, &rem_ip, 0x20)) {

					/* Now, list the shares ... */

					dir->dir_type = SMBC_FILE_SHARE;

					srv = smbc_server(context, server, "IPC$", workgroup, user, password);

					if (!srv) {

						if (dir) {
							SAFE_FREE(dir->fname);
							SAFE_FREE(dir);
						}
						return NULL;

					}

					dir->srv = srv;

					/* Now, list the servers ... */

					if (cli_RNetShareEnum(&srv->cli, list_fn, 
							      (void *)dir) < 0) {

						errno = cli_errno(&srv->cli);
						if (dir) {
							SAFE_FREE(dir->fname);
							SAFE_FREE(dir);
						}
						return NULL;

					}

				}
				else {

					errno = ENODEV;   /* Neither the workgroup nor server exists */
					if (dir) {
						SAFE_FREE(dir->fname);
						SAFE_FREE(dir);
					}
					return NULL;

				}

			}

		}
		else { /* The server and share are specified ... work from there ... */

			/* Well, we connect to the server and list the directory */

			dir->dir_type = SMBC_FILE_SHARE;

			srv = smbc_server(context, server, share, workgroup, user, password);

			if (!srv) {

				if (dir) {
					SAFE_FREE(dir->fname);
					SAFE_FREE(dir);
				}
				return NULL;

			}

			dir->srv = srv;

			/* Now, list the files ... */

			pstrcat(path, "\\*");

			if (cli_list(&srv->cli, path, aDIR | aSYSTEM | aHIDDEN, dir_list_fn, 
				     (void *)dir) < 0) {

				if (dir) {
					SAFE_FREE(dir->fname);
					SAFE_FREE(dir);
				}
				errno = smbc_errno(context, &srv->cli);
				return NULL;

			}
		}

	}

	DLIST_ADD(context->internal->_files, dir);
	return dir;

}

/*
 * Routine to close a directory
 */

static int smbc_closedir_ctx(SMBCCTX *context, SMBCFILE *dir)
{

        if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;

	}

	if (!dir || !DLIST_CONTAINS(context->internal->_files, dir)) {

		errno = EBADF;
		return -1;
    
	}

	smbc_remove_dir(dir); /* Clean it up */

	DLIST_REMOVE(context->internal->_files, dir);

	if (dir) {

		SAFE_FREE(dir->fname);
		SAFE_FREE(dir);    /* Free the space too */
	}

	return 0;

}

/*
 * Routine to get a directory entry
 */

struct smbc_dirent *smbc_readdir_ctx(SMBCCTX *context, SMBCFILE *dir)
{
	struct smbc_dirent *dirp, *dirent;

	/* Check that all is ok first ... */

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;
                DEBUG(0, ("Invalid context in smbc_readdir_ctx()\n"));
		return NULL;

	}

	if (!dir || !DLIST_CONTAINS(context->internal->_files, dir)) {

		errno = EBADF;
                DEBUG(0, ("Invalid dir in smbc_readdir_ctx()\n"));
		return NULL;

	}

	if (dir->file != False) { /* FIXME, should be dir, perhaps */

		errno = ENOTDIR;
                DEBUG(0, ("Found file vs directory in smbc_readdir_ctx()\n"));
		return NULL;

	}

	if (!dir->dir_next) {
		return NULL;
        }
	else {

		dirent = dir->dir_next->dirent;
		if (!dirent) {

			errno = ENOENT;
			return NULL;

		}

		/* Hmmm, do I even need to copy it? */

		memcpy(context->internal->_dirent, dirent, dirent->dirlen); /* Copy the dirent */
		dirp = (struct smbc_dirent *)context->internal->_dirent;
		dirp->comment = (char *)(&dirp->name + dirent->namelen + 1);
		dir->dir_next = dir->dir_next->next;

		return (struct smbc_dirent *)context->internal->_dirent;
	}

}

/*
 * Routine to get directory entries
 */

static int smbc_getdents_ctx(SMBCCTX *context, SMBCFILE *dir, struct smbc_dirent *dirp, int count)
{
	struct smbc_dir_list *dirlist;
	int rem = count, reqd;
	char *ndir = (char *)dirp;

	/* Check that all is ok first ... */

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;

	}

	if (!dir || !DLIST_CONTAINS(context->internal->_files, dir)) {

		errno = EBADF;
		return -1;
    
	}

	if (dir->file != False) { /* FIXME, should be dir, perhaps */

		errno = ENOTDIR;
		return -1;

	}

	/* 
	 * Now, retrieve the number of entries that will fit in what was passed
	 * We have to figure out if the info is in the list, or we need to 
	 * send a request to the server to get the info.
	 */

	while ((dirlist = dir->dir_next)) {
		struct smbc_dirent *dirent;

		if (!dirlist->dirent) {

			errno = ENOENT;  /* Bad error */
			return -1;

		}

		if (rem < (reqd = (sizeof(struct smbc_dirent) + dirlist->dirent->namelen + 
				   dirlist->dirent->commentlen + 1))) {

			if (rem < count) { /* We managed to copy something */

				errno = 0;
				return count - rem;

			}
			else { /* Nothing copied ... */

				errno = EINVAL;  /* Not enough space ... */
				return -1;

			}

		}

		dirent = dirlist->dirent;

		memcpy(ndir, dirent, reqd); /* Copy the data in ... */
    
		((struct smbc_dirent *)ndir)->comment = 
			(char *)(&((struct smbc_dirent *)ndir)->name + dirent->namelen + 1);

		ndir += reqd;

		rem -= reqd;

		dir->dir_next = dirlist = dirlist -> next;
	}

	if (rem == count)
		return 0;
	else 
		return count - rem;

}

/*
 * Routine to create a directory ...
 */

static int smbc_mkdir_ctx(SMBCCTX *context, const char *fname, mode_t mode)
{
	SMBCSRV *srv;
	fstring server, share, user, password, workgroup;
	pstring path;

	if (!context || !context->internal || 
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;

	}

	if (!fname) {

		errno = EINVAL;
		return -1;

	}
  
	DEBUG(4, ("smbc_mkdir(%s)\n", fname));

	if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0)) {
                errno = EINVAL;
                return -1;
        }

	if (user[0] == (char)0) fstrcpy(user, context->user);

	fstrcpy(workgroup, context->workgroup);

	srv = smbc_server(context, server, share, workgroup, user, password);

	if (!srv) {

		return -1;  /* errno set by smbc_server */

	}

	/* if (strncmp(srv->cli.dev, "IPC", 3) == 0) {

	   mode = aDIR | aRONLY;

	   }
	   else if (strncmp(srv->cli.dev, "LPT", 3) == 0) {

	   if (strcmp(path, "\\") == 0) {

	   mode = aDIR | aRONLY;

	   }
	   else {

	   mode = aRONLY;
	   smbc_stat_printjob(srv, path, &size, &m_time);
	   c_time = a_time = m_time;

	   }
	   else { */

	if (!cli_mkdir(&srv->cli, path)) {

		errno = smbc_errno(context, &srv->cli);
		return -1;

	} 

	return 0;

}

/*
 * Our list function simply checks to see if a directory is not empty
 */

static int smbc_rmdir_dirempty = True;

static void rmdir_list_fn(file_info *finfo, const char *mask, void *state)
{

	if (strncmp(finfo->name, ".", 1) != 0 && strncmp(finfo->name, "..", 2) != 0)
		smbc_rmdir_dirempty = False;

}

/*
 * Routine to remove a directory
 */

static int smbc_rmdir_ctx(SMBCCTX *context, const char *fname)
{
	SMBCSRV *srv;
	fstring server, share, user, password, workgroup;
	pstring path;

	if (!context || !context->internal || 
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;

	}

	if (!fname) {

		errno = EINVAL;
		return -1;

	}
  
	DEBUG(4, ("smbc_rmdir(%s)\n", fname));

	if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0))
        {
                errno = EINVAL;
                return -1;
        }

	if (user[0] == (char)0) fstrcpy(user, context->user);

	fstrcpy(workgroup, context->workgroup);

	srv = smbc_server(context, server, share, workgroup, user, password);

	if (!srv) {

		return -1;  /* errno set by smbc_server */

	}

	/* if (strncmp(srv->cli.dev, "IPC", 3) == 0) {

	   mode = aDIR | aRONLY;

	   }
	   else if (strncmp(srv->cli.dev, "LPT", 3) == 0) {

	   if (strcmp(path, "\\") == 0) {

	   mode = aDIR | aRONLY;

	   }
	   else {

	   mode = aRONLY;
	   smbc_stat_printjob(srv, path, &size, &m_time);
	   c_time = a_time = m_time;
	   
	   }
	   else { */

	if (!cli_rmdir(&srv->cli, path)) {

		errno = smbc_errno(context, &srv->cli);

		if (errno == EACCES) {  /* Check if the dir empty or not */

			pstring lpath; /* Local storage to avoid buffer overflows */

			smbc_rmdir_dirempty = True;  /* Make this so ... */

			pstrcpy(lpath, path);
			pstrcat(lpath, "\\*");

			if (cli_list(&srv->cli, lpath, aDIR | aSYSTEM | aHIDDEN, rmdir_list_fn,
				     NULL) < 0) {

				/* Fix errno to ignore latest error ... */

				DEBUG(5, ("smbc_rmdir: cli_list returned an error: %d\n", 
					  smbc_errno(context, &srv->cli)));
				errno = EACCES;

			}

			if (smbc_rmdir_dirempty)
				errno = EACCES;
			else
				errno = ENOTEMPTY;

		}

		return -1;

	} 

	return 0;

}

/*
 * Routine to return the current directory position
 */

static off_t smbc_telldir_ctx(SMBCCTX *context, SMBCFILE *dir)
{
	off_t ret_val; /* Squash warnings about cast */

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;

	}

	if (!dir || !DLIST_CONTAINS(context->internal->_files, dir)) {

		errno = EBADF;
		return -1;

	}

	if (dir->file != False) { /* FIXME, should be dir, perhaps */

		errno = ENOTDIR;
		return -1;

	}

	/*
	 * We return the pointer here as the offset
	 */
	ret_val = (int)dir->dir_next;
	return ret_val;

}

/*
 * A routine to run down the list and see if the entry is OK
 */

struct smbc_dir_list *smbc_check_dir_ent(struct smbc_dir_list *list, 
					 struct smbc_dirent *dirent)
{

	/* Run down the list looking for what we want */

	if (dirent) {

		struct smbc_dir_list *tmp = list;

		while (tmp) {

			if (tmp->dirent == dirent)
				return tmp;

			tmp = tmp->next;

		}

	}

	return NULL;  /* Not found, or an error */

}


/*
 * Routine to seek on a directory
 */

static int smbc_lseekdir_ctx(SMBCCTX *context, SMBCFILE *dir, off_t offset)
{
	long int l_offset = offset;  /* Handle problems of size */
	struct smbc_dirent *dirent = (struct smbc_dirent *)l_offset;
	struct smbc_dir_list *list_ent = (struct smbc_dir_list *)NULL;

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;

	}

	if (dir->file != False) { /* FIXME, should be dir, perhaps */

		errno = ENOTDIR;
		return -1;

	}

	/* Now, check what we were passed and see if it is OK ... */

	if (dirent == NULL) {  /* Seek to the begining of the list */

		dir->dir_next = dir->dir_list;
		return 0;

	}

	/* Now, run down the list and make sure that the entry is OK       */
	/* This may need to be changed if we change the format of the list */

	if ((list_ent = smbc_check_dir_ent(dir->dir_list, dirent)) == NULL) {

		errno = EINVAL;   /* Bad entry */
		return -1;

	}

	dir->dir_next = list_ent;

	return 0; 

}

/*
 * Routine to fstat a dir
 */

static int smbc_fstatdir_ctx(SMBCCTX *context, SMBCFILE *dir, struct stat *st)
{

	if (!context || !context->internal || 
	    !context->internal->_initialized) {

		errno = EINVAL;
		return -1;

	}

	/* No code yet ... */

	return 0;

}

int smbc_chmod_ctx(SMBCCTX *context, const char *fname, mode_t newmode)
{
        SMBCSRV *srv;
	fstring server, share, user, password, workgroup;
	pstring path;
	uint16 mode;

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;  /* Best I can think of ... */
		return -1;
    
	}

	if (!fname) {

		errno = EINVAL;
		return -1;

	}
  
	DEBUG(4, ("smbc_chmod(%s, 0%3o)\n", fname, newmode));

	if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0)) {
                errno = EINVAL;
                return -1;
        }

	if (user[0] == (char)0) fstrcpy(user, context->user);

	fstrcpy(workgroup, context->workgroup);

	srv = smbc_server(context, server, share, workgroup, user, password);

	if (!srv) {
		return -1;  /* errno set by smbc_server */
	}

	mode = 0;

	if (!(newmode & (S_IWUSR | S_IWGRP | S_IWOTH))) mode |= aRONLY;
	if ((newmode & S_IXUSR) && lp_map_archive(-1)) mode |= aARCH;
	if ((newmode & S_IXGRP) && lp_map_system(-1)) mode |= aSYSTEM;
	if ((newmode & S_IXOTH) && lp_map_hidden(-1)) mode |= aHIDDEN;

	if (!cli_setatr(&srv->cli, path, mode, 0)) {
		errno = smbc_errno(context, &srv->cli);
		return -1;
	}
	
        return 0;
}

int smbc_utimes_ctx(SMBCCTX *context, const char *fname, struct timeval *tbuf)
{
        SMBCSRV *srv;
	fstring server, share, user, password, workgroup;
	pstring path;
	uint16 mode;
        time_t t = (tbuf == NULL ? time(NULL) : tbuf->tv_sec);

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;  /* Best I can think of ... */
		return -1;
    
	}

	if (!fname) {

		errno = EINVAL;
		return -1;

	}
  
	DEBUG(4, ("smbc_utimes(%s, [%s])\n", fname, ctime(&t)));

	if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0)) {
                errno = EINVAL;
                return -1;
        }

	if (user[0] == (char)0) fstrcpy(user, context->user);

	fstrcpy(workgroup, context->workgroup);

	srv = smbc_server(context, server, share, workgroup, user, password);

	if (!srv) {
		return -1;  /* errno set by smbc_server */
	}

	if (!smbc_getatr(context, srv, path,
                         &mode, NULL,
                         NULL, NULL, NULL,
                         NULL)) {
                return -1;
	}

	if (!cli_setatr(&srv->cli, path, mode, t)) {
		/* some servers always refuse directory changes */
		if (!(mode & aDIR)) {
			errno = smbc_errno(context, &srv->cli);
                        return -1;
		}
	}

	return 0;
}


/* The MSDN is contradictory over the ordering of ACE entries in an ACL.
   However NT4 gives a "The information may have been modified by a
   computer running Windows NT 5.0" if denied ACEs do not appear before
   allowed ACEs. */

static int ace_compare(SEC_ACE *ace1, SEC_ACE *ace2)
{
	if (sec_ace_equal(ace1, ace2)) 
		return 0;

	if (ace1->type != ace2->type) 
		return ace2->type - ace1->type;

	if (sid_compare(&ace1->trustee, &ace2->trustee)) 
		return sid_compare(&ace1->trustee, &ace2->trustee);

	if (ace1->flags != ace2->flags) 
		return ace1->flags - ace2->flags;

	if (ace1->info.mask != ace2->info.mask) 
		return ace1->info.mask - ace2->info.mask;

	if (ace1->size != ace2->size) 
		return ace1->size - ace2->size;

	return memcmp(ace1, ace2, sizeof(SEC_ACE));
}


static void sort_acl(SEC_ACL *the_acl)
{
	uint32 i;
	if (!the_acl) return;

	qsort(the_acl->ace, the_acl->num_aces, sizeof(the_acl->ace[0]), QSORT_CAST ace_compare);

	for (i=1;i<the_acl->num_aces;) {
		if (sec_ace_equal(&the_acl->ace[i-1], &the_acl->ace[i])) {
			int j;
			for (j=i; j<the_acl->num_aces-1; j++) {
				the_acl->ace[j] = the_acl->ace[j+1];
			}
			the_acl->num_aces--;
		} else {
			i++;
		}
	}
}

/* convert a SID to a string, either numeric or username/group */
static void convert_sid_to_string(struct cli_state *ipc_cli,
                                  POLICY_HND *pol,
                                  fstring str,
                                  BOOL numeric,
                                  DOM_SID *sid)
{
	char **domains = NULL;
	char **names = NULL;
	uint32 *types = NULL;

	sid_to_string(str, sid);

        if (numeric) return;     /* no lookup desired */
        
	/* Ask LSA to convert the sid to a name */

	if (!NT_STATUS_IS_OK(cli_lsa_lookup_sids(ipc_cli, ipc_cli->mem_ctx,  
						 pol, 1, sid, &domains, 
						 &names, &types)) ||
	    !domains || !domains[0] || !names || !names[0]) {
		return;
	}

	/* Converted OK */

	slprintf(str, sizeof(fstring) - 1, "%s%s%s",
		 domains[0], lp_winbind_separator(),
		 names[0]);
}

/* convert a string to a SID, either numeric or username/group */
static BOOL convert_string_to_sid(struct cli_state *ipc_cli,
                                  POLICY_HND *pol,
                                  BOOL numeric,
                                  DOM_SID *sid,
                                  const char *str)
{
	uint32 *types = NULL;
	DOM_SID *sids = NULL;
	BOOL result = True;

        if (numeric) {
                if (strncmp(str, "S-", 2) == 0) {
                        return string_to_sid(sid, str);
                }

                result = False;
                goto done;
        }

	if (!NT_STATUS_IS_OK(cli_lsa_lookup_names(ipc_cli, ipc_cli->mem_ctx, 
						  pol, 1, &str, &sids, 
						  &types))) {
		result = False;
		goto done;
	}

	sid_copy(sid, &sids[0]);
 done:

	return result;
}


/* parse an ACE in the same format as print_ace() */
static BOOL parse_ace(struct cli_state *ipc_cli,
                      POLICY_HND *pol,
                      SEC_ACE *ace,
                      BOOL numeric,
                      char *str)
{
	char *p;
	const char *cp;
	fstring tok;
	unsigned atype, aflags, amask;
	DOM_SID sid;
	SEC_ACCESS mask;
	const struct perm_value *v;
        struct perm_value {
                const char *perm;
                uint32 mask;
        };

        /* These values discovered by inspection */
        static const struct perm_value special_values[] = {
                { "R", 0x00120089 },
                { "W", 0x00120116 },
                { "X", 0x001200a0 },
                { "D", 0x00010000 },
                { "P", 0x00040000 },
                { "O", 0x00080000 },
                { NULL, 0 },
        };

        static const struct perm_value standard_values[] = {
                { "READ",   0x001200a9 },
                { "CHANGE", 0x001301bf },
                { "FULL",   0x001f01ff },
                { NULL, 0 },
        };


	ZERO_STRUCTP(ace);
	p = strchr_m(str,':');
	if (!p) return False;
	*p = '\0';
	p++;
	/* Try to parse numeric form */

	if (sscanf(p, "%i/%i/%i", &atype, &aflags, &amask) == 3 &&
	    convert_string_to_sid(ipc_cli, pol, numeric, &sid, str)) {
		goto done;
	}

	/* Try to parse text form */

	if (!convert_string_to_sid(ipc_cli, pol, numeric, &sid, str)) {
		return False;
	}

	cp = p;
	if (!next_token(&cp, tok, "/", sizeof(fstring))) {
		return False;
	}

	if (StrnCaseCmp(tok, "ALLOWED", strlen("ALLOWED")) == 0) {
		atype = SEC_ACE_TYPE_ACCESS_ALLOWED;
	} else if (StrnCaseCmp(tok, "DENIED", strlen("DENIED")) == 0) {
		atype = SEC_ACE_TYPE_ACCESS_DENIED;
	} else {
		return False;
	}

	/* Only numeric form accepted for flags at present */

	if (!(next_token(&cp, tok, "/", sizeof(fstring)) &&
	      sscanf(tok, "%i", &aflags))) {
		return False;
	}

	if (!next_token(&cp, tok, "/", sizeof(fstring))) {
		return False;
	}

	if (strncmp(tok, "0x", 2) == 0) {
		if (sscanf(tok, "%i", &amask) != 1) {
			return False;
		}
		goto done;
	}

	for (v = standard_values; v->perm; v++) {
		if (strcmp(tok, v->perm) == 0) {
			amask = v->mask;
			goto done;
		}
	}

	p = tok;

	while(*p) {
		BOOL found = False;

		for (v = special_values; v->perm; v++) {
			if (v->perm[0] == *p) {
				amask |= v->mask;
				found = True;
			}
		}

		if (!found) return False;
		p++;
	}

	if (*p) {
		return False;
	}

 done:
	mask.mask = amask;
	init_sec_ace(ace, &sid, atype, mask, aflags);
	return True;
}

/* add an ACE to a list of ACEs in a SEC_ACL */
static BOOL add_ace(SEC_ACL **the_acl, SEC_ACE *ace, TALLOC_CTX *ctx)
{
	SEC_ACL *new;
	SEC_ACE *aces;
	if (! *the_acl) {
		(*the_acl) = make_sec_acl(ctx, 3, 1, ace);
		return True;
	}

	aces = calloc(1+(*the_acl)->num_aces,sizeof(SEC_ACE));
	memcpy(aces, (*the_acl)->ace, (*the_acl)->num_aces * sizeof(SEC_ACE));
	memcpy(aces+(*the_acl)->num_aces, ace, sizeof(SEC_ACE));
	new = make_sec_acl(ctx,(*the_acl)->revision,1+(*the_acl)->num_aces, aces);
	SAFE_FREE(aces);
	(*the_acl) = new;
	return True;
}


/* parse a ascii version of a security descriptor */
static SEC_DESC *sec_desc_parse(TALLOC_CTX *ctx,
                                struct cli_state *ipc_cli,
                                POLICY_HND *pol,
                                BOOL numeric,
                                char *str)
{
	const char *p = str;
	fstring tok;
	SEC_DESC *ret;
	size_t sd_size;
	DOM_SID *grp_sid=NULL, *owner_sid=NULL;
	SEC_ACL *dacl=NULL;
	int revision=1;

	while (next_token(&p, tok, "\t,\r\n", sizeof(tok))) {

		if (StrnCaseCmp(tok,"REVISION:", 9) == 0) {
			revision = strtol(tok+9, NULL, 16);
			continue;
		}

		if (StrnCaseCmp(tok,"OWNER:", 6) == 0) {
			owner_sid = (DOM_SID *)calloc(1, sizeof(DOM_SID));
			if (!owner_sid ||
			    !convert_string_to_sid(ipc_cli, pol,
                                                   numeric,
                                                   owner_sid, tok+6)) {
				DEBUG(5, ("Failed to parse owner sid\n"));
				return NULL;
			}
			continue;
		}

		if (StrnCaseCmp(tok,"OWNER+:", 7) == 0) {
			owner_sid = (DOM_SID *)calloc(1, sizeof(DOM_SID));
			if (!owner_sid ||
			    !convert_string_to_sid(ipc_cli, pol,
                                                   False,
                                                   owner_sid, tok+7)) {
				DEBUG(5, ("Failed to parse owner sid\n"));
				return NULL;
			}
			continue;
		}

		if (StrnCaseCmp(tok,"GROUP:", 6) == 0) {
			grp_sid = (DOM_SID *)calloc(1, sizeof(DOM_SID));
			if (!grp_sid ||
			    !convert_string_to_sid(ipc_cli, pol,
                                                   numeric,
                                                   grp_sid, tok+6)) {
				DEBUG(5, ("Failed to parse group sid\n"));
				return NULL;
			}
			continue;
		}

		if (StrnCaseCmp(tok,"GROUP+:", 7) == 0) {
			grp_sid = (DOM_SID *)calloc(1, sizeof(DOM_SID));
			if (!grp_sid ||
			    !convert_string_to_sid(ipc_cli, pol,
                                                   False,
                                                   grp_sid, tok+6)) {
				DEBUG(5, ("Failed to parse group sid\n"));
				return NULL;
			}
			continue;
		}

		if (StrnCaseCmp(tok,"ACL:", 4) == 0) {
			SEC_ACE ace;
			if (!parse_ace(ipc_cli, pol, &ace, numeric, tok+4)) {
				DEBUG(5, ("Failed to parse ACL %s\n", tok));
				return NULL;
			}
			if(!add_ace(&dacl, &ace, ctx)) {
				DEBUG(5, ("Failed to add ACL %s\n", tok));
				return NULL;
			}
			continue;
		}

		if (StrnCaseCmp(tok,"ACL+:", 5) == 0) {
			SEC_ACE ace;
			if (!parse_ace(ipc_cli, pol, &ace, False, tok+5)) {
				DEBUG(5, ("Failed to parse ACL %s\n", tok));
				return NULL;
			}
			if(!add_ace(&dacl, &ace, ctx)) {
				DEBUG(5, ("Failed to add ACL %s\n", tok));
				return NULL;
			}
			continue;
		}

		DEBUG(5, ("Failed to parse security descriptor\n"));
		return NULL;
	}

	ret = make_sec_desc(ctx, revision, SEC_DESC_SELF_RELATIVE, 
			    owner_sid, grp_sid, NULL, dacl, &sd_size);

	SAFE_FREE(grp_sid);
	SAFE_FREE(owner_sid);

	return ret;
}


/***************************************************** 
retrieve the acls for a file
*******************************************************/
static int cacl_get(TALLOC_CTX *ctx, struct cli_state *cli,
                    struct cli_state *ipc_cli, POLICY_HND *pol,
                    char *filename, char *name, char *buf, int bufsize)
{
	uint32 i;
        int n = 0;
        int n_used;
        BOOL all;
        BOOL numeric = True;
        BOOL determine_size = (bufsize == 0);
	int fnum = -1;
	SEC_DESC *sd;
	fstring sidstr;
        char *p;

	fnum = cli_nt_create(cli, filename, CREATE_ACCESS_READ);

	if (fnum == -1) {
                DEBUG(5, ("cacl_get failed to open %s: %s\n",
                          filename, cli_errstr(cli)));
                errno = 0;
		return -1;
	}

	sd = cli_query_secdesc(cli, fnum, ctx);

	if (!sd) {
                DEBUG(5, ("cacl_get Failed to query old descriptor\n"));
                errno = 0;
		return -1;
	}

	cli_close(cli, fnum);

        all = (*name == '*');
        numeric = (* (name + strlen(name) - 1) != '+');

        n_used = 0;

        if (all) {
                if (determine_size) {
                        p = talloc_asprintf(ctx,
                                            "REVISION:%d", sd->revision);
                        if (!p) {
                                errno = ENOMEM;
                                return -1;
                        }
                        n = strlen(p);
                } else {
                        n = snprintf(buf, bufsize,
                                     "REVISION:%d", sd->revision);
                }
        } else if (StrCaseCmp(name, "revision") == 0) {
                if (determine_size) {
                        p = talloc_asprintf(ctx, "%d", sd->revision);
                        if (!p) {
                                errno = ENOMEM;
                                return -1;
                        }
                        n = strlen(p);
                } else {
                        n = snprintf(buf, bufsize, "%d", sd->revision);
                }
        }
        
        if (!determine_size && n > bufsize) {
                errno = ERANGE;
                return -1;
        }
        buf += n;
        n_used += n;
        bufsize -= n;

	/* Get owner and group sid */

	if (sd->owner_sid) {
                convert_sid_to_string(ipc_cli, pol,
                                      sidstr, numeric, sd->owner_sid);
	} else {
		fstrcpy(sidstr, "");
	}

        if (all) {
                if (determine_size) {
                        p = talloc_asprintf(ctx, ",OWNER:%s", sidstr);
                        if (!p) {
                                errno = ENOMEM;
                                return -1;
                        }
                        n = strlen(p);
                } else {
                        n = snprintf(buf, bufsize, ",OWNER:%s", sidstr);
                }
        } else if (StrnCaseCmp(name, "owner", 5) == 0) {
                if (determine_size) {
                        p = talloc_asprintf(ctx, "%s", sidstr);
                        if (!p) {
                                errno = ENOMEM;
                                return -1;
                        }
                        n = strlen(p);
                } else {
                        n = snprintf(buf, bufsize, "%s", sidstr);
                }
        }

        if (!determine_size && n > bufsize) {
                errno = ERANGE;
                return -1;
        }
        buf += n;
        n_used += n;
        bufsize -= n;

	if (sd->grp_sid) {
		convert_sid_to_string(ipc_cli, pol,
                                      sidstr, numeric, sd->grp_sid);
	} else {
		fstrcpy(sidstr, "");
	}

        if (all) {
                if (determine_size) {
                        p = talloc_asprintf(ctx, ",GROUP:%s", sidstr);
                        if (!p) {
                                errno = ENOMEM;
                                return -1;
                        }
                        n = strlen(p);
                } else {
                        n = snprintf(buf, bufsize, ",GROUP:%s", sidstr);
                }
        } else if (StrnCaseCmp(name, "group", 5) == 0) {
                if (determine_size) {
                        p = talloc_asprintf(ctx, "%s", sidstr);
                        if (!p) {
                                errno = ENOMEM;
                                return -1;
                        }
                        n = strlen(p);
                } else {
                        n = snprintf(buf, bufsize, "%s", sidstr);
                }
        }

        if (!determine_size && n > bufsize) {
                errno = ERANGE;
                return -1;
        }
        buf += n;
        n_used += n;
        bufsize -= n;

	/* Add aces to value buffer  */
	for (i = 0; sd->dacl && i < sd->dacl->num_aces; i++) {

		SEC_ACE *ace = &sd->dacl->ace[i];
		convert_sid_to_string(ipc_cli, pol,
                                      sidstr, numeric, &ace->trustee);

                if (all) {
                        if (determine_size) {
                                p = talloc_asprintf(ctx, 
                                                    ",ACL:%s:%d/%d/0x%08x", 
                                                    sidstr,
                                                    ace->type,
                                                    ace->flags,
                                                    ace->info.mask);
                                if (!p) {
                                        errno = ENOMEM;
                                        return -1;
                                }
                                n = strlen(p);
                        } else {
                                n = snprintf(buf, bufsize,
                                             ",ACL:%s:%d/%d/0x%08x", 
                                             sidstr,
                                             ace->type,
                                             ace->flags,
                                             ace->info.mask);
                        }
                } else if ((StrnCaseCmp(name, "acl", 3) == 0 &&
                            StrCaseCmp(name + 3, sidstr) == 0) ||
                           (StrnCaseCmp(name, "acl+", 4) == 0 &&
                            StrCaseCmp(name + 4, sidstr) == 0)) {
                        if (determine_size) {
                                p = talloc_asprintf(ctx, 
                                                    "%d/%d/0x%08x", 
                                                    ace->type,
                                                    ace->flags,
                                                    ace->info.mask);
                                if (!p) {
                                        errno = ENOMEM;
                                        return -1;
                                }
                                n = strlen(p);
                        } else {
                                n = snprintf(buf, bufsize,
                                             "%d/%d/0x%08x", 
                                             ace->type, ace->flags, ace->info.mask);
                        }
                }
                if (n > bufsize) {
                        errno = ERANGE;
                        return -1;
                }
                buf += n;
                n_used += n;
                bufsize -= n;
	}

        if (n_used == 0) {
                errno = ENOATTR;
                return -1;
        }
	return n_used;
}


/***************************************************** 
set the ACLs on a file given an ascii description
*******************************************************/
static int cacl_set(TALLOC_CTX *ctx, struct cli_state *cli,
                    struct cli_state *ipc_cli, POLICY_HND *pol,
                    const char *filename, const char *the_acl,
                    int mode, int flags)
{
	int fnum;
        int err = 0;
	SEC_DESC *sd = NULL, *old;
        SEC_ACL *dacl = NULL;
	DOM_SID *owner_sid = NULL; 
	DOM_SID *grp_sid = NULL;
	uint32 i, j;
	size_t sd_size;
	int ret = 0;
        char *p;
        BOOL numeric = True;

        /* the_acl will be null for REMOVE_ALL operations */
        if (the_acl) {
                numeric = ((p = strchr(the_acl, ':')) != NULL &&
                           p > the_acl &&
                           p[-1] != '+');

                /* if this is to set the entire ACL... */
                if (*the_acl == '*') {
                        /* ... then increment past the first colon */
                        the_acl = p + 1;
                }

                sd = sec_desc_parse(ctx, ipc_cli, pol,
                                    numeric, (char *) the_acl);

                if (!sd) {
                        errno = EINVAL;
                        return -1;
                }
        }

	/* The desired access below is the only one I could find that works
	   with NT4, W2KP and Samba */

	fnum = cli_nt_create(cli, filename, CREATE_ACCESS_READ);

	if (fnum == -1) {
                DEBUG(5, ("cacl_set failed to open %s: %s\n",
                          filename, cli_errstr(cli)));
                errno = 0;
		return -1;
	}

	old = cli_query_secdesc(cli, fnum, ctx);

	if (!old) {
                DEBUG(5, ("cacl_set Failed to query old descriptor\n"));
                errno = 0;
		return -1;
	}

	cli_close(cli, fnum);

	switch (mode) {
	case SMBC_XATTR_MODE_REMOVE_ALL:
                old->dacl->num_aces = 0;
                SAFE_FREE(old->dacl->ace);
                SAFE_FREE(old->dacl);
                old->off_dacl = 0;
                dacl = old->dacl;
                break;

        case SMBC_XATTR_MODE_REMOVE:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			BOOL found = False;

			for (j=0;old->dacl && j<old->dacl->num_aces;j++) {
                                if (sec_ace_equal(&sd->dacl->ace[i],
                                                  &old->dacl->ace[j])) {
					uint32 k;
					for (k=j; k<old->dacl->num_aces-1;k++) {
						old->dacl->ace[k] = old->dacl->ace[k+1];
					}
					old->dacl->num_aces--;
					if (old->dacl->num_aces == 0) {
						SAFE_FREE(old->dacl->ace);
						SAFE_FREE(old->dacl);
						old->off_dacl = 0;
					}
					found = True;
                                        dacl = old->dacl;
					break;
				}
			}

			if (!found) {
                                err = ENOATTR;
                                ret = -1;
                                goto failed;
			}
		}
		break;

	case SMBC_XATTR_MODE_ADD:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			BOOL found = False;

			for (j=0;old->dacl && j<old->dacl->num_aces;j++) {
				if (sid_equal(&sd->dacl->ace[i].trustee,
					      &old->dacl->ace[j].trustee)) {
                                        if (!(flags & SMBC_XATTR_FLAG_CREATE)) {
                                                err = EEXIST;
                                                ret = -1;
                                                goto failed;
                                        }
                                        old->dacl->ace[j] = sd->dacl->ace[i];
                                        ret = -1;
					found = True;
				}
			}

			if (!found && (flags & SMBC_XATTR_FLAG_REPLACE)) {
                                err = ENOATTR;
                                ret = -1;
                                goto failed;
			}
                        
                        for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
                                add_ace(&old->dacl, &sd->dacl->ace[i], ctx);
                        }
		}
                dacl = old->dacl;
		break;

	case SMBC_XATTR_MODE_SET:
 		old = sd;
                owner_sid = old->owner_sid;
                grp_sid = old->grp_sid;
                dacl = old->dacl;
		break;

        case SMBC_XATTR_MODE_CHOWN:
                owner_sid = sd->owner_sid;
                break;

        case SMBC_XATTR_MODE_CHGRP:
                grp_sid = sd->grp_sid;
                break;
	}

	/* Denied ACE entries must come before allowed ones */
	sort_acl(old->dacl);

	/* Create new security descriptor and set it */
	sd = make_sec_desc(ctx, old->revision, SEC_DESC_SELF_RELATIVE, 
			   owner_sid, grp_sid, NULL, dacl, &sd_size);

	fnum = cli_nt_create(cli, filename,
                             WRITE_DAC_ACCESS | WRITE_OWNER_ACCESS);

	if (fnum == -1) {
		DEBUG(5, ("cacl_set failed to open %s: %s\n",
                          filename, cli_errstr(cli)));
                errno = 0;
		return -1;
	}

	if (!cli_set_secdesc(cli, fnum, sd)) {
		DEBUG(5, ("ERROR: secdesc set failed: %s\n", cli_errstr(cli)));
		ret = -1;
	}

	/* Clean up */

 failed:
	cli_close(cli, fnum);

        if (err != 0) {
                errno = err;
        }
        
	return ret;
}


int smbc_setxattr_ctx(SMBCCTX *context,
                      const char *fname,
                      const char *name,
                      const void *value,
                      size_t size,
                      int flags)
{
        int ret;
        SMBCSRV *srv;
        SMBCSRV *ipc_srv;
	fstring server, share, user, password, workgroup;
	pstring path;
        TALLOC_CTX *ctx;
        POLICY_HND pol;

	if (!context || !context->internal ||
	    !context->internal->_initialized) {

		errno = EINVAL;  /* Best I can think of ... */
		return -1;
    
	}

	if (!fname) {

		errno = EINVAL;
		return -1;

	}
  
	DEBUG(4, ("smbc_setxattr(%s, %s, %.*s)\n",
                  fname, name, (int) size, (char *) value));

	if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0)) {
                errno = EINVAL;
                return -1;
        }

	if (user[0] == (char)0) fstrcpy(user, context->user);

	fstrcpy(workgroup, context->workgroup);

	srv = smbc_server(context, server, share, workgroup, user, password);
	if (!srv) {
		return -1;  /* errno set by smbc_server */
	}

        ipc_srv = smbc_attr_server(context, server, share,
                                   workgroup, user, password,
                                   &pol);
        if (!ipc_srv) {
                return -1;
        }
        
        ctx = talloc_init("smbc_setxattr");
        if (!ctx) {
                errno = ENOMEM;
                return -1;
        }

        /*
         * Are they asking to set an access control element or to set
         * the entire access control list?
         */
        if (StrCaseCmp(name, "system.nt_sec_desc.*") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.*+") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.revision") == 0 ||
            StrnCaseCmp(name, "system.nt_sec_desc.acl", 22) == 0 ||
            StrnCaseCmp(name, "system.nt_sec_desc.acl+", 23) == 0) {

                /* Yup. */
                char *namevalue =
                        talloc_asprintf(ctx, "%s:%s", name+19, (char *) value);
                if (! namevalue) {
                        errno = ENOMEM;
                        ret = -1;
                } else {
                        ret = cacl_set(ctx, &srv->cli,
                                       &ipc_srv->cli, &pol, path,
                                       namevalue,
                                       (*namevalue == '*'
                                        ? SMBC_XATTR_MODE_SET
                                        : SMBC_XATTR_MODE_ADD),
                                       flags);
                }
                talloc_destroy(ctx);
                return ret;
        }

        /*
         * Are they asking to set the owner?
         */
        if (StrCaseCmp(name, "system.nt_sec_desc.owner") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.owner+") == 0) {

                /* Yup. */
                char *namevalue =
                        talloc_asprintf(ctx, "%s:%s", name+19, (char *) value);
                if (! namevalue) {
                        errno = ENOMEM;
                        ret = -1;
                } else {
                        ret = cacl_set(ctx, &srv->cli,
                                       &ipc_srv->cli, &pol, path,
                                       namevalue, SMBC_XATTR_MODE_CHOWN, 0);
                }
                talloc_destroy(ctx);
                return ret;
        }

        /*
         * Are they asking to set the group?
         */
        if (StrCaseCmp(name, "system.nt_sec_desc.group") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.group+") == 0) {

                /* Yup. */
                char *namevalue =
                        talloc_asprintf(ctx, "%s:%s", name+19, (char *) value);
                if (! namevalue) {
                        errno = ENOMEM;
                        ret = -1;
                } else {
                        ret = cacl_set(ctx, &srv->cli,
                                       &ipc_srv->cli, &pol, path,
                                       namevalue, SMBC_XATTR_MODE_CHOWN, 0);
                }
                talloc_destroy(ctx);
                return ret;
        }

        /* Unsupported attribute name */
        talloc_destroy(ctx);
        errno = EINVAL;
        return -1;
}

int smbc_getxattr_ctx(SMBCCTX *context,
                      const char *fname,
                      const char *name,
                      const void *value,
                      size_t size)
{
        int ret;
        SMBCSRV *srv;
        SMBCSRV *ipc_srv;
        fstring server, share, user, password, workgroup;
        pstring path;
        TALLOC_CTX *ctx;
        POLICY_HND pol;

        if (!context || !context->internal ||
            !context->internal->_initialized) {

                errno = EINVAL;  /* Best I can think of ... */
                return -1;
    
        }

        if (!fname) {

                errno = EINVAL;
                return -1;

        }
  
        DEBUG(4, ("smbc_getxattr(%s, %s)\n", fname, name));

        if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0)) {
                errno = EINVAL;
                return -1;
        }

        if (user[0] == (char)0) fstrcpy(user, context->user);

        fstrcpy(workgroup, context->workgroup);

        srv = smbc_server(context, server, share, workgroup, user, password);
        if (!srv) {
                return -1;  /* errno set by smbc_server */
        }

        ipc_srv = smbc_attr_server(context, server, share,
                                   workgroup, user, password,
                                   &pol);
        if (!ipc_srv) {
                return -1;
        }
        
        ctx = talloc_init("smbc:getxattr");
        if (!ctx) {
                errno = ENOMEM;
                return -1;
        }

        /* Are they requesting a supported attribute? */
        if (StrCaseCmp(name, "system.nt_sec_desc.*") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.*+") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.revision") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.owner") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.owner+") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.group") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.group+") == 0 ||
            StrnCaseCmp(name, "system.nt_sec_desc.acl", 22) == 0 ||
            StrnCaseCmp(name, "system.nt_sec_desc.acl+", 23) == 0) {

                /* Yup. */
                ret = cacl_get(ctx, &srv->cli,
                               &ipc_srv->cli, &pol, 
                               (char *) path, (char *) name + 19,
                               (char *) value, size);
                if (ret < 0 && errno == 0) {
                        errno = smbc_errno(context, &srv->cli);
                }
                talloc_destroy(ctx);
                return ret;
        }

        /* Unsupported attribute name */
        talloc_destroy(ctx);
        errno = EINVAL;
        return -1;
}


int smbc_removexattr_ctx(SMBCCTX *context,
                      const char *fname,
                      const char *name)
{
        int ret;
        SMBCSRV *srv;
        SMBCSRV *ipc_srv;
        fstring server, share, user, password, workgroup;
        pstring path;
        TALLOC_CTX *ctx;
        POLICY_HND pol;

        if (!context || !context->internal ||
            !context->internal->_initialized) {

                errno = EINVAL;  /* Best I can think of ... */
                return -1;
    
        }

        if (!fname) {

                errno = EINVAL;
                return -1;

        }
  
        DEBUG(4, ("smbc_removexattr(%s, %s)\n", fname, name));

        if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0)) {
                errno = EINVAL;
                return -1;
        }

        if (user[0] == (char)0) fstrcpy(user, context->user);

        fstrcpy(workgroup, context->workgroup);

        srv = smbc_server(context, server, share, workgroup, user, password);
        if (!srv) {
                return -1;  /* errno set by smbc_server */
        }

        ipc_srv = smbc_attr_server(context, server, share,
                                   workgroup, user, password,
                                   &pol);
        if (!ipc_srv) {
                return -1;
        }
        
        ipc_srv = smbc_attr_server(context, server, share,
                                   workgroup, user, password,
                                   &pol);
        if (!ipc_srv) {
                return -1;
        }
        
        ctx = talloc_init("smbc_removexattr");
        if (!ctx) {
                errno = ENOMEM;
                return -1;
        }

        /* Are they asking to set the entire ACL? */
        if (StrCaseCmp(name, "system.nt_sec_desc.*") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.*+") == 0) {

                /* Yup. */
                ret = cacl_set(ctx, &srv->cli,
                               &ipc_srv->cli, &pol, path,
                               NULL, SMBC_XATTR_MODE_REMOVE_ALL, 0);
                talloc_destroy(ctx);
                return ret;
        }

        /*
         * Are they asking to remove one or more spceific security descriptor
         * attributes?
         */
        if (StrCaseCmp(name, "system.nt_sec_desc.revision") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.owner") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.owner+") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.group") == 0 ||
            StrCaseCmp(name, "system.nt_sec_desc.group+") == 0 ||
            StrnCaseCmp(name, "system.nt_sec_desc.acl", 22) == 0 ||
            StrnCaseCmp(name, "system.nt_sec_desc.acl+", 23) == 0) {

                /* Yup. */
                ret = cacl_set(ctx, &srv->cli,
                               &ipc_srv->cli, &pol, path,
                               name + 19, SMBC_XATTR_MODE_REMOVE, 0);
                talloc_destroy(ctx);
                return ret;
        }

        /* Unsupported attribute name */
        talloc_destroy(ctx);
        errno = EINVAL;
        return -1;
}

int smbc_listxattr_ctx(SMBCCTX *context,
                       const char *fname,
                       char *list,
                       size_t size)
{
        /*
         * This isn't quite what listxattr() is supposed to do.  This returns
         * the complete set of attributes, always, rather than only those
         * attribute names which actually exist for a file.  Hmmm...
         */
        const char supported[] =
                "system.nt_sec_desc.revision\0"
                "system.nt_sec_desc.owner\0"
                "system.nt_sec_desc.owner+\0"
                "system.nt_sec_desc.group\0"
                "system.nt_sec_desc.group+\0"
                "system.nt_sec_desc.acl\0"
                "system.nt_sec_desc.acl+\0"
                "system.nt_sec_desc.*\0"
                "system.nt_sec_desc.*+\0"
                ;

        if (size == 0) {
                return sizeof(supported);
        }

        if (sizeof(supported) > size) {
                errno = ERANGE;
                return -1;
        }

        /* this can't be strcpy() because there are embedded null characters */
        memcpy(list, supported, sizeof(supported));
        return sizeof(supported);
}


/*
 * Open a print file to be written to by other calls
 */

static SMBCFILE *smbc_open_print_job_ctx(SMBCCTX *context, const char *fname)
{
        fstring server, share, user, password;
        pstring path;
        
        if (!context || !context->internal ||
            !context->internal->_initialized) {

                errno = EINVAL;
                return NULL;
    
        }

        if (!fname) {

                errno = EINVAL;
                return NULL;

        }
  
        DEBUG(4, ("smbc_open_print_job_ctx(%s)\n", fname));

        if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0)) {
                errno = EINVAL;
                return NULL;
        }

        /* What if the path is empty, or the file exists? */

        return context->open(context, fname, O_WRONLY, 666);

}

/*
 * Routine to print a file on a remote server ...
 *
 * We open the file, which we assume to be on a remote server, and then
 * copy it to a print file on the share specified by printq.
 */

static int smbc_print_file_ctx(SMBCCTX *c_file, const char *fname, SMBCCTX *c_print, const char *printq)
{
        SMBCFILE *fid1, *fid2;
        int bytes, saverr, tot_bytes = 0;
        char buf[4096];

        if (!c_file || !c_file->internal->_initialized || !c_print ||
            !c_print->internal->_initialized) {

                errno = EINVAL;
                return -1;

        }

        if (!fname && !printq) {

                errno = EINVAL;
                return -1;

        }

        /* Try to open the file for reading ... */

        if ((int)(fid1 = c_file->open(c_file, fname, O_RDONLY, 0666)) < 0) {
                
                DEBUG(3, ("Error, fname=%s, errno=%i\n", fname, errno));
                return -1;  /* smbc_open sets errno */
                
        }

        /* Now, try to open the printer file for writing */

        if ((int)(fid2 = c_print->open_print_job(c_print, printq)) < 0) {

                saverr = errno;  /* Save errno */
                c_file->close(c_file, fid1);
                errno = saverr;
                return -1;

        }

        while ((bytes = c_file->read(c_file, fid1, buf, sizeof(buf))) > 0) {

                tot_bytes += bytes;

                if ((c_print->write(c_print, fid2, buf, bytes)) < 0) {

                        saverr = errno;
                        c_file->close(c_file, fid1);
                        c_print->close(c_print, fid2);
                        errno = saverr;

                }

        }

        saverr = errno;

        c_file->close(c_file, fid1);  /* We have to close these anyway */
        c_print->close(c_print, fid2);

        if (bytes < 0) {

                errno = saverr;
                return -1;

        }

        return tot_bytes;

}

/*
 * Routine to list print jobs on a printer share ...
 */

static int smbc_list_print_jobs_ctx(SMBCCTX *context, const char *fname, smbc_list_print_job_fn fn)
{
        SMBCSRV *srv;
        fstring server, share, user, password, workgroup;
        pstring path;

        if (!context || !context->internal ||
            !context->internal->_initialized) {

                errno = EINVAL;
                return -1;

        }

        if (!fname) {
                
                errno = EINVAL;
                return -1;

        }
  
        DEBUG(4, ("smbc_list_print_jobs(%s)\n", fname));

        if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0)) {
                errno = EINVAL;
                return -1;
        }

        if (user[0] == (char)0) fstrcpy(user, context->user);
        
        fstrcpy(workgroup, context->workgroup);

        srv = smbc_server(context, server, share, workgroup, user, password);

        if (!srv) {

                return -1;  /* errno set by smbc_server */

        }

        if (cli_print_queue(&srv->cli, (void (*)(struct print_job_info *))fn) < 0) {

                errno = smbc_errno(context, &srv->cli);
                return -1;

        }
        
        return 0;

}

/*
 * Delete a print job from a remote printer share
 */

static int smbc_unlink_print_job_ctx(SMBCCTX *context, const char *fname, int id)
{
        SMBCSRV *srv;
        fstring server, share, user, password, workgroup;
        pstring path;
        int err;

        if (!context || !context->internal ||
            !context->internal->_initialized) {

                errno = EINVAL;
                return -1;

        }

        if (!fname) {

                errno = EINVAL;
                return -1;

        }
  
        DEBUG(4, ("smbc_unlink_print_job(%s)\n", fname));

        if (smbc_parse_path(context, fname,
                            server, sizeof(server),
                            share, sizeof(share),
                            path, sizeof(path),
                            user, sizeof(user),
                            password, sizeof(password),
                            NULL, 0)) {
                errno = EINVAL;
                return -1;
        }

        if (user[0] == (char)0) fstrcpy(user, context->user);

        fstrcpy(workgroup, context->workgroup);

        srv = smbc_server(context, server, share, workgroup, user, password);

        if (!srv) {

                return -1;  /* errno set by smbc_server */

        }

        if ((err = cli_printjob_del(&srv->cli, id)) != 0) {

                if (err < 0)
                        errno = smbc_errno(context, &srv->cli);
                else if (err == ERRnosuchprintjob)
                        errno = EINVAL;
                return -1;

        }

        return 0;

}

/*
 * Get a new empty handle to fill in with your own info 
 */
SMBCCTX * smbc_new_context(void)
{
        SMBCCTX * context;

        context = malloc(sizeof(SMBCCTX));
        if (!context) {
                errno = ENOMEM;
                return NULL;
        }

        ZERO_STRUCTP(context);

        context->internal = malloc(sizeof(struct smbc_internal_data));
        if (!context->internal) {
                errno = ENOMEM;
                return NULL;
        }

        ZERO_STRUCTP(context->internal);

        
        /* ADD REASONABLE DEFAULTS */
        context->debug            = 0;
        context->timeout          = 20000; /* 20 seconds */

        context->open             = smbc_open_ctx;
        context->creat            = smbc_creat_ctx;
        context->read             = smbc_read_ctx;
        context->write            = smbc_write_ctx;
        context->close            = smbc_close_ctx;
        context->unlink           = smbc_unlink_ctx;
        context->rename           = smbc_rename_ctx;
        context->lseek            = smbc_lseek_ctx;
        context->stat             = smbc_stat_ctx;
        context->fstat            = smbc_fstat_ctx;
        context->opendir          = smbc_opendir_ctx;
        context->closedir         = smbc_closedir_ctx;
        context->readdir          = smbc_readdir_ctx;
        context->getdents         = smbc_getdents_ctx;
        context->mkdir            = smbc_mkdir_ctx;
        context->rmdir            = smbc_rmdir_ctx;
        context->telldir          = smbc_telldir_ctx;
        context->lseekdir         = smbc_lseekdir_ctx;
        context->fstatdir         = smbc_fstatdir_ctx;
        context->chmod            = smbc_chmod_ctx;
        context->utimes           = smbc_utimes_ctx;
        context->setxattr         = smbc_setxattr_ctx;
        context->getxattr         = smbc_getxattr_ctx;
        context->removexattr      = smbc_removexattr_ctx;
        context->listxattr        = smbc_listxattr_ctx;
        context->open_print_job   = smbc_open_print_job_ctx;
        context->print_file       = smbc_print_file_ctx;
        context->list_print_jobs  = smbc_list_print_jobs_ctx;
        context->unlink_print_job = smbc_unlink_print_job_ctx;

        context->callbacks.check_server_fn      = smbc_check_server;
        context->callbacks.remove_unused_server_fn = smbc_remove_unused_server;

        smbc_default_cache_functions(context);

        return context;
}

/* 
 * Free a context
 *
 * Returns 0 on success. Otherwise returns 1, the SMBCCTX is _not_ freed 
 * and thus you'll be leaking memory if not handled properly.
 *
 */
int smbc_free_context(SMBCCTX * context, int shutdown_ctx)
{
        if (!context) {
                errno = EBADF;
                return 1;
        }
        
        if (shutdown_ctx) {
                SMBCFILE * f;
                DEBUG(1,("Performing aggressive shutdown.\n"));
                
                f = context->internal->_files;
                while (f) {
                        context->close(context, f);
                        f = f->next;
                }
                context->internal->_files = NULL;

                /* First try to remove the servers the nice way. */
                if (context->callbacks.purge_cached_fn(context)) {
                        SMBCSRV * s;
                        SMBCSRV * next;
                        DEBUG(1, ("Could not purge all servers, Nice way shutdown failed.\n"));
                        s = context->internal->_servers;
                        while (s) {
                                DEBUG(1, ("Forced shutdown: %p (fd=%d)\n", s, s->cli.fd));
                                cli_shutdown(&s->cli);
                                context->callbacks.remove_cached_srv_fn(context, s);
                                next = s->next;
                                DLIST_REMOVE(context->internal->_servers, s);
                                SAFE_FREE(s);
                                s = next;
                        }
                        context->internal->_servers = NULL;
                }
        }
        else {
                /* This is the polite way */    
                if (context->callbacks.purge_cached_fn(context)) {
                        DEBUG(1, ("Could not purge all servers, free_context failed.\n"));
                        errno = EBUSY;
                        return 1;
                }
                if (context->internal->_servers) {
                        DEBUG(1, ("Active servers in context, free_context failed.\n"));
                        errno = EBUSY;
                        return 1;
                }
                if (context->internal->_files) {
                        DEBUG(1, ("Active files in context, free_context failed.\n"));
                        errno = EBUSY;
                        return 1;
                }               
        }

        /* Things we have to clean up */
        SAFE_FREE(context->workgroup);
        SAFE_FREE(context->netbios_name);
        SAFE_FREE(context->user);
        
        DEBUG(3, ("Context %p succesfully freed\n", context));
        SAFE_FREE(context->internal);
        SAFE_FREE(context);
        return 0;
}


/*
 * Initialise the library etc 
 *
 * We accept a struct containing handle information.
 * valid values for info->debug from 0 to 100,
 * and insist that info->fn must be non-null.
 */
SMBCCTX * smbc_init_context(SMBCCTX * context)
{
        pstring conf;
        int pid;
        char *user = NULL, *home = NULL;

        if (!context || !context->internal) {
                errno = EBADF;
                return NULL;
        }

        /* Do not initialise the same client twice */
        if (context->internal->_initialized) { 
                return 0;
        }

        if (!context->callbacks.auth_fn || context->debug < 0 || context->debug > 100) {

                errno = EINVAL;
                return NULL;

        }

        if (!smbc_initialized) {
                /* Do some library wide intialisations the first time we get called */

                /* Set this to what the user wants */
                DEBUGLEVEL = context->debug;
                
                setup_logging( "libsmbclient", True);

                /* Here we would open the smb.conf file if needed ... */
                
                home = getenv("HOME");

                slprintf(conf, sizeof(conf), "%s/.smb/smb.conf", home);
                
                load_interfaces();  /* Load the list of interfaces ... */
                
                in_client = True; /* FIXME, make a param */

                if (!lp_load(conf, True, False, False)) {

                        /*
                         * Well, if that failed, try the dyn_CONFIGFILE
                         * Which points to the standard locn, and if that
                         * fails, silently ignore it and use the internal
                         * defaults ...
                         */

                   if (!lp_load(dyn_CONFIGFILE, True, False, False)) {
                      DEBUG(5, ("Could not load either config file: %s or %s\n",
                             conf, dyn_CONFIGFILE));
                   }
                }

                reopen_logs();  /* Get logging working ... */
        
                /* 
                 * Block SIGPIPE (from lib/util_sock.c: write())  
                 * It is not needed and should not stop execution 
                 */
                BlockSignals(True, SIGPIPE);
                
                /* Done with one-time initialisation */
                smbc_initialized = 1; 

        }
        
        if (!context->user) {
                /*
                 * FIXME: Is this the best way to get the user info? 
                 */
                user = getenv("USER");
                /* walk around as "guest" if no username can be found */
                if (!user) context->user = strdup("guest");
                else context->user = strdup(user);
        }

        if (!context->netbios_name) {
                /*
                 * We try to get our netbios name from the config. If that fails we fall
                 * back on constructing our netbios name from our hostname etc
                 */
                if (global_myname()) {
                        context->netbios_name = strdup(global_myname());
                }
                else {
                        /*
                         * Hmmm, I want to get hostname as well, but I am too lazy for the moment
                         */
                        pid = sys_getpid();
                        context->netbios_name = malloc(17);
                        if (!context->netbios_name) {
                                errno = ENOMEM;
                                return NULL;
                        }
                        slprintf(context->netbios_name, 16, "smbc%s%d", context->user, pid);
                }
        }

        DEBUG(1, ("Using netbios name %s.\n", context->netbios_name));

        if (!context->workgroup) {
                if (lp_workgroup()) {
                        context->workgroup = strdup(lp_workgroup());
                }
                else {
                        /* TODO: Think about a decent default workgroup */
                        context->workgroup = strdup("samba");
                }
        }

        DEBUG(1, ("Using workgroup %s.\n", context->workgroup));
                                        
        /* shortest timeout is 1 second */
        if (context->timeout > 0 && context->timeout < 1000) 
                context->timeout = 1000;

        /*
         * FIXME: Should we check the function pointers here? 
         */

        context->internal->_initialized = 1;
        
        return context;
}
