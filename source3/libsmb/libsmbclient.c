/* 
   Unix SMB/Netbios implementation.
   SMB client library implementation
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Richard Sharpe 2000, 2002
   Copyright (C) John Terpstra 2000
   Copyright (C) Tom Jansen (Ninja ISD) 2002 
   
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
    pull_utf8_allocate((void**)&new_usegment, new_segment);

    /* this assumes (very safely) that removing %aa sequences
       only shortens the string */
    strncpy(segment, new_usegment, sizeof_segment);

    free(new_usegment);
}

/*
 * Function to parse a path and turn it into components
 *
 * We accept smb://[[[domain;]user[:password@]]server[/share[/path[/file]]]]
 * 
 * smb://       means show all the workgroups
 * smb://name/  means, if name<1D> or name<1B> exists, list servers in workgroup,
 *              else, if name<20> exists, list all shares for server ...
 */

static const char *smbc_prefix = "smb:";

static int
smbc_parse_path(SMBCCTX *context, const char *fname, char *server, char *share, char *path,
		char *user, char *password) /* FIXME, lengths of strings */
{
	static pstring s;
	pstring userinfo;
	const char *p;
	char *q, *r;
	int len;

	server[0] = share[0] = path[0] = user[0] = password[0] = (char)0;
	pstrcpy(s, fname);

	/*  clean_fname(s);  causing problems ... */

	/* see if it has the right prefix */
	len = strlen(smbc_prefix);
	if (strncmp(s,smbc_prefix,len) || 
	    (s[len] != '/' && s[len] != 0)) return -1; /* What about no smb: ? */

	p = s + len;

	/* Watch the test below, we are testing to see if we should exit */

	if (strncmp(p, "//", 2) && strncmp(p, "\\\\", 2)) {

		return -1;

	}

	p += 2;  /* Skip the // or \\  */

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
			strncpy(user, username, sizeof(fstring));  /* FIXME, size and domain */

		if (passwd[0])
			strncpy(password, passwd, sizeof(fstring)); /* FIXME, size */

	}

	if (!next_token(&p, server, "/", sizeof(fstring))) {

		return -1;

	}

	if (*p == (char)0) goto decoding;  /* That's it ... */
  
	if (!next_token(&p, share, "/", sizeof(fstring))) {

		return -1;

	}

	pstrcpy(path, p);

	all_string_sub(path, "/", "\\", 0);

 decoding:
	decode_urlpart(path, sizeof(pstring));
	decode_urlpart(server, sizeof(fstring));
	decode_urlpart(share, sizeof(fstring));
	decode_urlpart(user, sizeof(fstring));
	decode_urlpart(password, sizeof(fstring));

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
	int auth_called = 0;
	struct cli_state c;
	struct nmb_name called, calling;
	char *p;
	const char *server_n = server;
	fstring group;
	pstring ipenv;
	struct in_addr ip;
	int tried_reverse = 0;
  
	zero_ip(&ip);
	ZERO_STRUCT(c);

	if (server[0] == 0) {
		errno = EPERM;
		return NULL;
	}

 check_server_cache:

	srv = context->callbacks.get_cached_srv_fn(context, server, share, 
						   workgroup, username);
	
	if (!auth_called && !srv && (!username[0] || !password[0])) {
		context->callbacks.auth_fn(server, share, workgroup, sizeof(fstring),
 			     username, sizeof(fstring), password, sizeof(fstring));
		/* 
		 * However, smbc_auth_fn may have picked up info relating to an 
		 * existing connection, so try for an existing connection again ...
		 */
		auth_called = 1;
		goto check_server_cache;
		
	}
	
	if (srv) {
		if (context->callbacks.check_server_fn(context, srv)) {
			/* 
			 * This server is no good anymore 
			 * Try to remove it and check for more possible servers in the cache 
			 */
			if (context->callbacks.remove_unused_server_fn(context, srv)) { 
				/* 
				 * We could not remove the server completely, remove it from the cache
				 * so we will not get it again. It will be removed when the last file/dir
				 * is closed.
				 */
				context->callbacks.remove_cached_srv_fn(context, srv);
			}
			
			/* 
			 * Maybe there are more cached connections to this server 
			 */
			goto check_server_cache; 
		}
		return srv;
 	}

	make_nmb_name(&calling, context->netbios_name, 0x0);
	make_nmb_name(&called , server, 0x20);

	DEBUG(4,("smbc_server: server_n=[%s] server=[%s]\n", server_n, server));
  
	if ((p=strchr_m(server_n,'#')) && 
	    (strcmp(p+1,"1D")==0 || strcmp(p+1,"01")==0)) {
    
		fstrcpy(group, server_n);
		p = strchr_m(group,'#');
		*p = 0;
		
	}

	DEBUG(4,(" -> server_n=[%s] server=[%s]\n", server_n, server));

 again:
	slprintf(ipenv,sizeof(ipenv)-1,"HOST_%s", server_n);

	zero_ip(&ip);

	/* have to open a new connection */
	if (!cli_initialise(&c)) {
		errno = ENOENT;
		return NULL;
	}

	c.timeout = context->timeout;

	if (!cli_connect(&c, server_n, &ip)) {
		cli_shutdown(&c);
 		errno = ENOENT;
 		return NULL;
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

	return srv;

 failed:
	cli_shutdown(&c);
	if (!srv) return NULL;
  
	SAFE_FREE(srv);
	return NULL;
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

	smbc_parse_path(context, fname, server, share, path, user, password); /* FIXME, check errors */

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
	if (srv->cli.capabilities & CAP_NT_SMBS) return False;

	if (cli_getatr(&srv->cli, path, mode, size, m_time)) {
		a_time = c_time = m_time;
		srv->no_pathinfo2 = True;
		return True;
	}

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

	smbc_parse_path(context, fname, server, share, path, user, password); /* FIXME, check errors */

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

	smbc_parse_path(ocontext, oname, server1, share1, path1, user1, password1);

	if (user1[0] == (char)0) fstrcpy(user1, ocontext->user);

	smbc_parse_path(ncontext, nname, server2, share2, path2, user2, password2);

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
	st->st_blksize = 512;
	st->st_blocks = (size+511)/512;
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

	smbc_parse_path(context, fname, server, share, path, user, password); /*FIXME, errors*/

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
 *
 * We want to allow:
 *
 * smb: which should list all the workgroups available
 * smb:workgroup
 * smb:workgroup//server
 * smb://server
 * smb://server/share
 * smb://<IP-addr> which should list shares on server
 * smb://<IP-addr>/share which should list files on share
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
	fstring server, share, user, password;
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

	if (smbc_parse_path(context, fname, server, share, path, user, password)) {
	        DEBUG(4, ("no valid path\n"));
		errno = EINVAL;
		return NULL;
	}

	DEBUG(4, ("parsed path: fname='%s' server='%s' share='%s' path='%s'\n", fname, server, share, path));

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

	if (server[0] == (char)0) {
	    struct in_addr server_ip;
		if (share[0] != (char)0 || path[0] != (char)0) {

			errno = EINVAL;
			if (dir) {
				SAFE_FREE(dir->fname);
				SAFE_FREE(dir);
			}
			return NULL;
		}

		/* We have server and share and path empty ... so list the workgroups */
                /* first try to get the LMB for our workgroup, and if that fails,     */
                /* try the DMB                                                        */

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
		    if (!name_status_find("*", 0, 0, server_ip, server)) {
			errno = ENOENT;
			return NULL;
		    }
		}	

		DEBUG(4, ("using workgroup %s %s\n", workgroup, server));

               /*
                * Get a connection to IPC$ on the server if we do not already have one
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

			if (dir) {
				SAFE_FREE(dir->fname);
				SAFE_FREE(dir);
			}
			errno = cli_errno(&srv->cli);

			return NULL;

		}
	}
	else { /* Server not an empty string ... Check the rest and see what gives */

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
				pstring buserver;

				dir->dir_type = SMBC_SERVER;

				/*
				 * Get the backup list ...
				 */


				if (!name_status_find("*", 0, 0, rem_ip, buserver)) {

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
		return NULL;

	}

	if (!dir || !DLIST_CONTAINS(context->internal->_files, dir)) {

		errno = EBADF;
		return NULL;

	}

	if (dir->file != False) { /* FIXME, should be dir, perhaps */

		errno = ENOTDIR;
		return NULL;

	}

	if (!dir->dir_next)
		return NULL;
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

	smbc_parse_path(context, fname, server, share, path, user, password); /*FIXME, errors*/

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

	smbc_parse_path(context, fname, server, share, path, user, password); /*FIXME, errors*/

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

	smbc_parse_path(context, fname, server, share, path, user, password); /*FIXME, errors*/

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

	smbc_parse_path(context, fname, server, share, path, user, password); /*FIXME, errors*/

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

	smbc_parse_path(context, fname, server, share, path, user, password); /*FIXME, errors*/

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
			DEBUG(1, ("Could not purge all servers, Nice way shutdown failed.\n"));
			s = context->internal->_servers;
			while (s) {
				cli_shutdown(&s->cli);
				context->callbacks.remove_cached_srv_fn(context, s);
				SAFE_FREE(s);
				s = s->next;
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
