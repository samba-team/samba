/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

/* 
 * $Id$
 */

#ifndef __ADMIN_LOCL_H__
#define __ADMIN_LOCL_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <err.h>
#include <roken.h>
#include <krb5.h>
#include <hdb_err.h>
#include <parse_time.h>

#include "hdb.h"

extern krb5_context context;
extern char database[];
extern HDB *db;

#define DECL(X) int X(int, char **)

DECL(get_entry);
DECL(load);
DECL(merge);
DECL(add_new_key);
DECL(mod_entry);
DECL(dump);
DECL(init);
DECL(get_entry);
DECL(del_entry);
DECL(ext_keytab);
DECL(help);
DECL(exit_kdb_edit);
DECL(set_db);

/* util.c */

void init_des_key(hdb_entry *ent);
void set_keys(hdb_entry *ent, char *password);
char *time2str(time_t t);
void event2string(Event *ev, char **str);
void print_hdbflags (FILE *fp, HDBFlags flags);
int parse_hdbflags (const char *s, HDBFlags *flags);

void init_entry (HDB *db, hdb_entry *ent);
void set_created_by (hdb_entry *ent);
void set_modified_by (hdb_entry *ent);
void edit_entry(hdb_entry *ent);
int set_password(hdb_entry *ent);

/* life.c */

time_t getlife(const char *prompt, const char *def);
size_t putlife(time_t t, char *s, size_t len);

#define ALLOC(X) ((X) = malloc(sizeof(*(X))))

#endif /* __ADMIN_LOCL_H__ */
