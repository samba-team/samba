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

#include "admin_locl.h"
#include <sl.h>

static SL_cmd commands[] = {
    { "add_new_key",	add_new_key, "add_new_key principal",	"" },
    { "ank", 		NULL, NULL, 			NULL },
    { "modify_entry",	mod_entry, "modify_entry principal", "" },
    { "dump",		dump, "dump [file]",		""  },
    { "load",		load, "load file",		"" },
    { "merge",		merge, "merge file",		"" }, 
    { "help",		help, "help",			"" }, 
    { "?",		NULL, NULL,			NULL },
    { "init",		init, "init realm...",		"" },
    { "get_entry",	get_entry, "get_entry principal","" },
    { "delete",		del_entry, "delete principal", 	"" },
    { "ext_keytab",	ext_keytab, "ext_keytab principal", "" },
    { "exit",		exit_kdb_edit, "exit", "" },
    { NULL,		NULL, NULL,			NULL }
};

krb5_context context;
char *database = HDB_DEFAULT_DB;

void
help(int argc, char **argv)
{
    sl_help(commands, argc, argv);
}

void
exit_kdb_edit (int argc, char **argv)
{
    exit (0);
}

int
main(int argc, char **argv)
{
    krb5_init_context(&context);
    return sl_loop(commands, "kdb_edit> ") != 0;
}
