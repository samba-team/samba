/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of the Institute nor the names of its contributors 
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

#include "hx_locl.h"
RCSID("$Id$");
#include <dirent.h>

static int
dir_init(hx509_context context,
	 hx509_certs certs, void **data, int flags, 
	 const char *residue, hx509_lock lock)
{
    *data = NULL;

    {
	struct stat sb;
	int ret;

	ret = stat(residue, &sb);
	if (ret == -1)
	    return ENOENT;

	if ((sb.st_mode & S_IFDIR) == 0)
	    return EINVAL;
    }

    *data = strdup(residue);
    if (*data == NULL)
	return ENOMEM;

    return 0;
}

static int
dir_free(hx509_certs certs, void *data)
{
    free(data);
    return 0;
}



static int 
dir_iter_start(hx509_context context,
	       hx509_certs certs, void *data, void **cursor)
{
    DIR *d;

    d = opendir(data);
    if (d == NULL) {
	*cursor = 0;
	return 0;
    }

    *cursor = d;
    return 0;
}

static int
dir_iter(hx509_context context,
	 hx509_certs certs, void *data, void *iter, hx509_cert *cert)
{
    DIR *d = iter;
    int ret;
    
    *cert = NULL;

    do {
	struct dirent *dir;
	char *fn;

	dir = readdir(d);
	if (dir == NULL)
	    return 0;
	
	if (asprintf(&fn, "%s/%s", (char *)data, dir->d_name) == -1)
	    return ENOMEM;
	
	ret = _hx509_file_to_cert(context, fn, cert);
	free(fn);
    } while(ret != 0);

    return ret;
}


static int
dir_iter_end(hx509_context context,
	     hx509_certs certs,
	     void *data,
	     void *cursor)
{
    DIR *d = cursor;
    closedir(d);
    return 0;
}


static struct hx509_keyset_ops keyset_dir = {
    "DIR",
    0,
    dir_init,
    dir_free,
    NULL,
    NULL,
    dir_iter_start,
    dir_iter,
    dir_iter_end
};

void
_hx509_ks_dir_register(hx509_context context)
{
    _hx509_ks_register(context, &keyset_dir);
}
