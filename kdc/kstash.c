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

#include "kdc_locl.h"

RCSID("$Id$");

char *keyfile = "m-key";
int help;

struct getargs args[] = {
    { "key-file", 'k', arg_string, &keyfile, "Master key file", "file" },
    { "help", 'h', arg_flag, &help }
};

int num_args = sizeof(args) / sizeof(args[0]);

int main(int argc, char **argv)
{
    char buf[1024];
    EncryptionKey key;
    FILE *f;
    size_t len;
    int optind = 0;

    set_progname(argv[0]);

    if(getarg(args, num_args, argc, argv, &optind)){
	arg_printusage (args, num_args, "");
	exit(1);
    }

    if(help){
	arg_printusage (args, num_args, "");
	exit(0);
    }

    des_read_pw_string(buf, sizeof(buf), "Master key: ", 1);
    key.keytype = KEYTYPE_DES;
    key.keyvalue.length = sizeof(des_cblock);
    key.keyvalue.data = malloc(key.keyvalue.length);
    des_string_to_key(buf, key.keyvalue.data);
    
#ifdef HAVE_UMASK
    umask(077);
#endif

    f = fopen(keyfile, "w");
    if(f == NULL)
	err(1, "Failed to open %s", keyfile);
    encode_EncryptionKey(buf + sizeof(buf) - 1, sizeof(buf), &key, &len);
    fwrite(buf + sizeof(buf) - len, len, 1, f);
    fclose(f);
    exit(0);
}
