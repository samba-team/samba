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

#include "kuser_locl.h"
RCSID("$Id$");

static void
usage (void)
{
    errx (1, "Usage: %s [-f] [-p] [principal]", __progname);
}

int
main (int argc, char **argv)
{
  krb5_error_code err;
  krb5_context context;
  krb5_ccache  ccache;
  krb5_principal principal;
  krb5_principal server;
  krb5_creds cred;
  krb5_preauthtype pre_auth_types[] = {KRB5_PADATA_ENC_TIMESTAMP};
  int c;
  char *realm;
  int preauth = 1;

  union {
      krb5_flags i;
      KDCOptions f;
  }options;

  set_progname (argv[0]);
  options.i = 0;
  while ((c = getopt (argc, argv, "fp")) != EOF) {
      switch (c) {
      case 'f':
	  options.f.forwardable = 1;
	  break;
      case 'p':
	  preauth = 0;
	  break;
      default:
	  usage ();
      }
  }
  argc -= optind;
  argv += optind;

  err = krb5_init_context (&context);
  if (err)
      errx (1, "krb5_init_context: %s", krb5_get_err_text(context, err));
  
  err = krb5_cc_default (context, &ccache);
  if (err)
      errx (1, "krb5_cc_default: %s", krb5_get_err_text(context, err));
  
  err = krb5_get_default_realm (context, &realm);
  if (err)
      errx (1, "krb5_get_default_realm: %s",
	    krb5_get_err_text(context, err));

  if(argv[0]){
      char *p;
      err = krb5_parse_name (context, argv[0], &principal);
      if (err)
	  errx (1, "krb5_parse_name: %s", krb5_get_err_text(context, err));
      krb5_unparse_name(context, principal, &p);
      fprintf (stderr, "%s's ", p);
      free(p);
  }else{
      struct passwd *pw;

      pw = getpwuid(getuid());
      err = krb5_build_principal(context, &principal,
				 strlen(realm), realm,
				 pw->pw_name, NULL);
      if (err)
	  errx (1, "krb5_build_principal: %s",
		krb5_get_err_text(context, err));
      fprintf (stderr, "%s@%s's ", pw->pw_name, realm);
  }
  free(realm);

  err = krb5_cc_initialize (context, ccache, principal);
  if (err)
      errx (1, "krb5_cc_initialize: %s",
	    krb5_get_err_text(context, err));

  memset(&cred, 0, sizeof(cred));
  cred.client = principal;
  cred.times.endtime = 0;

  err = krb5_build_principal_ext (context,
				  &server,
				  strlen(principal->realm),
				  principal->realm,
				  strlen("krbtgt"),
				  "krbtgt",
				  strlen(principal->realm),
				  principal->realm,
				  NULL);
  if (err)
      errx (1, "krb5_build_principal_ext: %s",
	    krb5_get_err_text(context, err));

  server->name.name_type = KRB5_NT_SRV_INST;

  cred.client = principal;
  cred.server = server;
  cred.times.endtime = 0;

  err = krb5_get_in_tkt_with_password (context,
				       options.i,
				       NULL,
				       NULL,
				       preauth ? pre_auth_types : NULL,
				       NULL,
				       ccache,
				       &cred,
				       NULL);
  if (err)
      errx (1, "krb5_get_in_tkt_with_password: %s",
	    krb5_get_err_text(context, err));
  
  krb5_free_principal (context, principal);
  krb5_free_principal (context, server);
  krb5_free_ccache (context, ccache);
  krb5_free_context (context);
  return 0;
}
