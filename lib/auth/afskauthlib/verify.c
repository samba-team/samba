/*
 * Copyright (c) 1995, 1996, 1997, 1998, 1999 Kungliga Tekniska Högskolan
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
 *      This product includes software developed by the Kungliga Tekniska
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

#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <krb.h>
#include <kafs.h>
#include <roken.h>

/*
 *
 */

int
afs_verify(char *name,
	   char *password,
	   int32_t *exp,
	   int quiet)
{
  int ret = 1;
  char lrealm[REALM_SZ];
  char tkt_string[MaxPathLen];
  struct passwd *pwd;

  if (krb_get_lrealm (lrealm, 1) != KFAILURE &&
      (pwd = k_getpwnam (name)) != NULL) {
    snprintf (tkt_string, sizeof(tkt_string),
	      "%s%d_%d", TKT_ROOT,
	      (unsigned)pwd->pw_uid, (unsigned)getpid());
    krb_set_tkt_string (tkt_string);
    ret = krb_verify_user (name, "", lrealm, password,
			   KRB_VERIFY_SECURE, NULL);
    if (ret == KSUCCESS) {
      if (k_hasafs()) {
	k_setpag ();
	krb_afslog_uid_home (0, 0, pwd->pw_uid, pwd->pw_dir);
      }
    } else if (!quiet)
      printf ("%s\n", krb_get_err_text (ret));
  }
  if (ret)
    ret = unix_verify_user (name, password);

  return ret;
}

char *
afs_gettktstring (void)
{
  return tkt_string ();
}
