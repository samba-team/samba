/*
 * Copyright (c) 1995, 1996 Kungliga Tekniska Högskolan (Royal Institute
 * of Technology, Stockholm, Sweden).
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

#include "otp_locl.h"

RCSID("$Id$");

static char *prog;

#define USAGE_STRING \
          "Usage: %s [-r] [-f alg] [-u user] num seed\n" \
	  "       or -[d|l] [-u user]\n" \
	  "       or -h\n"

#define HELP_STRING \
    "This program sets, renews, deletes or lists one-time passwords (OTP)\n" \
    "\tdefault: set directly OTP\n" \
    "\t-r: renew securely OTP\n" \
    "\t-d: delete OTP\n" \
    "\t-l: list OTP status\n" \
    "\t-h: help!\n" \
    "\t-u user: specify a user, default is the current user.\n" \
    "\t		only root can use this option.\n" \
    "\t-f alg: encryption algorithm (md4|md5|sha), default is md5.\n" \
    "\tnum seed: number of iterations and seed for OTP\n"

static void
help (void)
{
  fprintf(stderr, USAGE_STRING HELP_STRING, prog);
  exit (0);
}

static void
usage (void)
{
  fprintf(stderr, USAGE_STRING, prog);
  exit (1);
}

static int
renew (int argc, char **argv, OtpAlgorithm *alg, char *user)
{
  OtpContext oldctx, newctx, *ctx;
  char prompt[128];
  char pw[64];
  void *dbm;
  int ret;

  if (argc != 2)
    usage();

  ctx = &oldctx;
  if(otp_challenge (ctx, user, prompt, sizeof(prompt)))
    return 1;
  if(des_read_pw_string (pw, sizeof(pw), prompt, 0))
    return 1;
  ret = otp_verify_user_1 (ctx, pw);
  if (ret == 0) {
    newctx.alg = alg;
    newctx.user = user;
    newctx.n = atoi (argv[0]);
    strncpy (newctx.seed, argv[1], sizeof(newctx.seed));
    newctx.seed[sizeof(newctx.seed) - 1] = '\0';
    strlwr(newctx.seed);
    sprintf (prompt, "[ otp-%s %u %s ]",
	     newctx.alg->name,
	     newctx.n, 
	     newctx.seed);
    if (des_read_pw_string (pw, sizeof(pw), prompt, 0) == 0 &&
	otp_parse (newctx.key, pw, alg) == 0) {
      ctx = &newctx;
    }
  }
  dbm = otp_db_open ();
  if (dbm == NULL) {
    fprintf (stderr, "%s: otp_db_open failed\n", prog);
    return 1;
  }
  otp_put (dbm, ctx);
  otp_db_close (dbm);
  return ret;
}

static int
set (int argc, char **argv, OtpAlgorithm *alg, char *user)
{
  void *db;
  OtpContext ctx;
  char pw[OTP_MAX_PASSPHRASE + 1];
  int ret;
  int i;

  if (argc != 2)
    usage();

  ctx.alg = alg;
  ctx.user = strdup (user);
  if (ctx.user == NULL) {
    fprintf (stderr, "%s: Out of memory\n", prog);
    return 1;
  }
  ctx.n = atoi (argv[0]);
  strncpy (ctx.seed, argv[1], sizeof(ctx.seed));
  ctx.seed[sizeof(ctx.seed) - 1] = '\0';
  strlwr(ctx.seed);
  do {
    if (des_read_pw_string (pw, sizeof(pw), "Pass-phrase: ", 1))
      return 1;
    if (strlen (pw) < OTP_MIN_PASSPHRASE)
      printf ("Too short pass-phrase.  Use at least %d characters\n",
	      OTP_MIN_PASSPHRASE);
  } while(strlen(pw) < OTP_MIN_PASSPHRASE);
  ctx.alg->init (ctx.key, pw, ctx.seed);
  for (i = 0; i < ctx.n; ++i)
    ctx.alg->next (ctx.key);
  db = otp_db_open ();
  if(db == NULL) {
    fprintf (stderr, "%s: otp_db_open failed\n", prog);
    free (ctx.user);
    return 1;
  }
  ret = otp_put (db, &ctx);
  otp_db_close (db);
  free (ctx.user);
  return ret;
}

/*
 * Delete otp of user from the database
 */

static int
delete_otp (int argc, char **argv, char *user)
{
  void *db;
  OtpContext ctx;
  int ret;

  if (argc != 0) 
    usage();

  db = otp_db_open ();
  if(db == NULL) {
    fprintf (stderr, "%s: otp_db_open failed\n", prog);
    return 1;
  }

  ctx.user = user;
  ret = otp_delete(db, &ctx);
  otp_db_close (db);
  return ret;
}

/*
 * Get and print out the otp entry for some user
 */

static void
print_otp_entry_for_name (void *db, char *user)
{
  OtpContext ctx;

  ctx.user = user;
  if (!otp_simple_get(db, &ctx)) {
    fprintf(stdout, "%s\totp-%s %d %s\n", 
	    ctx.user, ctx.alg->name, ctx.n, ctx.seed);
    free(ctx.alg);
  }
}

/*
 * Print otp entries for one or all users
 */

static int
list_otps (int argc, char **argv, char *user)
{
  void *db;
  OtpContext ctx;
  struct passwd *pw;

  if (argc != 0) 
    usage();

  db = otp_db_open ();
  if(db == NULL) {
    fprintf (stderr, "%s: otp_db_open failed\n", prog);
    return 1;
  }

  if (user)
    print_otp_entry_for_name(db, user);
  else
    /* scans all users... so as to get a deterministic order */
    while ((pw = getpwent()))
      print_otp_entry_for_name(db, pw->pw_name);

  otp_db_close (db);
  return 0;
}

int
main (int argc, char **argv)
{
  int c;
  int renewp = 0, listp = 0, deletep = 0, defaultp = 0;
  int uid = getuid();
  OtpAlgorithm *alg = otp_find_alg (OTP_ALG_DEFAULT);
  char *user = NULL;
  struct passwd *pwd;

  prog = argv[0];

  while ((c = getopt (argc, argv, "hrf:u:ld")) != EOF)
    switch (c) {
    case 'h' : 
      help();
      break;
    case 'l' :
      listp = 1;
      break;
    case 'd' :
      if (uid != 0) {
	fprintf (stderr, "%s: Only root can delete OTPs\n",
		 prog);
	return 1;
      }
      deletep = 1;
      break;
    case 'r' :
      renewp = 1;
      break;
    case 'f' :
      alg = otp_find_alg (optarg);
      if (alg == NULL) {
	fprintf (stderr, "%s: Unknown algorithm: %s\n", prog, optarg);
	return 1;
      }
      break;
    case 'u' :
      if (uid != 0) {
	fprintf (stderr, "%s: Only root can use `-u'\n", prog);
	return 1;
      }
      user = optarg;
      break;
    default :
      usage ();
      break;
    }
  argc -= optind;
  argv += optind;

  if (!(listp || deletep || renewp))
    defaultp = 1;

  if ( listp + deletep + renewp + defaultp != 1) /* one of -d or -l or -r or none */
    usage();

  if (listp)
    return list_otps (argc, argv, user);

  if (user == NULL) {
    struct passwd *pwd;

    pwd = k_getpwuid(uid);
    if (pwd == NULL) {
      fprintf (stderr, "%s: You don't exist\n", prog);
      return 1;
    }
    user = pwd->pw_name;
  }
  
  if (deletep)
    return delete_otp (argc, argv, user);
  else if (renewp)
    return renew (argc, argv, alg, user);
  else
    return set (argc, argv, alg, user);
}
