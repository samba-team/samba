#include "otp_locl.h"

RCSID("$Id$");

char *prog;

static void
usage ()
{
  fprintf(stderr,
	  "Usage: %s [-h] [-r] [-s] [-n count] [-f alg] num seed\n",
	  prog);
  exit (1);
}

static void
strlwr (char *s)
{
  while(*s) {
    *s = tolower(*s);
    s++;
  }
}

static int
renew (int argc, char **argv, int count, OtpAlgorithm *alg, int hexp)
{
  struct passwd *pwd;
  OtpContext oldctx, newctx, *ctx;
  char *user;
  char prompt[128];
  char pw[64];
  void *dbm;
  int ret;

  if (argc != 2)
    usage();

  pwd = getpwuid (getuid ());
  if (pwd == NULL) {
    fprintf(stderr, "%s: You don't exist\n", prog);
    return 1;
  }
  user = pwd->pw_name;
  ctx = &oldctx;
  if(otp_challenge (ctx, user, prompt, sizeof(prompt)))
    return 1;
  des_read_pw_string (pw, sizeof(pw), prompt, 0);
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
    des_read_pw_string (pw, sizeof(pw), prompt, 0);
    if (otp_parse (newctx.key, pw, alg) == 0) {
      ctx = &newctx;
    }
  }
  dbm = otp_db_open ();
  if (dbm == NULL) {
    fprintf (stderr, "%s: otp_db_open failed\n", prog);
    free (user);
    return 1;
  }
  otp_put (dbm, ctx);
  otp_db_close (dbm);
  free (user);
  return ret;
}

static int
set (int argc, char **argv, int count, OtpAlgorithm *alg, int hexp)
{
  void *db;
  OtpContext ctx;
  struct passwd *pwd;
  char pw[OTP_MAX_PASSPHRASE + 1];
  int ret;
  int i;

  if (argc != 2)
    usage();

  pwd = getpwuid (getuid ());
  if (pwd == NULL) {
    fprintf(stderr, "%s: You don't exist\n", prog);
    return 1;
  }

  ctx.alg = alg;
  ctx.user = strdup (pwd->pw_name);
  ctx.n = atoi (argv[0]);
  strncpy (ctx.seed, argv[1], sizeof(ctx.seed));
  ctx.seed[sizeof(ctx.seed) - 1] = '\0';
  strlwr(ctx.seed);
  do {
    des_read_pw_string (pw, sizeof(pw), "Pass-phrase", 1);
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

int
print (int argc, char **argv, int count, OtpAlgorithm *alg, int hexp)
{
  char pw[64];
  OtpKey key;
  int n;
  int i;
  char *seed;

  if (argc != 2)
    usage ();
  n = atoi(argv[0]);
  seed = argv[1];
  des_read_pw_string (pw, sizeof(pw), "Password: ", 0);
  alg->init (key, pw, seed);
  for (i = 0; i < n; ++i) {
    char s[30];

    alg->next (key);
    if (i >= n - count) {
      if (hexp)
	otp_print_hex (key, s);
      else
	otp_print_stddict (key, s);
      printf ("%d: %s\n", i + 1, s);
    }
  }
  return 0;
}

int
main (int argc, char **argv)
{
  int c;
  int count = 10;
  int setp = 0;
  int hexp = 0;
  int renewp = 0;
  OtpAlgorithm *alg = otp_find_alg ("md4");

  prog = argv[0];

  while ((c = getopt (argc, argv, "rshn:f:")) != EOF)
    switch (c) {
    case 'r' :
      renewp = 1;
      break;
    case 'n' :
      count = atoi (optarg);
      break;
    case 'h' :
      hexp = 1;
      break;
    case 's' :
      setp = 1;
      break;
    case 'f' :
      alg = otp_find_alg (optarg);
      if (alg == NULL) {
	fprintf (stderr, "%s: Unknown algorithm: %s\n", prog, optarg);
	return 1;
      }
      break;
    default :
      usage ();
      break;
    }
  if (setp && renewp) {
    fprintf (stderr, "%s: `-r' and `-s' incompatible\n", prog);
    return 1;
  }
  
  argc -= optind;
  argv += optind;

  if (setp)
    return set (argc, argv, count, alg, hexp);
  else if (renewp)
    return renew (argc, argv, count, alg, hexp);
  else
    return print (argc, argv, count, alg, hexp);
}
