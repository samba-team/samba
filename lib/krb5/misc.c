#include "krb5_locl.h"


krb5_error_code
krb5_get_lrealm(char **realm)
{
  FILE *F;
  char s[128];
  char *p, *q;
  F = fopen("/etc/krb5.conf", "r");
  while(fgets(s, 128, F)){
    if((p = strstr(s, "default_realm"))){
      p = strchr(p, '=');
      p++;
      while(isspace(*p)) p++;
      q = p;
      while(isalnum(*p) || strchr("_.-", *p)) p++;
      *p=0;
      *realm = strdup(q);
      fclose(F);
      return 0;
    }
  }
  fclose(F);
  *realm = 0;
  return 0;
}
