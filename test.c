#include <stdio.h>
#include "krb5.h"
#include "config_file.h"

int main(int argc, char **argv)
{
  k5_cfile *cf;
  char *p;
  krb5_parse_config_file(&cf, "krb5.conf");
  krb5_get_config_tag(cf, "realms ATHENA.MIT.EDU v4_instance_convert mit", &p);

  return 0;
}
