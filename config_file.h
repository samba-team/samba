#ifndef __CONF_H__
#define __CONF_H__

enum { 
  krb5_config_value_string, 
  krb5_config_value_list 
};

struct krb5_config_relation;

typedef struct krb5_config_value{
  int type;
  union {
    char *string;
    struct krb5_config_relation *relations;
  }data;
}krb5_config_value;

typedef struct krb5_config_relation{
  char *tag;
  struct krb5_config_value value;
  struct krb5_config_relation *next;
}krb5_config_relation;

typedef struct krb5_config_section{
  char *name;
  struct krb5_config_relation *relations;
  struct krb5_config_section *next;
}krb5_config_section;

typedef struct k5_cfile{
  char *filename;
  struct krb5_config_section *sections;
}k5_cfile;



/*
static char *gettoken(FILE *F);
static void
free_config_file(k5_cfile *cf);
static krb5_error_code
new_config_file(k5_cfile **cf, const char *filename);
static void
free_config_section(krb5_config_section *sec);
static krb5_error_code
new_config_section(krb5_config_section **sec, const char *name);
static void
free_config_relation(krb5_config_relation *rel);
static void
free_config_value(krb5_config_value val);
static krb5_error_code
parse_config_file(k5_cfile **cf, const char *filename);
*/
#endif /* __CONF_H__ */
