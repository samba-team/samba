/* $Id$ */

#ifndef __CONFIG_FILE_H__
#define __CONFIG_FILE_H__

struct krb5_config_binding {
    enum { STRING, LIST } type;
    char *name;
    struct krb5_config_binding *next;
    union {
	char *string;
	struct krb5_config_binding *list;
    } u;
};

typedef struct krb5_config_binding krb5_config_binding;

typedef krb5_config_binding krb5_config_section;

#if 0
struct krb5_config_section {
    char *name;
    krb5_config_binding *list;
    struct krb5_config_section *next;
};

typedef struct krb5_config_section krb5_config_section;
#endif

#endif /* __CONFIG_FILE_H__ */
