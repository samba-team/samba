/*
 * $Id$
 */

#ifndef __KRB5_ERROR_H__
#define __KRB5_ERROR_H__

struct error_table {
    char const * const * msgs;
    long base;
    int n_msgs;
};

struct error_list {
    struct error_list *next;
    const struct error_table * table;
};

const char *krb5_get_err_text(krb5_context context, long code);

#endif /* __KRB5_ERROR_H__ */
