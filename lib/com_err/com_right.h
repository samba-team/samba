/* $Id$ */

#ifndef __ERROR_H__
#define __ERROR_H__

struct error_table {
    char const * const * msgs;
    long base;
    int n_msgs;
};

struct error_list {
    struct error_list *next;
    const struct error_table * table;
};

#endif /* __ERROR_H__ */
