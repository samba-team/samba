/* $Id$ */

#ifndef __ERROR_H__
#define __ERROR_H__

struct error_table {
    char const * const * msgs;
    long base;
    int n_msgs;
    struct error_table *next;
};

const char *com_right(struct error_table *list, long code);

#endif /* __ERROR_H__ */
