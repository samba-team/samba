#ifndef _CHECK_GEN_H
#define _CHECK_GEN_H
typedef struct my_vers_s {
    int v;
} my_vers;

int my_copy_vers(const my_vers *, my_vers *);
void my_free_vers(my_vers *);
#endif /* _CHECK_GEN_H */
