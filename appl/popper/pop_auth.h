#ifndef __pop_auth_h__
#define __pop_auth_h__

struct auth_mech {
    const char *name;
    int (*init)(POP*, void**);
    int (*loop)(POP*, void*, void*, size_t, void**, size_t*);
    int (*cleanup)(POP*, void*);
};

#define POP_AUTH_CONTINUE	0
#define POP_AUTH_FAILURE	1
#define POP_AUTH_COMPLETE	2

void pop_auth_set_error(const char *message);

#ifdef KRB5
extern struct auth_mech gssapi_mech;
#endif
#ifdef KRB4
extern struct auth_mech krb4_mech;
#endif


#endif /* __pop_auth_h__ */
