#include "krb5_locl.h"

RCSID("$Id$");

typedef struct fd_storage{
    int fd;
}fd_storage;

#define FD(S) (((fd_storage*)(S)->data)->fd)

static size_t
fd_fetch(krb5_storage *sp, void *data, size_t size)
{
    return read(FD(sp), data, size);
}

static size_t
fd_store(krb5_storage *sp, void *data, size_t size)
{
    return write(FD(sp), data, size);
}

static off_t
fd_seek(krb5_storage *sp, off_t offset, int whence)
{
    return lseek(FD(sp), offset, whence);
}

krb5_storage *
krb5_storage_from_fd(int fd)
{
    krb5_storage *sp = malloc(sizeof(krb5_storage));
    sp->data = malloc(sizeof(fd_storage));
    FD(sp) = fd;
    sp->fetch = fd_fetch;
    sp->store = fd_store;
    sp->seek = fd_seek;
    sp->free = NULL;
    return sp;
}
