#include "krb5_locl.h"

RCSID("$Id$");

typedef struct mem_storage{
    unsigned char *base;
    size_t size;
    unsigned char *ptr;
}mem_storage;

static size_t
mem_fetch(krb5_storage *sp, void *data, size_t size)
{
    mem_storage *s = (mem_storage*)sp->data;
    if(size > s->base + s->size - s->ptr)
	size = s->base + s->size - s->ptr;
    memmove(data, s->ptr, size);
    sp->seek(sp, size, SEEK_CUR);
    return size;
}

size_t
mem_store(krb5_storage *sp, void *data, size_t size)
{
    mem_storage *s = (mem_storage*)sp->data;
    if(size > s->base + s->size - s->ptr)
	size = s->base + s->size - s->ptr;
    memmove(s->ptr, data, size);
    sp->seek(sp, size, SEEK_CUR);
    return size;
}

off_t
mem_seek(krb5_storage *sp, off_t offset, int whence)
{
    mem_storage *s = (mem_storage*)sp->data;
    switch(whence){
    case SEEK_SET:
	if(offset > s->size)
	    offset = s->size;
	if(offset < 0)
	    offset = 0;
	s->ptr = s->base + offset;
	break;
    case SEEK_CUR:
	sp->seek(sp, s->ptr - s->base + offset, SEEK_SET);
	break;
    case SEEK_END:
	sp->seek(sp, s->size + offset, SEEK_SET);
    default:
	errno = EINVAL;
	return -1;
    }
    return s->ptr - s->base;
}

krb5_storage *
krb5_storage_from_mem(void *buf, size_t len)
{
    krb5_storage *sp = malloc(sizeof(krb5_storage));
    mem_storage *s = malloc(sizeof(*s));
    sp->data = s;
    s->base = buf;
    s->size = len;
    s->ptr = buf;
    sp->fetch = mem_fetch;
    sp->store = mem_store;
    sp->seek = mem_seek;
    sp->free = NULL;
    return sp;
}


