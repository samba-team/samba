#include "krb5_locl.h"

RCSID("$Id$");

typedef struct emem_storage{
    unsigned char *base;
    size_t size;
    size_t len;
    unsigned char *ptr;
}emem_storage;

static size_t
emem_fetch(krb5_storage *sp, void *data, size_t size)
{
    emem_storage *s = (emem_storage*)sp->data;
    if(s->base + s->len - s->ptr < size)
	size = s->base + s->len - s->ptr;
    memmove(data, s->ptr, size);
    sp->seek(sp, size, SEEK_CUR);
    return size;
}

static size_t
emem_store(krb5_storage *sp, void *data, size_t size)
{
    emem_storage *s = (emem_storage*)sp->data;
    if(size > s->base + s->size - s->ptr){
	s->size = 2 * (size + (s->ptr - s->base)); /* XXX */
	s->base = realloc(s->base, s->size);
    }
    memmove(s->ptr, data, size);
    sp->seek(sp, size, SEEK_CUR);
    return size;
}

static off_t
emem_seek(krb5_storage *sp, off_t offset, int whence)
{
    emem_storage *s = (emem_storage*)sp->data;
    switch(whence){
    case SEEK_SET:
	if(offset > s->size)
	    offset = s->size;
	if(offset < 0)
	    offset = 0;
	s->ptr = s->base + offset;
	if(offset > s->len)
	    s->len = offset;
	break;
    case SEEK_CUR:
	sp->seek(sp,s->ptr - s->base + offset, SEEK_SET);
	break;
    case SEEK_END:
	sp->seek(sp, s->len + offset, SEEK_SET);
	break;
    default:
	errno = EINVAL;
	return -1;
    }
    return s->ptr - s->base;
}

static void
emem_free(krb5_storage *sp)
{
    free(((emem_storage*)sp->data)->base);
}

krb5_storage *
krb5_storage_emem(void)
{
    krb5_storage *sp = malloc(sizeof(krb5_storage));
    emem_storage *s = malloc(sizeof(*s));
    sp->data = s;
    s->size = 1024;
    s->base = malloc(s->size);
    s->len = 0;
    s->ptr = s->base;
    sp->fetch = emem_fetch;
    sp->store = emem_store;
    sp->seek = emem_seek;
    sp->free = emem_free;
    return sp;
}
