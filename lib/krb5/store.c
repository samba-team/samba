#include "krb5_locl.h"

RCSID("$Id$");

struct krb5_fd_storage{
    int fd;
};

#define FD(S) (((struct krb5_fd_storage*)(S)->data)->fd)

struct krb5_mem_storage{
    void *base;
    size_t len;
    void *ptr;
};

#define MEM(S) ((struct krb5_mem_storage*)((S)->data))

size_t
fd_fetch(krb5_storage *sp, void *data, size_t size)
{
    return read(FD(sp), data, size);
}

size_t
fd_store(krb5_storage *sp, void *data, size_t size)
{
    return write(FD(sp), data, size);
}

off_t
fd_seek(krb5_storage *sp, off_t offset, int whence)
{
    return lseek(FD(sp), offset, whence);
}

size_t
mem_fetch(krb5_storage *sp, void *data, size_t size)
{
    memmove(data, MEM(sp)->ptr, size);
    sp->seek(sp, size, SEEK_CUR);
    return size;
}

size_t
mem_store(krb5_storage *sp, void *data, size_t size)
{
    memmove(MEM(sp)->ptr, data, size);
    sp->seek(sp, size, SEEK_CUR);
    return size;
}

off_t
mem_seek(krb5_storage *sp, off_t offset, int whence)
{
    switch(whence){
    case SEEK_SET:
	if(offset > MEM(sp)->len)
	    offset = MEM(sp)->len;
	if(offset < 0)
	    offset = 0;
	MEM(sp)->ptr = (char*)(MEM(sp)->base) + offset;
	break;
    case SEEK_CUR:
	sp->seek(sp,
		 (char *)MEM(sp)->ptr - (char *)MEM(sp)->base + offset,
		 SEEK_SET);
	break;
    case SEEK_END:
	sp->seek(sp, MEM(sp)->len + offset, SEEK_SET);
    default:
	errno = EINVAL;
	return -1;
    }
    return (char *)MEM(sp)->ptr - (char *)MEM(sp)->base;
}

krb5_storage *
krb5_storage_from_fd(int fd)
{
    krb5_storage *sp = malloc(sizeof(krb5_storage));
    sp->data = malloc(sizeof(struct krb5_fd_storage));
    FD(sp) = fd;
    sp->fetch = fd_fetch;
    sp->store = fd_store;
    sp->seek = fd_seek;
    return sp;
}

krb5_storage *
krb5_storage_from_mem(void *buf, size_t len)
{
    krb5_storage *sp = malloc(sizeof(krb5_storage));
    sp->data = malloc(sizeof(struct krb5_mem_storage));
    MEM(sp)->base = buf;
    MEM(sp)->len = len;
    MEM(sp)->ptr = buf;
    sp->fetch = mem_fetch;
    sp->store = mem_store;
    sp->seek = mem_seek;
    return sp;
}

krb5_error_code
krb5_storage_free(krb5_storage *sp)
{
    free(sp->data);
    free(sp);
    return 0;
}


krb5_error_code
krb5_store_int32(krb5_storage *sp,
		 int32_t value)
{
    int ret;

    value = htonl(value);
    ret = sp->store(sp, &value, sizeof(value));
    if (ret != sizeof(value))
	return (ret<0)?errno:KRB5_CC_END;
    return 0;
}

krb5_error_code
krb5_ret_int32(krb5_storage *sp,
	       int32_t *value)
{
    int32_t v;
    int ret;
    ret = sp->fetch(sp, &v, sizeof(v));
    if(ret != sizeof(v))
	return (ret<0)?errno:KRB5_CC_END;

    *value = ntohl(v);
    return 0;
}

krb5_error_code
krb5_store_int16(krb5_storage *sp,
		 int16_t value)
{
    int ret;

    value = htons(value);
    ret = sp->store(sp, &value, sizeof(value));
    if (ret != sizeof(value))
	return (ret<0)?errno:KRB5_CC_END;
    return 0;
}

krb5_error_code
krb5_ret_int16(krb5_storage *sp,
	       int16_t *value)
{
    int16_t v;
    int ret;
    ret = sp->fetch(sp, &v, sizeof(v));
    if(ret != sizeof(v))
	return (ret<0)?errno:KRB5_CC_END; /* XXX */
  
    *value = ntohs(v);
    return 0;
}

krb5_error_code
krb5_store_int8(krb5_storage *sp,
		int8_t value)
{
    int ret;

    ret = sp->store(sp, &value, sizeof(value));
    if (ret != sizeof(value))
	return (ret<0)?errno:KRB5_CC_END;
    return 0;
}

krb5_error_code
krb5_ret_int8(krb5_storage *sp,
	      int8_t *value)
{
    int ret;

    ret = sp->fetch(sp, value, sizeof(*value));
    if (ret != sizeof(*value))
	return (ret<0)?errno:KRB5_CC_END;
    return 0;
}

krb5_error_code
krb5_store_data(krb5_storage *sp,
		krb5_data data)
{
    int ret;
    ret = krb5_store_int32(sp, data.length);
    if(ret < 0)
	return ret;
    ret = sp->store(sp, data.data, data.length);
    if(ret != data.length){
	if(ret < 0)
	    return errno;
	return KRB5_CC_END;
    }
    return 0;
}

krb5_error_code
krb5_ret_data(krb5_storage *sp,
	      krb5_data *data)
{
    int ret;
    int size;
    ret = krb5_ret_int32(sp, &size);
    if(ret)
	return ret;
    data->length = size;
    data->data = malloc(size);
    ret = sp->fetch(sp, data->data, size);
    if(ret != size)
	return (ret < 0)? errno : KRB5_CC_END;
    return 0;
}


krb5_error_code
krb5_store_principal(krb5_storage *sp,
		     krb5_principal p)
{
    int i;
    int ret;
    ret = krb5_store_int32(sp, p->type);
    if(ret) return ret;
    ret = krb5_store_int32(sp, p->ncomp);
    if(ret) return ret;
    ret = krb5_store_data(sp, p->realm);
    if(ret) return ret;
    for(i = 0; i < p->ncomp; i++){
	ret = krb5_store_data(sp, p->comp[i]);
	if(ret) return ret;
    }
    return 0;
}

krb5_error_code
krb5_ret_principal(krb5_storage *sp,
		   krb5_principal *princ)
{
    int i;
    int ret;
    krb5_principal p;

    p = ALLOC(1, krb5_principal_data);
    if(p == NULL)
	return ENOMEM;

    if((ret = krb5_ret_int32(sp, &p->type)))
	return ret;
    ret = krb5_ret_int32(sp, &p->ncomp);
    if(ret) return ret;
    ret = krb5_ret_data(sp, &p->realm);
    if(ret) return ret;
    p->comp = ALLOC(p->ncomp, krb5_data);
    if(p->comp == NULL){
	return ENOMEM;
    }
    for(i = 0; i < p->ncomp; i++){
	ret = krb5_ret_data(sp, &p->comp[i]);
	if(ret) return ret;
    }
    *princ = p;
    return 0;
}

krb5_error_code
krb5_store_keyblock(krb5_storage *sp, krb5_keyblock p)
{
    int ret;
    ret =krb5_store_int32(sp, p.keytype);
    if(ret) return ret;
    ret = krb5_store_data(sp, p.contents);
    return ret;
}

krb5_error_code
krb5_ret_keyblock(krb5_storage *sp, krb5_keyblock *p)
{
    int ret;
    ret = krb5_ret_int32(sp, (int32_t*)&p->keytype); /* keytype + etype */
    if(ret) return ret;
    ret = krb5_ret_data(sp, &p->contents);
    return ret;
}

krb5_error_code
krb5_store_times(krb5_storage *sp, krb5_times times)
{
    int ret;
    ret = krb5_store_int32(sp, times.authtime);
    if(ret) return ret;
    ret = krb5_store_int32(sp, times.starttime);
    if(ret) return ret;
    ret = krb5_store_int32(sp, times.endtime);
    if(ret) return ret;
    ret = krb5_store_int32(sp, times.renew_till);
    return ret;
}

krb5_error_code
krb5_ret_times(krb5_storage *sp, krb5_times *times)
{
    int ret;
    int32_t tmp;
    ret = krb5_ret_int32(sp, &tmp);
    times->authtime = tmp;
    if(ret) return ret;
    ret = krb5_ret_int32(sp, &tmp);
    times->starttime = tmp;
    if(ret) return ret;
    ret = krb5_ret_int32(sp, &tmp);
    times->endtime = tmp;
    if(ret) return ret;
    ret = krb5_ret_int32(sp, &tmp);
    times->renew_till = tmp;
    return ret;
}

krb5_error_code
krb5_store_address(krb5_storage *sp, krb5_address p)
{
    int ret;
    ret = krb5_store_int16(sp, p.type);
    if(ret) return ret;
    ret = krb5_store_data(sp, p.address);
    return ret;
}

krb5_error_code
krb5_ret_address(krb5_storage *sp, krb5_address *adr)
{
    int16_t t;
    int ret;
    ret = krb5_ret_int16(sp, &t);
    if(ret) return ret;
    adr->type = t;
    ret = krb5_ret_data(sp, &adr->address);
    return ret;
}

krb5_error_code
krb5_store_addrs(krb5_storage *sp, krb5_addresses p)
{
    int i;
    int ret;
    ret = krb5_store_int32(sp, p.number);
    if(ret) return ret;
    for(i = 0; i<p.number; i++){
	ret = krb5_store_address(sp, p.addrs[i]);
	if(ret) break;
    }
    return ret;
}

krb5_error_code
krb5_ret_addrs(krb5_storage *sp, krb5_addresses *adr)
{
    int i;
    int ret;
    ret = krb5_ret_int32(sp, &adr->number);
    if(ret) return ret;
    adr->addrs = ALLOC(adr->number, krb5_address);
    for(i = 0; i < adr->number; i++){
	ret = krb5_ret_address(sp, &adr->addrs[i]);
	if(ret) break;
    }
    return ret;
}

krb5_error_code
krb5_store_authdata(krb5_storage *sp, krb5_data p)
{
    return krb5_store_data(sp, p);
}

krb5_error_code
krb5_ret_authdata(krb5_storage *sp, krb5_data *auth)
{
    return krb5_ret_data(sp, auth);
}
