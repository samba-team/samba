#include "krb5_locl.h"

krb5_error_code
krb5_store_int32(int fd,
		 int32_t value)
{
    int ret;

    value = htonl(value);
    ret = write(fd, &value, sizeof(value));
    if (ret != sizeof(value))
	return (ret<0)?errno:KRB5_CC_END;
    return 0;
}

krb5_error_code
krb5_ret_int32(int fd,
	       int32_t *value)
{
    int32_t v;
    int ret;
    ret = read(fd, &v, sizeof(v));
    if(ret != sizeof(v))
	return (ret<0)?errno:KRB5_CC_END;

    *value = ntohl(v);
    return 0;
}

krb5_error_code
krb5_store_int16(int fd,
		 int16_t value)
{
    int ret;

    value = htons(value);
    ret = write(fd, &value, sizeof(value));
    if (ret != sizeof(value))
	return (ret<0)?errno:KRB5_CC_END;
    return 0;
}

krb5_error_code
krb5_ret_int16(int fd,
	       int16_t *value)
{
    int16_t v;
    int ret;
    ret = read(fd, &v, sizeof(v));
    if(ret != sizeof(v))
	return (ret<0)?errno:KRB5_CC_END; /* XXX */
  
    *value = ntohs(v);
    return 0;
}

krb5_error_code
krb5_store_int8(int fd,
		int8_t value)
{
    int ret;

    ret = write(fd, &value, sizeof(value));
    if (ret != sizeof(value))
	return (ret<0)?errno:KRB5_CC_END;
    return 0;
}

krb5_error_code
krb5_ret_int8(int fd,
	      int8_t *value)
{
    int ret;

    ret = read (fd, value, sizeof(*value));
    if (ret != sizeof(*value))
	return (ret<0)?errno:KRB5_CC_END;
    return 0;
}

krb5_error_code
krb5_store_data(int fd,
		krb5_data data)
{
    int ret;
    ret = krb5_store_int32(fd, data.length);
    if(ret < 0)
	return ret;
    ret = write(fd, data.data, data.length);
    if(ret != data.length){
	if(ret < 0)
	    return errno;
	return KRB5_CC_END;
    }
    return 0;
}

krb5_error_code
krb5_ret_data(int fd,
	      krb5_data *data)
{
    int ret;
    int size;
    ret = krb5_ret_int32(fd, &size);
    if(ret)
	return ret;
    data->length = size;
    data->data = malloc(size);
    ret = read(fd, data->data, size);
    if(ret != size)
	return (ret < 0)? errno : KRB5_CC_END;
    return 0;
}

krb5_error_code
krb5_store_principal(int fd,
		     krb5_principal p)
{
    int i;
    int ret;
    ret = krb5_store_int32(fd, p->type);
    if(ret) return ret;
    ret = krb5_store_int32(fd, p->ncomp);
    if(ret) return ret;
    ret = krb5_store_data(fd, p->realm);
    if(ret) return ret;
    for(i = 0; i < p->ncomp; i++){
	ret = krb5_store_data(fd, p->comp[i]);
	if(ret) return ret;
    }
    return 0;
}

krb5_error_code
krb5_ret_principal(int fd,
		   krb5_principal *princ)
{
    int i;
    int ret;
    krb5_principal p;

    p = ALLOC(1, krb5_principal_data);
    if(p == NULL)
	return ENOMEM;

    if((ret = krb5_ret_int32(fd, &p->type)))
	return ret;
    ret = krb5_ret_int32(fd, &p->ncomp);
    if(ret) return ret;
    ret = krb5_ret_data(fd, &p->realm);
    if(ret) return ret;
    p->comp = ALLOC(p->ncomp, krb5_data);
    if(p->comp == NULL){
	return ENOMEM;
    }
    for(i = 0; i < p->ncomp; i++){
	ret = krb5_ret_data(fd, &p->comp[i]);
	if(ret) return ret;
    }
    *princ = p;
    return 0;
}

krb5_error_code
krb5_store_keyblock(int fd, krb5_keyblock p)
{
    int ret;
    ret =krb5_store_int32(fd, p.keytype);
    if(ret) return ret;
    ret = krb5_store_data(fd, p.contents);
    return ret;
}

krb5_error_code
krb5_ret_keyblock(int fd, krb5_keyblock *p)
{
    int ret;
    ret = krb5_ret_int32(fd, (int32_t*)&p->keytype); /* keytype + etype */
    if(ret) return ret;
    ret = krb5_ret_data(fd, &p->contents);
    return ret;
}

krb5_error_code
krb5_store_times(int fd, krb5_times times)
{
    int ret;
    ret = krb5_store_int32(fd, times.authtime);
    if(ret) return ret;
    ret = krb5_store_int32(fd, times.starttime);
    if(ret) return ret;
    ret = krb5_store_int32(fd, times.endtime);
    if(ret) return ret;
    ret = krb5_store_int32(fd, times.renew_till);
    return ret;
}

krb5_error_code
krb5_ret_times(int fd, krb5_times *times)
{
    int ret;
    int32_t tmp;

    ret = krb5_ret_int32(fd, &tmp);
    times->authtime = tmp;
    if(ret) return ret;
    ret = krb5_ret_int32(fd, &tmp);
    times->starttime = tmp;
    if(ret) return ret;
    ret = krb5_ret_int32(fd, &tmp);
    times->endtime = tmp;
    if(ret) return ret;
    ret = krb5_ret_int32(fd, &tmp);
    times->renew_till = tmp;
    return ret;
}

krb5_error_code
krb5_store_address(int fd, krb5_address p)
{
    int ret;
    ret = krb5_store_int16(fd, p.type);
    if(ret) return ret;
    ret = krb5_store_data(fd, p.address);
    return ret;
}

krb5_error_code
krb5_ret_address(int fd, krb5_address *adr)
{
    int16_t t;
    int ret;
    ret = krb5_ret_int16(fd, &t);
    if(ret) return ret;
    adr->type = t;
    ret = krb5_ret_data(fd, &adr->address);
    return ret;
}

krb5_error_code
krb5_store_addrs(int fd, krb5_addresses p)
{
    int i;
    int ret;
    ret = krb5_store_int32(fd, p.number);
    if(ret) return ret;
    for(i = 0; i<p.number; i++){
	ret = krb5_store_address(fd, p.addrs[i]);
	if(ret) break;
    }
    return ret;
}

krb5_error_code
krb5_ret_addrs(int fd, krb5_addresses *adr)
{
    int i;
    int ret;
    ret = krb5_ret_int32(fd, &adr->number);
    if(ret) return ret;
    adr->addrs = ALLOC(adr->number, krb5_address);
    for(i = 0; i < adr->number; i++){
	ret = krb5_ret_address(fd, &adr->addrs[i]);
	if(ret) break;
    }
    return ret;
}

krb5_error_code
krb5_store_authdata(int fd, krb5_data p)
{
    return krb5_store_data(fd, p);
}

krb5_error_code
krb5_ret_authdata(int fd, krb5_data *auth)
{
    return krb5_ret_data(fd, auth);
}
