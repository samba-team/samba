/* $Id$ */

#ifndef __STORE_H__
#define __STORE_H__

krb5_storage *krb5_storage_from_fd(int fd);

krb5_storage *krb5_storage_from_mem(void *buf, size_t len);

krb5_error_code krb5_storage_free(krb5_storage *sp);

#define __PT(N, T) krb5_error_code krb5_store_##N(krb5_storage*, T); krb5_error_code krb5_ret_##N(krb5_storage *, T*)

__PT(int32, int32_t);
__PT(int16, int16_t);
__PT(int8, int8_t);
__PT(data, krb5_data);
__PT(principal, krb5_principal);
__PT(keyblock, krb5_keyblock);
__PT(times, krb5_times);
__PT(address, krb5_address);
__PT(addrs, krb5_addresses);
__PT(authdata, krb5_data);

#undef __PT

#endif /* __STORE_H__ */
