#ifndef __STORE_H__
#define __STORE_H__

krb5_error_code
krb5_store_int32(int fd,
		 int32_t value);

krb5_error_code
krb5_ret_int32(int fd,
	       int32_t *value);

krb5_error_code
krb5_store_int16(int fd,
		 int16_t value);

krb5_error_code
krb5_ret_int16(int fd,
	       int16_t *value);

krb5_error_code
krb5_store_int8(int fd,
		int8_t value);

krb5_error_code
krb5_ret_int8(int fd,
	      int8_t *value);

krb5_error_code
krb5_store_data(int fd,
		krb5_data data);

krb5_error_code
krb5_ret_data(int fd,
	      krb5_data *data);

krb5_error_code
krb5_store_principal(int fd,
		     krb5_principal p);

krb5_error_code
krb5_ret_principal(int fd,
		   krb5_principal *princ);

krb5_error_code
krb5_store_keyblock(int fd, krb5_keyblock p);

krb5_error_code
krb5_ret_keyblock(int fd, krb5_keyblock *p);

krb5_error_code
krb5_store_times(int fd, krb5_times times);

krb5_error_code
krb5_ret_times(int fd, krb5_times *times);

krb5_error_code
krb5_store_address(int fd, krb5_address p);

krb5_error_code
krb5_ret_address(int fd, krb5_address *adr);

krb5_error_code
krb5_store_addrs(int fd, krb5_addresses p);

krb5_error_code
krb5_ret_addrs(int fd, krb5_addresses *adr);

krb5_error_code
krb5_store_authdata(int fd, krb5_data p);

krb5_error_code
krb5_ret_authdata(int fd, krb5_data *auth);

#endif /* __STORE_H__ */
