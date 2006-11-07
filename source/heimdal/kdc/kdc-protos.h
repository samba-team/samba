/* This is a generated file */
#ifndef __kdc_protos_h__
#define __kdc_protos_h__

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

void
kdc_log (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	int /*level*/,
	const char */*fmt*/,
	...);

char*
kdc_log_msg (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	int /*level*/,
	const char */*fmt*/,
	...);

char*
kdc_log_msg_va (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	int /*level*/,
	const char */*fmt*/,
	va_list /*ap*/);

void
kdc_openlog (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/);

void
krb5_kdc_default_config (krb5_kdc_configuration */*config*/);

int
krb5_kdc_process_krb5_request (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	unsigned char */*buf*/,
	size_t /*len*/,
	krb5_data */*reply*/,
	const char */*from*/,
	struct sockaddr */*addr*/,
	int /*datagram_reply*/);

int
krb5_kdc_process_request (
	krb5_context /*context*/,
	krb5_kdc_configuration */*config*/,
	unsigned char */*buf*/,
	size_t /*len*/,
	krb5_data */*reply*/,
	krb5_boolean */*prependlength*/,
	const char */*from*/,
	struct sockaddr */*addr*/,
	int /*datagram_reply*/);

#ifdef __cplusplus
}
#endif

#endif /* __kdc_protos_h__ */
