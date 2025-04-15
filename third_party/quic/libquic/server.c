/*
 * Perform a QUIC server-side handshake.
 *
 * Copyright (c) 2024 Red Hat, Inc.
 *
 * libquic is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "netinet/quic.h"

static int quic_server_psk_handshake(int sockfd, const char *psk, const char *alpns)
{
	gnutls_psk_server_credentials_t cred;
	gnutls_session_t session;
	size_t alpn_len;
	char alpn[64];
	int ret;

	ret = gnutls_psk_allocate_server_credentials(&cred);
	if (ret)
		goto err;
	ret = gnutls_psk_set_server_credentials_file(cred, psk);
	if (ret)
		goto err_cred;
	ret = gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET);
	if (ret)
		goto err_cred;
	ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);
	if (ret)
		goto err_session;

	ret = gnutls_priority_set_direct(session, QUIC_PRIORITY, NULL);
	if (ret)
		goto err_session;

	if (alpns) {
		ret = quic_session_set_alpn(session, alpns, strlen(alpns));
		if (ret)
			goto err_session;
	}

	gnutls_transport_set_int(session, sockfd);

	ret = quic_handshake(session);
	if (ret)
		goto err_session;

	if (alpns) {
		alpn_len = sizeof(alpn);
		ret = quic_session_get_alpn(session, alpn, &alpn_len);
	}

err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_psk_free_server_credentials(cred);
err:
	return ret;
}

static int quic_server_x509_handshake(int sockfd, const char *pkey,
				      const char *cert, const char *alpns)
{
	gnutls_certificate_credentials_t cred;
	gnutls_session_t session;
	size_t alpn_len;
	char alpn[64];
	int ret;

	ret = gnutls_certificate_allocate_credentials(&cred);
	if (ret)
		goto err;
	ret = gnutls_certificate_set_x509_system_trust(cred);
	if (ret < 0)
		goto err_cred;
	ret = gnutls_certificate_set_x509_key_file(cred, cert, pkey, GNUTLS_X509_FMT_PEM);
	if (ret)
		goto err_cred;
	ret = gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET);
	if (ret)
		goto err_cred;
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (ret)
		goto err_session;

	ret = gnutls_priority_set_direct(session, QUIC_PRIORITY, NULL);
	if (ret)
		goto err_session;

	if (alpns) {
		ret = quic_session_set_alpn(session, alpns, strlen(alpns));
		if (ret)
			goto err_session;
	}

	gnutls_transport_set_int(session, sockfd);

	ret = quic_handshake(session);
	if (ret)
		goto err_session;

	if (alpns) {
		alpn_len = sizeof(alpn);
		ret = quic_session_get_alpn(session, alpn, &alpn_len);
	}

err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	return ret;
}

/**
 * quic_server_handshake - start a QUIC handshake with Certificate or PSK mode on server side
 * @sockfd: IPPROTO_QUIC type socket
 * @pkey_file: private key file for Certificate mode or pre-shared key file for PSK mode
 * @cert_file: certificate file for Certificate mode or null for PSK mode
 * @alpns: ALPNs supported and split by ','
 *
 * Return values:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_server_handshake(int sockfd, const char *pkey_file,
			  const char *cert_file, const char *alpns)
{
	if (cert_file)
		return  quic_server_x509_handshake(sockfd, pkey_file, cert_file, alpns);

	return quic_server_psk_handshake(sockfd, pkey_file, alpns);
}
