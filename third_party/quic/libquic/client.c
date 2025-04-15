/*
 * Perform a QUIC client-side handshake.
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

#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "netinet/quic.h"

static int quic_client_psk_handshake(int sockfd, const char *identity,
				     const gnutls_datum_t *key, const char *alpns)
{
	gnutls_psk_client_credentials_t cred;
	gnutls_session_t session;
	size_t alpn_len;
	char alpn[64];
	int ret;

	ret = gnutls_psk_allocate_client_credentials(&cred);
	if (ret)
		goto err;
	ret = gnutls_psk_set_client_credentials(cred, identity, key, GNUTLS_PSK_KEY_RAW);
	if (ret)
		goto err_cred;

	ret = gnutls_init(&session, GNUTLS_CLIENT);
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
	gnutls_psk_free_client_credentials(cred);
err:
	return ret;
}

static int quic_client_x509_handshake(int sockfd, const char *alpns, const char *host)
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

	ret = gnutls_init(&session, GNUTLS_CLIENT);
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

	if (host) {
		ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS, host, strlen(host));
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

static int quic_file_read_psk(const char *file, char *identity[], gnutls_datum_t *pkey)
{
	unsigned char *end, *head, *key, *buf;
	int fd, err = -1, i = 0;
	struct stat statbuf;
	gnutls_datum_t gkey;
	unsigned int size;

	fd = open(file, O_RDONLY);
	if (fd == -1)
		return -1;
	if (fstat(fd, &statbuf))
		goto out;

	size = (unsigned int)statbuf.st_size;
	head = malloc(size);
	if (!head)
		goto out;
	if (read(fd, head, size) == -1) {
		free(head);
		goto out;
	}

	buf = head;
	end = buf + size - 1;
	do {
		key = (unsigned char *)strchr((char *)buf, ':');
		if (!key) {
			free(head);
			goto out;
		}
		*key = '\0';
		identity[i] = (char *)buf;

		key++;
		gkey.data = key;

		buf = (unsigned char *)strchr((char *)key, '\n');
		if (!buf) {
			gkey.size = end - gkey.data;
			buf = end;
			goto decode;
		}
		*buf = '\0';
		buf++;
		gkey.size = strlen((char *)gkey.data);
decode:
		if (gnutls_hex_decode2(&gkey, &pkey[i])) {
			free(head);
			goto out;
		}
		i++;
	} while (buf < end && i < 5);

	err = i;
out:
	close(fd);
	return err;
}

/**
 * quic_client_handshake - start a QUIC handshake with Certificate or PSK mode on client side
 * @sockfd: IPPROTO_QUIC type socket
 * @psk_file: pre-shared key file for PSK mode
 * @hostname: server name for Certificate mode
 * @alpns: ALPNs supported and split by ','
 *
 * Return values:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_client_handshake(int sockfd, const char *pkey_file,
			  const char *hostname, const char *alpns)
{
	gnutls_datum_t keys[5];
	char *identities[5];
	int ret;

	if (!pkey_file)
		return quic_client_x509_handshake(sockfd, alpns, hostname);

	ret = quic_file_read_psk(pkey_file, identities, keys);
	if (ret <= 0)
		return -EINVAL;

	ret = quic_client_psk_handshake(sockfd, identities[0], &keys[0], alpns);

	free(identities[0]);
	return ret;
}
