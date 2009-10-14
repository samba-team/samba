/*
* CIFS user-space helper.
* Copyright (C) Igor Mammedov (niallain@gmail.com) 2007
* Copyright (C) Jeff Layton (jlayton@redhat.com) 2009
*
* Used by /sbin/request-key for handling
* cifs upcall for kerberos authorization of access to share and
* cifs upcall for DFS srver name resolving (IPv4/IPv6 aware).
* You should have keyutils installed and add something like the
* following lines to /etc/request-key.conf file:

create cifs.spnego * * /usr/local/sbin/cifs.upcall %k
create dns_resolver * * /usr/local/sbin/cifs.upcall %k

* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include "includes.h"
#include <keyutils.h>

#include "cifs_spnego.h"

const char *CIFSSPNEGO_VERSION = "1.2";
static const char *prog = "cifs.upcall";
typedef enum _sectype {
	NONE = 0,
	KRB5,
	MS_KRB5
} sectype_t;

/*
 * given a process ID, get the value of the KRB5CCNAME environment variable
 * in the context of that process. On error, just return NULL.
 */
static char *
get_krb5_ccname(pid_t pid)
{
	int fd;
	ssize_t len, left;

	/*
	 * FIXME: sysconf for ARG_MAX instead? Kernel seems to be limited to a
	 * page however, so it may not matter.
	 */
	char buf[4096];
	char *p, *value = NULL;

	buf[4095] = '\0';
	snprintf(buf, 4095, "/proc/%d/environ", pid);
	fd = open(buf, O_RDONLY);
	if (fd < 0) {
		syslog(LOG_DEBUG, "%s: unable to open %s: %d", __func__, buf,
			errno);
		return NULL;
	}

	/* FIXME: don't assume that we get it all in the first read? */
	len = read(fd, buf, 4096);
	close(fd);
	if (len < 0) {
		syslog(LOG_DEBUG, "%s: unable to read from /proc/%d/environ: "
				  "%d", __func__, pid, errno);
		return NULL;
	}

	left = len;
	p = buf;

	/* can't have valid KRB5CCNAME if there are < 13 bytes left */
	while (left > 12) {
		if (strncmp("KRB5CCNAME=", p, 11)) {
			p += strnlen(p, left);
			++p;
			left = buf + len - p;
			continue;
		}
		p += 11;
		left -= 11;
		value = SMB_STRNDUP(p, left);
		break;
	}
	syslog(LOG_DEBUG, "%s: KRB5CCNAME=%s", __func__,
				value ? value : "(null)");
	return value;
}

/*
 * Prepares AP-REQ data for mechToken and gets session key
 * Uses credentials from cache. It will not ask for password
 * you should receive credentials for yuor name manually using
 * kinit or whatever you wish.
 *
 * in:
 * 	oid -		string with OID/ Could be OID_KERBEROS5
 * 			or OID_KERBEROS5_OLD
 * 	principal -	Service name.
 * 			Could be "cifs/FQDN" for KRB5 OID
 * 			or for MS_KRB5 OID style server principal
 * 			like "pdc$@YOUR.REALM.NAME"
 *
 * out:
 * 	secblob -	pointer for spnego wrapped AP-REQ data to be stored
 * 	sess_key-	pointer for SessionKey data to be stored
 *
 * ret: 0 - success, others - failure
 */
static int
handle_krb5_mech(const char *oid, const char *principal, DATA_BLOB *secblob,
		 DATA_BLOB *sess_key, const char *ccname)
{
	int retval;
	DATA_BLOB tkt, tkt_wrapped;

	syslog(LOG_DEBUG, "%s: getting service ticket for %s", __func__,
			  principal);

	/* get a kerberos ticket for the service and extract the session key */
	retval = cli_krb5_get_ticket(principal, 0, &tkt, sess_key, 0, ccname,
				     NULL);

	if (retval) {
		syslog(LOG_DEBUG, "%s: failed to obtain service ticket (%d)",
				  __func__, retval);
		return retval;
	}

	syslog(LOG_DEBUG, "%s: obtained service ticket", __func__);

	/* wrap that up in a nice GSS-API wrapping */
	tkt_wrapped = spnego_gen_krb5_wrap(tkt, TOK_ID_KRB_AP_REQ);

	/* and wrap that in a shiny SPNEGO wrapper */
	*secblob = gen_negTokenInit(oid, tkt_wrapped);

	data_blob_free(&tkt_wrapped);
	data_blob_free(&tkt);
	return retval;
}

#define DKD_HAVE_HOSTNAME	0x1
#define DKD_HAVE_VERSION	0x2
#define DKD_HAVE_SEC		0x4
#define DKD_HAVE_IPV4		0x8
#define DKD_HAVE_IPV6		0x10
#define DKD_HAVE_UID		0x20
#define DKD_HAVE_PID		0x40
#define DKD_MUSTHAVE_SET (DKD_HAVE_HOSTNAME|DKD_HAVE_VERSION|DKD_HAVE_SEC)

static struct decoded_args {
	int		ver;
	char		*hostname;
	uid_t		uid;
	pid_t		pid;
	sectype_t	sec;
};

static int
decode_key_description(const char *desc, struct decoded_args *arg)
{
	int retval = 0;
	char *pos;
	const char *tkn = desc;

	do {
		pos = index(tkn, ';');
		if (strncmp(tkn, "host=", 5) == 0) {
			int len;

			if (pos == NULL)
				len = strlen(tkn);
			else
				len = pos - tkn;

			len -= 4;
			SAFE_FREE(arg->hostname);
			arg->hostname = SMB_XMALLOC_ARRAY(char, len);
			strlcpy(arg->hostname, tkn + 5, len);
			retval |= DKD_HAVE_HOSTNAME;
		} else if (strncmp(tkn, "ipv4=", 5) == 0) {
			/* BB: do we need it if we have hostname already? */
		} else if (strncmp(tkn, "ipv6=", 5) == 0) {
			/* BB: do we need it if we have hostname already? */
		} else if (strncmp(tkn, "pid=", 4) == 0) {
			errno = 0;
			arg->pid = strtol(tkn + 4, NULL, 0);
			if (errno != 0) {
				syslog(LOG_ERR, "Invalid pid format: %s",
				       strerror(errno));
				return 1;
			} else {
				retval |= DKD_HAVE_PID;
			}
		} else if (strncmp(tkn, "sec=", 4) == 0) {
			if (strncmp(tkn + 4, "krb5", 4) == 0) {
				retval |= DKD_HAVE_SEC;
				arg->sec = KRB5;
			} else if (strncmp(tkn + 4, "mskrb5", 6) == 0) {
				retval |= DKD_HAVE_SEC;
				arg->sec = MS_KRB5;
			}
		} else if (strncmp(tkn, "uid=", 4) == 0) {
			errno = 0;
			arg->uid = strtol(tkn + 4, NULL, 16);
			if (errno != 0) {
				syslog(LOG_ERR, "Invalid uid format: %s",
				       strerror(errno));
				return 1;
			} else {
				retval |= DKD_HAVE_UID;
			}
		} else if (strncmp(tkn, "ver=", 4) == 0) {	/* if version */
			errno = 0;
			arg->ver = strtol(tkn + 4, NULL, 16);
			if (errno != 0) {
				syslog(LOG_ERR, "Invalid version format: %s",
				       strerror(errno));
				return 1;
			} else {
				retval |= DKD_HAVE_VERSION;
			}
		}
		if (pos == NULL)
			break;
		tkn = pos + 1;
	} while (tkn);
	return retval;
}

static int
cifs_resolver(const key_serial_t key, const char *key_descr)
{
	int c;
	struct addrinfo *addr;
	char ip[INET6_ADDRSTRLEN];
	void *p;
	const char *keyend = key_descr;
	/* skip next 4 ';' delimiters to get to description */
	for (c = 1; c <= 4; c++) {
		keyend = index(keyend+1, ';');
		if (!keyend) {
			syslog(LOG_ERR, "invalid key description: %s",
					key_descr);
			return 1;
		}
	}
	keyend++;

	/* resolve name to ip */
	c = getaddrinfo(keyend, NULL, NULL, &addr);
	if (c) {
		syslog(LOG_ERR, "unable to resolve hostname: %s [%s]",
				keyend, gai_strerror(c));
		return 1;
	}

	/* conver ip to string form */
	if (addr->ai_family == AF_INET)
		p = &(((struct sockaddr_in *)addr->ai_addr)->sin_addr);
	else
		p = &(((struct sockaddr_in6 *)addr->ai_addr)->sin6_addr);

	if (!inet_ntop(addr->ai_family, p, ip, sizeof(ip))) {
		syslog(LOG_ERR, "%s: inet_ntop: %s", __func__, strerror(errno));
		freeaddrinfo(addr);
		return 1;
	}

	/* setup key */
	c = keyctl_instantiate(key, ip, strlen(ip)+1, 0);
	if (c == -1) {
		syslog(LOG_ERR, "%s: keyctl_instantiate: %s", __func__,
				strerror(errno));
		freeaddrinfo(addr);
		return 1;
	}

	freeaddrinfo(addr);
	return 0;
}

static void
usage(void)
{
	syslog(LOG_INFO, "Usage: %s [-c] [-v] key_serial", prog);
	fprintf(stderr, "Usage: %s [-c] [-v] key_serial\n", prog);
}

int main(const int argc, char *const argv[])
{
	struct cifs_spnego_msg *keydata = NULL;
	DATA_BLOB secblob = data_blob_null;
	DATA_BLOB sess_key = data_blob_null;
	key_serial_t key = 0;
	size_t datalen;
	long rc = 1;
	int c, use_cifs_service_prefix = 0;
	char *buf, *princ, *ccname = NULL;
	struct decoded_args arg = { };
	const char *oid;

	openlog(prog, 0, LOG_DAEMON);

	while ((c = getopt(argc, argv, "cv")) != -1) {
		switch (c) {
		case 'c':
			use_cifs_service_prefix = 1;
			break;
		case 'v':
			printf("version: %s\n", CIFSSPNEGO_VERSION);
			goto out;
		default:
			syslog(LOG_ERR, "unknown option: %c", c);
			goto out;
		}
	}

	/* is there a key? */
	if (argc <= optind) {
		usage();
		goto out;
	}

	/* get key and keyring values */
	errno = 0;
	key = strtol(argv[optind], NULL, 10);
	if (errno != 0) {
		key = 0;
		syslog(LOG_ERR, "Invalid key format: %s", strerror(errno));
		goto out;
	}

	rc = keyctl_describe_alloc(key, &buf);
	if (rc == -1) {
		syslog(LOG_ERR, "keyctl_describe_alloc failed: %s",
		       strerror(errno));
		rc = 1;
		goto out;
	}

	syslog(LOG_DEBUG, "key description: %s", buf);

	if ((strncmp(buf, "cifs.resolver", sizeof("cifs.resolver")-1) == 0) ||
	    (strncmp(buf, "dns_resolver", sizeof("dns_resolver")-1) == 0)) {
		rc = cifs_resolver(key, buf);
		goto out;
	}

	rc = decode_key_description(buf, &arg);
	if ((rc & DKD_MUSTHAVE_SET) != DKD_MUSTHAVE_SET) {
		syslog(LOG_ERR, "unable to get necessary params from key "
				"description (0x%x)", rc);
		rc = 1;
		SAFE_FREE(buf);
		goto out;
	}
	SAFE_FREE(buf);

	if (arg.ver > CIFS_SPNEGO_UPCALL_VERSION) {
		syslog(LOG_ERR, "incompatible kernel upcall version: 0x%x",
				arg.ver);
		rc = 1;
		goto out;
	}

	if (rc & DKD_HAVE_PID)
		ccname = get_krb5_ccname(arg.pid);

	if (rc & DKD_HAVE_UID) {
		rc = setuid(arg.uid);
		if (rc == -1) {
			syslog(LOG_ERR, "setuid: %s", strerror(errno));
			goto out;
		}
	}

	// do mech specific authorization
	switch (arg.sec) {
	case MS_KRB5:
	case KRB5:
		/* for "cifs/" service name + terminating 0 */
		datalen = strlen(arg.hostname) + 5 + 1;
		princ = SMB_XMALLOC_ARRAY(char, datalen);
		if (!princ) {
			rc = 1;
			break;
		}

		if (use_cifs_service_prefix)
			strlcpy(princ, "cifs/", datalen);
		else
			strlcpy(princ, "host/", datalen);

		strlcpy(princ + 5, arg.hostname, datalen - 5);

		if (arg.sec == MS_KRB5)
			oid = OID_KERBEROS5_OLD;
		else
			oid = OID_KERBEROS5;

		rc = handle_krb5_mech(oid, princ, &secblob, &sess_key, ccname);
		SAFE_FREE(princ);
		break;
	default:
		syslog(LOG_ERR, "sectype: %d is not implemented", arg.sec);
		rc = 1;
		break;
	}

	if (rc)
		goto out;

	/* pack SecurityBLob and SessionKey into downcall packet */
	datalen =
	    sizeof(struct cifs_spnego_msg) + secblob.length + sess_key.length;
	keydata = (struct cifs_spnego_msg*)SMB_XMALLOC_ARRAY(char, datalen);
	if (!keydata) {
		rc = 1;
		goto out;
	}
	keydata->version = arg.ver;
	keydata->flags = 0;
	keydata->sesskey_len = sess_key.length;
	keydata->secblob_len = secblob.length;
	memcpy(&(keydata->data), sess_key.data, sess_key.length);
	memcpy(&(keydata->data) + keydata->sesskey_len,
	       secblob.data, secblob.length);

	/* setup key */
	rc = keyctl_instantiate(key, keydata, datalen, 0);
	if (rc == -1) {
		syslog(LOG_ERR, "keyctl_instantiate: %s", strerror(errno));
		goto out;
	}

	/* BB: maybe we need use timeout for key: for example no more then
	 * ticket lifietime? */
	/* keyctl_set_timeout( key, 60); */
out:
	/*
	 * on error, negatively instantiate the key ourselves so that we can
	 * make sure the kernel doesn't hang it off of a searchable keyring
	 * and interfere with the next attempt to instantiate the key.
	 */
	if (rc != 0  && key == 0)
		keyctl_negate(key, 1, KEY_REQKEY_DEFL_DEFAULT);
	data_blob_free(&secblob);
	data_blob_free(&sess_key);
	SAFE_FREE(ccname);
	SAFE_FREE(arg.hostname);
	SAFE_FREE(keydata);
	return rc;
}
