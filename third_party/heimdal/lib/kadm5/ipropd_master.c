/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "iprop.h"
#include <rtbl.h>

static krb5_log_facility *log_facility;

static int verbose;

static const char *slave_stats_file;
static const char *slave_stats_temp_file;
static const char *slave_time_missing = "2 min";
static const char *slave_time_gone = "5 min";

static int time_before_missing;
static int time_before_gone;

const char *master_hostname;
const char *pidfile_basename;
static char hostname[128];

static krb5_socket_t
make_signal_socket (krb5_context context)
{
#ifndef NO_UNIX_SOCKETS
    struct sockaddr_un addr;
    const char *fn;
    krb5_socket_t fd;

    fn = kadm5_log_signal_socket(context);

    fd = socket (AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
	krb5_err (context, 1, errno, "socket AF_UNIX");
    memset (&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strlcpy (addr.sun_path, fn, sizeof(addr.sun_path));
    unlink (addr.sun_path);
    if (bind (fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	krb5_err (context, 1, errno, "bind %s", addr.sun_path);
    return fd;
#else
    struct addrinfo *ai = NULL;
    krb5_socket_t fd;

    kadm5_log_signal_socket_info(context, 1, &ai);

    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (rk_IS_BAD_SOCKET(fd))
	krb5_err (context, 1, rk_SOCK_ERRNO, "socket AF=%d", ai->ai_family);

    if (rk_IS_SOCKET_ERROR( bind (fd, ai->ai_addr, ai->ai_addrlen) ))
	krb5_err (context, 1, rk_SOCK_ERRNO, "bind");
    return fd;
#endif
}

static krb5_socket_t
make_listen_socket (krb5_context context, const char *port_str)
{
    krb5_socket_t fd;
    int one = 1;
    struct sockaddr_in addr;

    fd = socket (AF_INET, SOCK_STREAM, 0);
    if (rk_IS_BAD_SOCKET(fd))
	krb5_err (context, 1, rk_SOCK_ERRNO, "socket AF_INET");
    (void) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one));
    memset (&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    if (port_str) {
	addr.sin_port = krb5_getportbyname (context,
					      port_str, "tcp",
					      0);
	if (addr.sin_port == 0) {
	    char *ptr;
	    long port;

	    port = strtol (port_str, &ptr, 10);
	    if (port == 0 && ptr == port_str)
		krb5_errx (context, 1, "bad port `%s'", port_str);
	    addr.sin_port = htons(port);
	}
    } else {
	addr.sin_port = krb5_getportbyname (context, IPROP_SERVICE,
					    "tcp", IPROP_PORT);
    }
    if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	krb5_err (context, 1, errno, "bind");
    if (listen(fd, SOMAXCONN) < 0)
	krb5_err (context, 1, errno, "listen");
    return fd;
}


struct slave {
    krb5_socket_t fd;
    struct sockaddr_in addr;
    char *name;
    krb5_auth_context ac;
    uint32_t version;
    uint32_t version_tstamp;
    uint32_t version_ack;
    time_t seen;
    unsigned long flags;
#define SLAVE_F_DEAD	0x1
#define SLAVE_F_AYT	0x2
#define SLAVE_F_READY   0x4
    /*
     * We'll use non-blocking I/O so no slave can hold us back.
     *
     * We call the state left over from a partial write a "tail".
     *
     * The krb5_data holding an KRB-PRIV will be the write buffer.
     */
    struct {
        /* Every message we send is a KRB-PRIV with a 4-byte length prefixed */
        uint8_t         header_buf[4];
        krb5_data       header;
        krb5_data       packet;
        size_t          packet_off;
        /* For send_complete() we need an sp as part of the tail */
        krb5_storage    *dump;
        uint32_t        vno;
    } tail;
    struct {
        uint8_t         header_buf[4];
        krb5_data       packet;
        size_t          offset;
        int             hlen;
    } input;
    /*
     * Continuation for fair diff sending we send N entries at a time.
     */
    struct {
        off_t       off_next_version;   /* offset in log of next diff */
        uint32_t    initial_version;    /* at time of previous diff */
        uint32_t    initial_tstamp;     /* at time of previous diff */
        uint32_t    last_version_sent;
        int         more;               /* need to send more diffs */
    } next_diff;
    struct slave *next;
};

typedef struct slave slave;

static int
check_acl (krb5_context context, const char *name)
{
    const char *fn;
    FILE *fp;
    char buf[256];
    int ret = 1;
    char *slavefile = NULL;

    if (asprintf(&slavefile, "%s/slaves", hdb_db_dir(context)) == -1
	|| slavefile == NULL)
	errx(1, "out of memory");

    fn = krb5_config_get_string_default(context,
					NULL,
					slavefile,
					"kdc",
					"iprop-acl",
					NULL);

    fp = fopen (fn, "r");
    free(slavefile);
    if (fp == NULL)
	return 1;
    while (fgets(buf, sizeof(buf), fp) != NULL) {
	buf[strcspn(buf, "\r\n")] = '\0';
	if (strcmp (buf, name) == 0) {
	    ret = 0;
	    break;
	}
    }
    fclose (fp);
    return ret;
}

static void
slave_seen(slave *s)
{
    s->flags &= ~SLAVE_F_AYT;
    s->seen = time(NULL);
}

static int
slave_missing_p (slave *s)
{
    if (time(NULL) > s->seen + time_before_missing)
	return 1;
    return 0;
}

static int
slave_gone_p (slave *s)
{
    if (time(NULL) > s->seen + time_before_gone)
	return 1;
    return 0;
}

static void
slave_dead(krb5_context context, slave *s)
{
    krb5_warnx(context, "slave %s dead", s->name);

    if (!rk_IS_BAD_SOCKET(s->fd)) {
	rk_closesocket (s->fd);
	s->fd = rk_INVALID_SOCKET;
    }
    s->flags |= SLAVE_F_DEAD;
    slave_seen(s);
}

static void
remove_slave (krb5_context context, slave *s, slave **root)
{
    slave **p;

    if (!rk_IS_BAD_SOCKET(s->fd))
	rk_closesocket (s->fd);
    if (s->name)
	free (s->name);
    if (s->ac)
	krb5_auth_con_free (context, s->ac);

    /* Free any pending input/output state */
    krb5_data_free(&s->input.packet);
    krb5_data_free(&s->tail.packet);
    krb5_storage_free(s->tail.dump);

    for (p = root; *p; p = &(*p)->next)
	if (*p == s) {
	    *p = s->next;
	    break;
	}
    free (s);
}

static void
add_slave (krb5_context context, krb5_keytab keytab, slave **root,
	   krb5_socket_t fd)
{
    krb5_principal server = NULL;
    krb5_error_code ret;
    slave *s;
    socklen_t addr_len;
    krb5_ticket *ticket = NULL;

    s = calloc(1, sizeof(*s));
    if (s == NULL) {
	krb5_warnx (context, "add_slave: no memory");
	return;
    }
    s->name = NULL;
    s->ac = NULL;
    s->input.packet.data = NULL;
    s->tail.header.data = NULL;
    s->tail.packet.data = NULL;
    s->tail.dump = NULL;

    addr_len = sizeof(s->addr);
    s->fd = accept (fd, (struct sockaddr *)&s->addr, &addr_len);
    if (rk_IS_BAD_SOCKET(s->fd)) {
	krb5_warn (context, rk_SOCK_ERRNO, "accept");
	goto error;
    }

    /*
     * We write message lengths separately from the payload, and may do
     * back-to-back small writes when flushing pending input and then a new
     * update.  Avoid Nagle delays.
     */
#if defined(IPPROTO_TCP) && defined(TCP_NODELAY)
    {
        int nodelay = 1;
        (void) setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY,
                          (void *)&nodelay, sizeof(nodelay));
    }
#endif

    ret = krb5_sname_to_principal (context, hostname, IPROP_NAME,
				   KRB5_NT_SRV_HST, &server);
    if (ret) {
	krb5_warn (context, ret, "krb5_sname_to_principal");
	goto error;
    }

    ret = krb5_recvauth (context, &s->ac, &s->fd,
			 IPROP_VERSION, server, 0, keytab, &ticket);

    /*
     * We'll be doing non-blocking I/O only after authentication.  We don't
     * want to get stuck talking to any one slave.
     *
     * If we get a partial write, we'll finish writing when the socket becomes
     * writable.
     *
     * Partial reads will be treated as EOF, causing the slave to be marked
     * dead.
     *
     * To do non-blocking I/O for authentication we'll have to implement our
     * own krb5_recvauth().
     */
    socket_set_nonblocking(s->fd, 1);

    if (ret) {
	krb5_warn (context, ret, "krb5_recvauth");
	goto error;
    }
    ret = krb5_unparse_name (context, ticket->client, &s->name);
    if (ret) {
	krb5_warn (context, ret, "krb5_unparse_name");
	goto error;
    }
    if (check_acl (context, s->name)) {
	krb5_warnx (context, "%s not in acl", s->name);
	goto error;
    }

    {
	slave *l = *root;

	while (l) {
	    if (strcmp(l->name, s->name) == 0)
		break;
	    l = l->next;
	}
	if (l) {
	    if (l->flags & SLAVE_F_DEAD) {
		remove_slave(context, l, root);
	    } else {
		krb5_warnx (context, "second connection from %s", s->name);
		goto error;
	    }
	}
    }

    krb5_free_principal(context, server);
    krb5_free_ticket(context, ticket);
    krb5_warnx (context, "connection from %s", s->name);

    s->version = 0;
    s->version_ack = 0;
    s->flags = 0;
    slave_seen(s);
    s->next = *root;
    *root = s;
    return;
error:
    remove_slave(context, s, root);
    krb5_free_principal(context, server);
    if (ticket)
	krb5_free_ticket(context, ticket);
}

static int
dump_one (krb5_context context, HDB *db, hdb_entry *entry, void *v)
{
    krb5_error_code ret;
    krb5_storage *dump = (krb5_storage *)v;
    krb5_storage *sp;
    krb5_data data;

    ret = hdb_entry2value (context, entry, &data);
    if (ret)
	return ret;
    ret = krb5_data_realloc (&data, data.length + 4);
    if (ret)
	goto done;
    memmove ((char *)data.data + 4, data.data, data.length - 4);
    sp = krb5_storage_from_data(&data);
    if (sp == NULL) {
	ret = krb5_enomem(context);
	goto done;
    }
    ret = krb5_store_uint32(sp, ONE_PRINC);
    krb5_storage_free(sp);

    if (ret == 0)
        ret = krb5_store_data(dump, data);

done:
    krb5_data_free (&data);
    return ret;
}

static int
write_dump (krb5_context context, krb5_storage *dump,
	    const char *database, uint32_t current_version)
{
    krb5_error_code ret;
    krb5_storage *sp;
    HDB *db;
    krb5_data data;
    char buf[8];

    /* we assume that the caller has obtained an exclusive lock */

    ret = krb5_storage_truncate(dump, 0);
    if (ret)
	return ret;

    if (krb5_storage_seek(dump, 0, SEEK_SET) != 0)
        return errno;

    /*
     * First we store zero as the HDB version, this will indicate to a
     * later reader that the dumpfile is invalid.  We later write the
     * correct version in the file after we have written all of the
     * messages.  A dump with a zero version will not be considered
     * to be valid.
     */

    ret = krb5_store_uint32(dump, 0);
    if (ret)
        return ret;

    ret = hdb_create (context, &db, database);
    if (ret)
	krb5_err (context, IPROPD_RESTART, ret, "hdb_create: %s", database);
    ret = db->hdb_open (context, db, O_RDONLY, 0);
    if (ret)
	krb5_err (context, IPROPD_RESTART, ret, "db->open");

    sp = krb5_storage_from_mem (buf, 4);
    if (sp == NULL)
	krb5_errx (context, IPROPD_RESTART, "krb5_storage_from_mem");
    krb5_store_uint32 (sp, TELL_YOU_EVERYTHING);
    krb5_storage_free (sp);

    data.data   = buf;
    data.length = 4;

    ret = krb5_store_data(dump, data);
    if (ret) {
	krb5_warn (context, ret, "write_dump");
	return ret;
    }

    ret = hdb_foreach (context, db, HDB_F_ADMIN_DATA, dump_one, dump);
    if (ret) {
	krb5_warn (context, ret, "write_dump: hdb_foreach");
	return ret;
    }

    (*db->hdb_close)(context, db);
    (*db->hdb_destroy)(context, db);

    sp = krb5_storage_from_mem (buf, 8);
    if (sp == NULL)
	krb5_errx (context, IPROPD_RESTART, "krb5_storage_from_mem");
    ret = krb5_store_uint32(sp, NOW_YOU_HAVE);
    if (ret == 0)
      krb5_store_uint32(sp, current_version);
    krb5_storage_free (sp);

    data.length = 8;

    if (ret == 0)
        ret = krb5_store_data(dump, data);

    /*
     * We must ensure that the entire valid dump is written to disk
     * before we write the current version at the front thus making
     * it a valid dump file.  If we crash around here, this can be
     * important upon reboot.
     */

    if (ret == 0)
        ret = krb5_storage_fsync(dump);

    if (ret == 0 && krb5_storage_seek(dump, 0, SEEK_SET) == -1)
	ret = errno;

    /* Write current version at the front making the dump valid */

    if (ret == 0)
        ret = krb5_store_uint32(dump, current_version);

    /*
     * We don't need to fsync(2) after the real version is written as
     * it is not a disaster if it doesn't make it to disk if we crash.
     * After all, we'll just create a new dumpfile.
     */

    if (ret == 0)
        krb5_warnx(context, "wrote new dumpfile (version %u)",
                   current_version);
    else
        krb5_warn(context, ret, "failed to write new dumpfile (version %u)",
                  current_version);

    return ret;
}

static int
mk_priv_tail(krb5_context context, slave *s, krb5_data *data)
{
    uint32_t len;
    int ret;

    ret = krb5_mk_priv(context, s->ac, data, &s->tail.packet, NULL);
    if (ret)
        return ret;

    len = s->tail.packet.length;
    _krb5_put_int(s->tail.header_buf, len, sizeof(s->tail.header_buf));
    s->tail.header.length = sizeof(s->tail.header_buf);
    s->tail.header.data = s->tail.header_buf;
    return 0;
}

static int
have_tail(slave *s)
{
    return s->tail.header.length || s->tail.packet.length || s->tail.dump;
}

static int
more_diffs(slave *s)
{
    return s->next_diff.more;
}

#define SEND_COMPLETE_MAX_RECORDS 50
#define SEND_DIFFS_MAX_RECORDS 50

static int
send_tail(krb5_context context, slave *s)
{
    krb5_data data;
    ssize_t bytes = 0;
    size_t rem = 0;
    size_t n;
    int ret;

    if (! have_tail(s))
        return 0;

    /*
     * For the case where we're continuing a send_complete() send up to
     * SEND_COMPLETE_MAX_RECORDS records now, and the rest asynchronously
     * later.  This ensures that sending a complete dump to a slow-to-drain
     * client does not prevent others from getting serviced.
     */
    for (n = 0; n < SEND_COMPLETE_MAX_RECORDS; n++) {
        if (! have_tail(s))
            return 0;

        if (s->tail.header.length) {
            bytes = krb5_net_write(context, &s->fd,
                                   s->tail.header.data,
                                   s->tail.header.length);
            if (bytes < 0)
                goto err;

            s->tail.header.length -= bytes;
            s->tail.header.data = (char *)s->tail.header.data + bytes;
            rem = s->tail.header.length;
            if (rem)
                goto ewouldblock;
        }

        if (s->tail.packet.length) {
            bytes = krb5_net_write(context, &s->fd,
                                   (char *)s->tail.packet.data + s->tail.packet_off,
                                   s->tail.packet.length - s->tail.packet_off);
            if (bytes < 0)
                goto err;
            s->tail.packet_off += bytes;
            if (bytes)
                slave_seen(s);
            rem = s->tail.packet.length - s->tail.packet_off;
            if (rem)
                goto ewouldblock;

            krb5_data_free(&s->tail.packet);
            s->tail.packet_off = 0;
        }

        if (s->tail.dump == NULL)
            return 0;

        /*
         * We're in the middle of a send_complete() that was interrupted by
         * EWOULDBLOCK.  Continue the sending of the dump.
         */
        ret = krb5_ret_data(s->tail.dump, &data);
        if (ret == HEIM_ERR_EOF) {
            krb5_storage_free(s->tail.dump);
            s->tail.dump = NULL;
            s->version = s->tail.vno;
            return 0;
        }

        if (ret) {
            krb5_warn(context, ret, "failed to read entry from dump!");
        } else {
            ret = mk_priv_tail(context, s, &data);
            krb5_data_free(&data);
            if (ret == 0)
                continue;
            krb5_warn(context, ret, "failed to make and send a KRB-PRIV to %s",
                      s->name);
        }

        slave_dead(context, s);
        return ret;
    }

    if (ret == 0 && s->tail.dump != NULL)
        return EWOULDBLOCK;

err:
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        krb5_warn(context, ret = errno,
                  "error sending diffs to now-dead slave %s", s->name);
        slave_dead(context, s);
        return ret;
    }

ewouldblock:
    if (verbose)
        krb5_warnx(context, "would block writing %llu bytes to slave %s",
                   (unsigned long long)rem, s->name);
    return EWOULDBLOCK;
}

static int
send_complete(krb5_context context, slave *s, const char *database,
	      uint32_t current_version, uint32_t oldest_version,
              uint32_t initial_log_tstamp)
{
    krb5_error_code ret;
    krb5_storage *dump = NULL;
    uint32_t vno = 0;
    int fd = -1;
    struct stat st;
    char *dfn;

    ret = asprintf(&dfn, "%s/ipropd.dumpfile", hdb_db_dir(context));
    if (ret == -1 || !dfn)
	return krb5_enomem(context);

    fd = open(dfn, O_CREAT|O_RDWR, 0600);
    if (fd == -1) {
	ret = errno;
	krb5_warn(context, ret, "Cannot open/create iprop dumpfile %s", dfn);
	free(dfn);
        return ret;
    }
    free(dfn);

    dump = krb5_storage_from_fd(fd);
    if (!dump) {
	ret = errno;
	krb5_warn(context, ret, "krb5_storage_from_fd");
	goto done;
    }

    for (;;) {
	ret = flock(fd, LOCK_SH);
	if (ret == -1) {
	    ret = errno;
	    krb5_warn(context, ret, "flock(fd, LOCK_SH)");
	    goto done;
	}

	if (krb5_storage_seek(dump, 0, SEEK_SET) == (off_t)-1) {
	    ret = errno;
	    krb5_warn(context, ret, "krb5_storage_seek(dump, 0, SEEK_SET)");
	    goto done;
	}

	vno = 0;
	ret = krb5_ret_uint32(dump, &vno);
	if (ret && ret != HEIM_ERR_EOF) {
	    krb5_warn(context, ret, "krb5_ret_uint32(dump, &vno)");
	    goto done;
	}

        if (fstat(fd, &st) == -1) {
            ret = errno;
            krb5_warn(context, ret, "send_complete: could not stat dump file");
            goto done;
        }

	/*
	 * If the current dump has an appropriate version, then we can
	 * break out of the loop and send the file below.
	 */
	if (ret == 0 && vno != 0 && st.st_mtime > initial_log_tstamp &&
            vno >= oldest_version && vno <= current_version)
	    break;

        if (verbose)
            krb5_warnx(context, "send_complete: dumping HDB");

	/*
	 * Otherwise, we may need to write a new dump file.  We
	 * obtain an exclusive lock on the fd.  Because this is
	 * not guaranteed to be an upgrade of our existing shared
	 * lock, someone else may have written a new dumpfile while
	 * we were waiting and so we must first check the vno of
	 * the dump to see if that happened.  If it did, we need
	 * to go back to the top of the loop so that we can downgrade
	 * our lock to a shared one.
	 */

	ret = flock(fd, LOCK_EX);
	if (ret == -1) {
	    ret = errno;
	    krb5_warn(context, ret, "flock(fd, LOCK_EX)");
	    goto done;
	}

	ret = krb5_storage_seek(dump, 0, SEEK_SET);
	if (ret == -1) {
	    ret = errno;
	    krb5_warn(context, ret, "krb5_storage_seek(dump, 0, SEEK_SET)");
	    goto done;
	}

	vno = 0;
	ret = krb5_ret_uint32(dump, &vno);
	if (ret && ret != HEIM_ERR_EOF) {
	    krb5_warn(context, ret, "krb5_ret_uint32(dump, &vno)");
	    goto done;
	}

        if (fstat(fd, &st) == -1) {
            ret = errno;
            krb5_warn(context, ret, "send_complete: could not stat dump file");
            goto done;
        }

	/* check if someone wrote a better version for us */
        if (ret == 0 && vno != 0 && st.st_mtime > initial_log_tstamp &&
            vno >= oldest_version && vno <= current_version)
	    continue;

	/* Now, we know that we must write a new dump file.  */

	ret = write_dump(context, dump, database, current_version);
	if (ret)
	    goto done;

	/*
	 * And we must continue to the top of the loop so that we can
	 * downgrade to a shared lock.
	 */
    }

    /*
     * Leaving the above loop, dump should have a ptr right after the initial
     * 4 byte DB version number and we should have a shared lock on the file
     * (which we may have just created), so we are reading to start sending
     * the data down the wire.
     *
     * Note: (krb5_storage_from_fd() dup()'s the fd)
     */

    s->tail.dump = dump;
    s->tail.vno = vno;
    dump = NULL;
    ret = send_tail(context, s);

done:
    if (fd != -1)
	close(fd);
    if (dump)
	krb5_storage_free(dump);
    return ret;
}

static int
send_are_you_there (krb5_context context, slave *s)
{
    krb5_storage *sp;
    krb5_data data;
    char buf[4];
    int ret;

    if (s->flags & (SLAVE_F_DEAD|SLAVE_F_AYT))
	return 0;

    /*
     * Write any remainder of previous write, if we can.  If we'd block we'll
     * return EWOULDBLOCK.
     */
    ret = send_tail(context, s);
    if (ret)
        return ret;

    krb5_warnx(context, "slave %s missing, sending AYT", s->name);

    s->flags |= SLAVE_F_AYT;

    data.data = buf;
    data.length = 4;

    sp = krb5_storage_from_mem (buf, 4);
    if (sp == NULL) {
	krb5_warnx (context, "are_you_there: krb5_data_alloc");
	slave_dead(context, s);
	return ENOMEM;
    }
    ret = krb5_store_uint32(sp, ARE_YOU_THERE);
    krb5_storage_free (sp);

    if (ret == 0)
        ret = mk_priv_tail(context, s, &data);
    if (ret == 0)
        ret = send_tail(context, s);
    if (ret && ret != EWOULDBLOCK) {
        krb5_warn(context, ret, "are_you_there");
        slave_dead(context, s);
    }
    return ret;
}

static int
diffready(krb5_context context, slave *s)
{
    /*
     * Don't send any diffs until slave has sent an I_HAVE telling us the
     * initial version number!
     */
    if ((s->flags & SLAVE_F_READY) == 0)
        return 0;

    if (s->flags & SLAVE_F_DEAD) {
        if (verbose)
            krb5_warnx(context, "not sending diffs to dead slave %s", s->name);
        return 0;
    }

    /* Write any remainder of previous write, if we can. */
    if (send_tail(context, s) != 0)
        return 0;

    return 1;
}

static int
nodiffs(krb5_context context, slave *s, uint32_t current_version)
{
    krb5_storage *sp;
    krb5_data data;
    int ret;

    if (s->version < current_version)
        return 0;

    /*
     * If we had sent a partial diff, and now they're caught up, then there's
     * no more.
     */
    s->next_diff.more = 0;

    if (verbose)
        krb5_warnx(context, "slave %s version %ld already sent", s->name,
                   (long)s->version);
    sp = krb5_storage_emem();
    if (sp == NULL)
        krb5_errx(context, IPROPD_RESTART, "krb5_storage_from_mem");

    ret = krb5_store_uint32(sp, YOU_HAVE_LAST_VERSION);
    if (ret == 0) {
        krb5_data_zero(&data);
        ret = krb5_storage_to_data(sp, &data);
    }
    krb5_storage_free(sp);
    if (ret == 0) {
        ret = mk_priv_tail(context, s, &data);
        krb5_data_free(&data);
    }
    if (ret == 0)
        send_tail(context, s);

    return 1;
}

/*
 * Lock the log and return initial version and timestamp
 */
static int
get_first(kadm5_server_context *server_context, int log_fd,
          uint32_t *initial_verp, uint32_t *initial_timep)
{
    krb5_context context = server_context->context;
    int ret;

    /*
     * We don't want to perform tight retry loops on log access errors, so on
     * error mark the slave dead.  The slave reconnect after a delay...
     */
    if (flock(log_fd, LOCK_SH) == -1) {
        krb5_warn(context, errno, "could not obtain shared lock on log file");
        return -1;
    }

    ret = kadm5_log_get_version_fd(server_context, log_fd, LOG_VERSION_FIRST,
                                   initial_verp, initial_timep);
    if (ret == HEIM_ERR_EOF)
        ret = kadm5_log_get_version_fd(server_context, log_fd,
                                       LOG_VERSION_UBER, initial_verp,
                                       initial_timep);
    if (ret != 0) {
        flock(log_fd, LOCK_UN);
        krb5_warn(context, ret, "could not read initial log entry");
        return -1;
    }

    return 0;
}

/*-
 * Find the left end of the diffs in the log we want to send.
 *
 * - On success, return a positive offset to the first new entry, retaining
 *   a read lock on the log file.
 * - On error, return a negative offset, with the lock released.
 * - If we simply find no successor entry in the log, return zero
 *   with the lock released, which indicates that fallback to send_complete()
 *   is needed.
 */
static off_t
get_left(kadm5_server_context *server_context, slave *s, krb5_storage *sp,
         int log_fd, uint32_t current_version,
         uint32_t *initial_verp, uint32_t *initial_timep)
{
    krb5_context context = server_context->context;
    off_t pos;
    off_t left;
    int ret;

    for (;;) {
        uint32_t ver = s->version;

        /* This acquires a read lock on success */
        ret = get_first(server_context, log_fd,
                        initial_verp, initial_timep);
        if (ret != 0)
            return -1;

        /* When the slave version is out of range, send the whole database. */
        if (ver == 0 || ver < *initial_verp || ver > current_version) {
            flock(log_fd, LOCK_UN);
            return 0;
        }

        /* Avoid seeking past the last committed record */
        if (kadm5_log_goto_end(server_context, sp) != 0 ||
            (pos = krb5_storage_seek(sp, 0, SEEK_CUR)) < 0)
            goto err;

        /*
         * First try to see if we can find it quickly by seeking to the right
         * end of the previous diff sent.
         */
        if (s->next_diff.last_version_sent > 0 &&
            s->next_diff.off_next_version > 0 &&
            s->next_diff.off_next_version < pos &&
            s->next_diff.initial_version == *initial_verp &&
            s->next_diff.initial_tstamp == *initial_timep) {
            /*
             * Sanity check that the left version matches what we wanted, the
             * log may have been truncated since.
             */
            left = s->next_diff.off_next_version;
            if (krb5_storage_seek(sp, left, SEEK_SET) != left)
                goto err;
            if (kadm5_log_next(context, sp, &ver, NULL, NULL, NULL) == 0 &&
                ver == s->next_diff.last_version_sent + 1)
                return left;
        }

        if (krb5_storage_seek(sp, pos, SEEK_SET) != pos)
            goto err;

        /*
         * Drop the lock and try to find the left entry by seeking backward
         * from the end of the end of the log.  If we succeed, re-acquire the
         * lock, update "next_diff", and retry the fast-path.
         */
        flock(log_fd, LOCK_UN);

        /* Slow path: seek backwards, entry by entry, from the end */
        for (;;) {
            enum kadm_ops op;
            uint32_t len;

            ret = kadm5_log_previous(context, sp, &ver, NULL, &op, &len);
            if (ret)
                return -1;
            left = krb5_storage_seek(sp, -16, SEEK_CUR);
            if (left < 0)
                return left;
            if (ver == s->version + 1)
                break;

            /*
             * We don't expect to reach the slave's version, unless the log
             * has been modified after we released the lock.
             */
            if (ver == s->version) {
                krb5_warnx(context, "iprop log truncated while sending diffs "
                           "to slave??  ver = %lu", (unsigned long)ver);
                return -1;
            }

            /* If we've reached the uber record, send the complete database */
            if (left == 0 || (ver == 0 && op == kadm_nop))
                return 0;
        }
        assert(ver == s->version + 1);

        /* Set up the fast-path pre-conditions */
        s->next_diff.last_version_sent = s->version;
        s->next_diff.off_next_version = left;
        s->next_diff.initial_version = *initial_verp;
        s->next_diff.initial_tstamp = *initial_timep;

        /*
         * If we loop then we're hoping to hit the fast path so we can return a
         * non-zero, positive left offset with the lock held.
         *
         * We just updated the fast path pre-conditions, so unless a log
         * truncation event happens between the point where we dropped the lock
         * and the point where we rearcuire it above, we will hit the fast
         * path.
         */
    }

 err:
    flock(log_fd, LOCK_UN);
    return -1;
}

static off_t
get_right(krb5_context context, int log_fd, krb5_storage *sp,
          int lastver, slave *s, off_t left, uint32_t *verp)
{
    int ret = 0;
    int i = 0;
    uint32_t ver = s->version;
    off_t right = krb5_storage_seek(sp, left, SEEK_SET);

    if (right <= 0) {
        flock(log_fd, LOCK_UN);
        return -1;
    }

    /* The "lastver" bound should preclude us reaching EOF */
    for (; ret == 0 && i < SEND_DIFFS_MAX_RECORDS && ver < lastver; ++i) {
        uint32_t logver;

        ret = kadm5_log_next(context, sp, &logver, NULL, NULL, NULL);
        if (logver != ++ver)
            ret = KADM5_LOG_CORRUPT;
    }

    if (ret == 0)
        right = krb5_storage_seek(sp, 0, SEEK_CUR);
    else
        right = -1;
    if (right <= 0) {
        flock(log_fd, LOCK_UN);
        return -1;
    }
    *verp = ver;
    return right;
}

static void
send_diffs(kadm5_server_context *server_context, slave *s, int log_fd,
           const char *database, uint32_t current_version)
{
    krb5_context context = server_context->context;
    krb5_storage *sp;
    uint32_t initial_version;
    uint32_t initial_tstamp;
    uint32_t ver = 0;
    off_t left = 0;
    off_t right = 0;
    krb5_ssize_t bytes;
    krb5_data data;
    int ret = 0;

    if (!diffready(context, s) || nodiffs(context, s, current_version))
        return;

    if (verbose)
        krb5_warnx(context, "sending diffs to live-seeming slave %s", s->name);

    sp = krb5_storage_from_fd(log_fd);
    if (sp == NULL)
        krb5_err(context, IPROPD_RESTART_SLOW, ENOMEM,
                 "send_diffs: out of memory");

    left = get_left(server_context, s, sp, log_fd, current_version,
                    &initial_version, &initial_tstamp);
    if (left < 0) {
        krb5_storage_free(sp);
        slave_dead(context, s);
        return;
    }

    if (left == 0) {
        /* Slave's version is not in the log, fall back on send_complete() */
        krb5_storage_free(sp);
        send_complete(context, s, database, current_version,
                      initial_version, initial_tstamp);
        return;
    }

    /* We still hold the read lock, if right > 0 */
    right = get_right(server_context->context, log_fd, sp, current_version,
                      s, left, &ver);
    if (right == left) {
        flock(log_fd, LOCK_UN);
        krb5_storage_free(sp);
        return;
    }
    if (right < left) {
        assert(right < 0);
        krb5_storage_free(sp);
        slave_dead(context, s);
        return;
    }

    if (krb5_storage_seek(sp, left, SEEK_SET) != left) {
        ret = errno ? errno : EIO;
        flock(log_fd, LOCK_UN);
        krb5_warn(context, ret, "send_diffs: krb5_storage_seek");
        krb5_storage_free(sp);
        slave_dead(context, s);
        return;
    }

    ret = krb5_data_alloc(&data, right - left + 4);
    if (ret) {
        flock(log_fd, LOCK_UN);
        krb5_warn(context, ret, "send_diffs: krb5_data_alloc");
        krb5_storage_free(sp);
        slave_dead(context, s);
        return;
    }

    bytes = krb5_storage_read(sp, (char *)data.data + 4, data.length - 4);
    flock(log_fd, LOCK_UN);
    krb5_storage_free(sp);
    if (bytes != data.length - 4)
        krb5_errx(context, IPROPD_RESTART, "locked log truncated???");

    sp = krb5_storage_from_data(&data);
    if (sp == NULL) {
        krb5_err(context, IPROPD_RESTART_SLOW, ENOMEM, "out of memory");
        return;
    }
    ret = krb5_store_uint32(sp, FOR_YOU);
    krb5_storage_free(sp);

    if (ret == 0)
	ret = mk_priv_tail(context, s, &data);
    krb5_data_free(&data);
    if (ret == 0) {
        /* Save the fast-path continuation */
        s->next_diff.last_version_sent = ver;
        s->next_diff.off_next_version = right;
        s->next_diff.initial_version = initial_version;
        s->next_diff.initial_tstamp = initial_tstamp;
        s->next_diff.more = ver < current_version;
        ret = send_tail(context, s);

        krb5_warnx(context,
                   "syncing slave %s from version %lu to version %lu",
                   s->name, (unsigned long)s->version,
                   (unsigned long)ver);
        s->version = ver;
    }

    if (ret && ret != EWOULDBLOCK) {
        krb5_warn(context, ret, "send_diffs: making or sending "
                  "KRB-PRIV message");
        slave_dead(context, s);
        return;
    }
    slave_seen(s);
    return;
}

/* Sensible bound on slave message size */
#define SLAVE_MSG_MAX 65536

static int
fill_input(krb5_context context, slave *s)
{
    krb5_error_code ret;

    if (s->input.hlen < 4) {
        uint8_t *buf = s->input.header_buf + s->input.hlen;
        size_t len = 4 - s->input.hlen;
        krb5_ssize_t bytes = krb5_net_read(context, &s->fd, buf, len);

        if (bytes == 0)
            return HEIM_ERR_EOF;
        if (bytes < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                return EWOULDBLOCK;
            return errno ? errno : EIO;
        }
        s->input.hlen += bytes;
        if (bytes < len)
            return EWOULDBLOCK;

        buf = s->input.header_buf;
        len = ((unsigned long)buf[0] << 24) | (buf[1] << 16)
	    | (buf[2] << 8) | buf[3];
        if (len > SLAVE_MSG_MAX)
            return EINVAL;
        ret = krb5_data_alloc(&s->input.packet, len);
        if (ret != 0)
            return ret;
    }

    if (s->input.offset < s->input.packet.length) {
        u_char *buf = (u_char *)s->input.packet.data + s->input.offset;
        size_t len = s->input.packet.length - s->input.offset;
        krb5_ssize_t bytes = krb5_net_read(context, &s->fd, buf, len);

        if (bytes == 0)
            return HEIM_ERR_EOF;
        if (bytes < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                return EWOULDBLOCK;
            return errno ? errno : EIO;
        }
        s->input.offset += bytes;
        if (bytes != len)
            return EWOULDBLOCK;
    }
    return 0;
}

static int
read_msg(krb5_context context, slave *s, krb5_data *out)
{
    int ret = fill_input(context, s);

    if (ret != 0)
	return ret;

    ret = krb5_rd_priv(context, s->ac, &s->input.packet, out, NULL);

    /* Prepare for next packet */
    krb5_data_free(&s->input.packet);
    s->input.offset = 0;
    s->input.hlen = 0;

    return ret;
}

static int
process_msg(kadm5_server_context *server_context, slave *s, int log_fd,
	    const char *database, uint32_t current_version)
{
    krb5_context context = server_context->context;
    int ret = 0;
    krb5_data out;
    krb5_storage *sp;
    uint32_t tmp;

    ret = read_msg(context, s, &out);
    if (ret) {
        if (ret != EWOULDBLOCK)
            krb5_warn(context, ret, "error reading message from %s", s->name);
	return ret;
    }

    sp = krb5_storage_from_mem(out.data, out.length);
    if (sp == NULL) {
	krb5_warnx(context, "process_msg: no memory");
	krb5_data_free(&out);
	return 1;
    }
    if (krb5_ret_uint32(sp, &tmp) != 0) {
	krb5_warnx(context, "process_msg: client send too short command");
	krb5_data_free(&out);
	return 1;
    }
    switch (tmp) {
    case I_HAVE :
	ret = krb5_ret_uint32(sp, &tmp);
	if (ret != 0) {
	    krb5_warnx(context, "process_msg: client send too little I_HAVE data");
	    break;
	}
        /*
         * XXX Make the slave send the timestamp as well, and try to get it
         * here, and pass it to send_diffs().
         */
        /*
         * New slave whose version number we've not yet seen.  If the version
         * number is zero, the slave has no data, and we'll send a complete
         * database (that happens in send_diffs()).  Otherwise, we'll record a
         * non-zero initial version and attempt an incremental update.
         *
         * NOTE!: Once the slave is "ready" (its first I_HAVE has conveyed its
         * initial version), we MUST NOT update s->version to the slave's
         * I_HAVE version, since we may already have sent later updates, and
         * MUST NOT send them again, otherwise we can get further and further
         * out of sync resending larger and larger diffs.  The "not yet ready"
         * is an essential precondition for setting s->version to the value
         * in the I_HAVE message.  This happens only once when the slave
         * first connects.
         */
	if (!(s->flags & SLAVE_F_READY)) {
	    if (current_version < tmp) {
		krb5_warnx(context, "Slave %s (version %u) has later version "
			   "than the master (version %u) OUT OF SYNC",
			   s->name, tmp, current_version);
                /* Force send_complete() */
                tmp = 0;
	    }
            /*
             * Mark the slave as ready for updates based on incoming signals.
             * Prior to the initial I_HAVE, we don't know the slave's version
             * number, and MUST not send it anything, since we'll needlessly
             * attempt to send the whole database!
             */
	    s->version = tmp;
            s->flags |= SLAVE_F_READY;
            if (verbose)
                krb5_warnx(context, "slave %s ready for updates from version %u",
                           s->name, tmp);
	}
        if ((s->version_ack = tmp) < s->version)
            break;
        send_diffs(server_context, s, log_fd, database, current_version);
        break;
    case I_AM_HERE :
        if (verbose)
            krb5_warnx(context, "slave %s is there", s->name);
	break;
    case ARE_YOU_THERE:
    case FOR_YOU :
    default :
	krb5_warnx(context, "Ignoring command %d", tmp);
	break;
    }

    krb5_data_free(&out);
    krb5_storage_free(sp);

    slave_seen(s);

    return ret;
}

#define SLAVE_NAME	"Name"
#define SLAVE_ADDRESS	"Address"
#define SLAVE_VERSION	"Version"
#define SLAVE_STATUS	"Status"
#define SLAVE_SEEN	"Last Seen"

static void
init_stats_names(krb5_context context)
{
    const char *fn = NULL;
    char *buf = NULL;

    if (slave_stats_file)
	fn = slave_stats_file;
    else if ((fn = krb5_config_get_string(context, NULL, "kdc",
                                          "iprop-stats", NULL)) == NULL) {
        if (asprintf(&buf, "%s/slaves-stats", hdb_db_dir(context)) != -1
	    && buf != NULL)
            fn = buf;
        buf = NULL;
    }
    if (fn != NULL) {
        slave_stats_file = fn;
        if (asprintf(&buf, "%s.tmp", fn) != -1 && buf != NULL)
            slave_stats_temp_file = buf;
    }
}

static void
write_master_down(krb5_context context)
{
    char str[100];
    time_t t = time(NULL);
    FILE *fp = NULL;

    if (slave_stats_temp_file != NULL)
        fp = fopen(slave_stats_temp_file, "w");
    if (fp == NULL)
	return;
    if (krb5_format_time(context, t, str, sizeof(str), TRUE) == 0)
        fprintf(fp, "master down at %s\n", str);
    else
        fprintf(fp, "master down\n");

    if (fclose(fp) != EOF)
        (void) rk_rename(slave_stats_temp_file, slave_stats_file);
}

static void
write_stats(krb5_context context, slave *slaves, uint32_t current_version)
{
    char str[100];
    rtbl_t tbl;
    time_t t = time(NULL);
    FILE *fp = NULL;

    if (slave_stats_temp_file != NULL)
        fp = fopen(slave_stats_temp_file, "w");
    if (fp == NULL)
	return;

    if (krb5_format_time(context, t, str, sizeof(str), TRUE))
        snprintf(str, sizeof(str), "<unknown-time>");
    fprintf(fp, "Status for slaves, last updated: %s\n\n", str);

    fprintf(fp, "Master version: %lu\n\n", (unsigned long)current_version);

    tbl = rtbl_create();
    if (tbl == NULL) {
	fclose(fp);
	return;
    }

    rtbl_add_column(tbl, SLAVE_NAME, 0);
    rtbl_add_column(tbl, SLAVE_ADDRESS, 0);
    rtbl_add_column(tbl, SLAVE_VERSION, RTBL_ALIGN_RIGHT);
    rtbl_add_column(tbl, SLAVE_STATUS, 0);
    rtbl_add_column(tbl, SLAVE_SEEN, 0);

    rtbl_set_prefix(tbl, "  ");
    rtbl_set_column_prefix(tbl, SLAVE_NAME, "");

    while (slaves) {
	krb5_address addr;
	krb5_error_code ret;
	rtbl_add_column_entry(tbl, SLAVE_NAME, slaves->name);
	ret = krb5_sockaddr2address (context,
				     (struct sockaddr*)&slaves->addr, &addr);
	if(ret == 0) {
	    krb5_print_address(&addr, str, sizeof(str), NULL);
	    krb5_free_address(context, &addr);
	    rtbl_add_column_entry(tbl, SLAVE_ADDRESS, str);
	} else
	    rtbl_add_column_entry(tbl, SLAVE_ADDRESS, "<unknown>");

	snprintf(str, sizeof(str), "%u", (unsigned)slaves->version_ack);
	rtbl_add_column_entry(tbl, SLAVE_VERSION, str);

	if (slaves->flags & SLAVE_F_DEAD)
	    rtbl_add_column_entry(tbl, SLAVE_STATUS, "Down");
	else
	    rtbl_add_column_entry(tbl, SLAVE_STATUS, "Up");

	ret = krb5_format_time(context, slaves->seen, str, sizeof(str), TRUE);
        if (ret)
            rtbl_add_column_entry(tbl, SLAVE_SEEN, "<error-formatting-time>");
        else
            rtbl_add_column_entry(tbl, SLAVE_SEEN, str);

	slaves = slaves->next;
    }

    rtbl_format(tbl, fp);
    rtbl_destroy(tbl);

    if (fclose(fp) != EOF)
        (void) rk_rename(slave_stats_temp_file, slave_stats_file);
}


static char sHDB[] = "HDBGET:";
static char *realm;
static int version_flag;
static int help_flag;
static char *keytab_str = sHDB;
static char *database;
static char *config_file;
static char *port_str;
static int detach_from_console;
static int daemon_child = -1;

static struct getargs args[] = {
    { "config-file", 'c', arg_string, &config_file, NULL, NULL },
    { "realm", 'r', arg_string, &realm, NULL, NULL },
    { "keytab", 'k', arg_string, &keytab_str,
      "keytab to get authentication from", "kspec" },
    { "database", 'd', arg_string, &database, "database", "file"},
    { "slave-stats-file", 0, arg_string, rk_UNCONST(&slave_stats_file),
      "file for slave status information", "file"},
    { "time-missing", 0, arg_string, rk_UNCONST(&slave_time_missing),
      "time before slave is polled for presence", "time"},
    { "time-gone", 0, arg_string, rk_UNCONST(&slave_time_gone),
      "time of inactivity after which a slave is considered gone", "time"},
    { "port", 0, arg_string, &port_str,
      "port ipropd will listen to", "port"},
    { "detach", 0, arg_flag, &detach_from_console,
      "detach from console", NULL },
    { "daemon-child", 0, arg_integer, &daemon_child,
      "private argument, do not use", NULL },
    { "pidfile-basename", 0, arg_string, &pidfile_basename,
      "basename of pidfile; private argument for testing", "NAME" },
    { "hostname", 0, arg_string, rk_UNCONST(&master_hostname),
      "hostname of master (if not same as hostname)", "hostname" },
    { "verbose", 0, arg_flag, &verbose, NULL, NULL },
    { "version", 0, arg_flag, &version_flag, NULL, NULL },
    { "help", 0, arg_flag, &help_flag, NULL, NULL }
};
static int num_args = sizeof(args) / sizeof(args[0]);

int
main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    void *kadm_handle;
    kadm5_server_context *server_context;
    kadm5_config_params conf;
    krb5_socket_t signal_fd, listen_fd;
    int log_fd;
    slave *slaves = NULL;
    uint32_t current_version = 0, old_version = 0;
    krb5_keytab keytab;
    char **files;
    int aret;
    int optidx = 0;
    int restarter_fd = -1;
    struct stat st;

    setprogname(argv[0]);

    if (getarg(args, num_args, argc, argv, &optidx))
        krb5_std_usage(1, args, num_args);

    if (help_flag)
	krb5_std_usage(0, args, num_args);

    if (version_flag) {
	print_version(NULL);
	exit(0);
    }

    memset(hostname, 0, sizeof(hostname));

    if (master_hostname &&
        strlcpy(hostname, master_hostname,
                sizeof(hostname)) >= sizeof(hostname)) {
        errx(1, "Hostname too long: %s", master_hostname);
    } else if (master_hostname == NULL) {
        if (gethostname(hostname, sizeof(hostname)) == -1)
            err(1, "Could not get hostname");
        if (hostname[sizeof(hostname) - 1] != '\0')
            errx(1, "Hostname too long %.*s...",
                 (int)sizeof(hostname), hostname);
    }

    if (detach_from_console && daemon_child == -1)
        daemon_child = roken_detach_prep(argc, argv, "--daemon-child");
    rk_pidfile(pidfile_basename);

    ret = krb5_init_context(&context);
    if (ret)
        errx(1, "krb5_init_context failed: %d", ret);

    setup_signal();

    if (config_file == NULL) {
	aret = asprintf(&config_file, "%s/kdc.conf", hdb_db_dir(context));
	if (aret == -1 || config_file == NULL)
	    errx(1, "out of memory");
    }

    ret = krb5_prepend_config_files_default(config_file, &files);
    if (ret)
	krb5_err(context, 1, ret, "getting configuration files");

    ret = krb5_set_config_files(context, files);
    krb5_free_config_files(files);
    if (ret)
	krb5_err(context, 1, ret, "reading configuration files");

    init_stats_names(context);

    time_before_gone = parse_time (slave_time_gone,  "s");
    if (time_before_gone < 0)
	krb5_errx (context, 1, "couldn't parse time: %s", slave_time_gone);
    time_before_missing = parse_time (slave_time_missing,  "s");
    if (time_before_missing < 0)
	krb5_errx (context, 1, "couldn't parse time: %s", slave_time_missing);

    krb5_openlog(context, "ipropd-master", &log_facility);
    krb5_set_warn_dest(context, log_facility);

    ret = krb5_kt_register(context, &hdb_get_kt_ops);
    if(ret)
	krb5_err(context, 1, ret, "krb5_kt_register");

    ret = krb5_kt_resolve(context, keytab_str, &keytab);
    if(ret)
	krb5_err(context, 1, ret, "krb5_kt_resolve: %s", keytab_str);

    memset(&conf, 0, sizeof(conf));
    if(realm) {
	conf.mask |= KADM5_CONFIG_REALM;
	conf.realm = realm;
    }
    ret = kadm5_init_with_skey_ctx (context,
				    KADM5_ADMIN_SERVICE,
				    NULL,
				    KADM5_ADMIN_SERVICE,
				    &conf, 0, 0,
				    &kadm_handle);
    if (ret)
	krb5_err (context, 1, ret, "kadm5_init_with_password_ctx");

    server_context = (kadm5_server_context *)kadm_handle;

    log_fd = open (server_context->log_context.log_file, O_RDONLY, 0);
    if (log_fd < 0)
	krb5_err (context, 1, errno, "open %s",
		  server_context->log_context.log_file);

    if (fstat(log_fd, &st) == -1)
        krb5_err(context, 1, errno, "stat %s",
                 server_context->log_context.log_file);

    if (flock(log_fd, LOCK_SH) == -1)
        krb5_err(context, 1, errno, "shared flock %s",
                 server_context->log_context.log_file);
    kadm5_log_get_version_fd(server_context, log_fd, LOG_VERSION_LAST,
                             &current_version, NULL);
    flock(log_fd, LOCK_UN);

    signal_fd = make_signal_socket (context);
    listen_fd = make_listen_socket (context, port_str);

    krb5_warnx(context, "ipropd-master started at version: %lu",
	       (unsigned long)current_version);

    roken_detach_finish(NULL, daemon_child);
    restarter_fd = restarter(context, NULL);

    while (exit_flag == 0){
	slave *p;
	fd_set readset, writeset;
	int max_fd = 0;
	struct timeval to = {30, 0};
	uint32_t vers;
        struct stat st2;;

#ifndef NO_LIMIT_FD_SETSIZE
	if (signal_fd >= FD_SETSIZE || listen_fd >= FD_SETSIZE ||
            restarter_fd >= FD_SETSIZE)
	    krb5_errx (context, IPROPD_RESTART, "fd too large");
#endif

	FD_ZERO(&readset);
	FD_ZERO(&writeset);
	FD_SET(signal_fd, &readset);
	max_fd = max(max_fd, signal_fd);
	FD_SET(listen_fd, &readset);
	max_fd = max(max_fd, listen_fd);
        if (restarter_fd > -1) {
            FD_SET(restarter_fd, &readset);
            max_fd = max(max_fd, restarter_fd);
        }

	for (p = slaves; p != NULL; p = p->next) {
	    if (p->flags & SLAVE_F_DEAD)
		continue;
	    FD_SET(p->fd, &readset);
            if (have_tail(p) || more_diffs(p))
                FD_SET(p->fd, &writeset);
	    max_fd = max(max_fd, p->fd);
	}

	ret = select(max_fd + 1, &readset, &writeset, NULL, &to);
	if (ret < 0) {
	    if (errno == EINTR)
		continue;
	    else
		krb5_err (context, IPROPD_RESTART, errno, "select");
	}

        if (stat(server_context->log_context.log_file, &st2) == -1) {
            krb5_warn(context, errno, "could not stat log file by path");
            st2 = st;
        }

        if (st2.st_dev != st.st_dev || st2.st_ino != st.st_ino) {
            (void) close(log_fd);

            log_fd = open(server_context->log_context.log_file, O_RDONLY, 0);
            if (log_fd < 0)
                krb5_err(context, IPROPD_RESTART_SLOW, errno, "open %s",
                          server_context->log_context.log_file);

            if (fstat(log_fd, &st) == -1)
                krb5_err(context, IPROPD_RESTART_SLOW, errno, "stat %s",
                         server_context->log_context.log_file);

            if (flock(log_fd, LOCK_SH) == -1)
                krb5_err(context, IPROPD_RESTART, errno, "shared flock %s",
                         server_context->log_context.log_file);
            kadm5_log_get_version_fd(server_context, log_fd, LOG_VERSION_LAST,
                                     &current_version, NULL);
            flock(log_fd, LOCK_UN);
        }

	if (ret == 0) {
            /* Recover from failed transactions */
            if (kadm5_log_init_nb(server_context) == 0)
                kadm5_log_end(server_context);

	    if (flock(log_fd, LOCK_SH) == -1)
                krb5_err(context, IPROPD_RESTART, errno,
                         "could not lock log file");
	    kadm5_log_get_version_fd(server_context, log_fd, LOG_VERSION_LAST,
                                     &current_version, NULL);
	    flock(log_fd, LOCK_UN);

	    if (current_version > old_version) {
                if (verbose)
                    krb5_warnx(context,
                               "Missed a signal, updating slaves %lu to %lu",
                               (unsigned long)old_version,
                               (unsigned long)current_version);
		for (p = slaves; p != NULL; p = p->next) {
		    if (p->flags & SLAVE_F_DEAD)
			continue;
		    send_diffs(server_context, p, log_fd, database,
                               current_version);
		}
                old_version = current_version;
	    }
	}

        if (ret && FD_ISSET(restarter_fd, &readset)) {
            exit_flag = SIGTERM;
            break;
        }

	if (ret && FD_ISSET(signal_fd, &readset)) {
#ifndef NO_UNIX_SOCKETS
	    struct sockaddr_un peer_addr;
#else
	    struct sockaddr_storage peer_addr;
#endif
	    socklen_t peer_len = sizeof(peer_addr);

	    if(recvfrom(signal_fd, (void *)&vers, sizeof(vers), 0,
			(struct sockaddr *)&peer_addr, &peer_len) < 0) {
		krb5_warn (context, errno, "recvfrom");
		continue;
	    }
	    --ret;
	    assert(ret >= 0);
	    old_version = current_version;
	    if (flock(log_fd, LOCK_SH) == -1)
                krb5_err(context, IPROPD_RESTART, errno, "shared flock %s",
                         server_context->log_context.log_file);
	    kadm5_log_get_version_fd(server_context, log_fd, LOG_VERSION_LAST,
                                     &current_version, NULL);
	    flock(log_fd, LOCK_UN);
	    if (current_version != old_version) {
                /*
                 * If current_version < old_version then the log got
                 * truncated and we'll end up doing full propagations.
                 *
                 * Truncating the log when the current version is
                 * numerically small can lead to race conditions.
                 * Ideally we should identify log versions as
                 * {init_or_trunc_time, vno}, then we could not have any
                 * such race conditions, but this would either require
                 * breaking backwards compatibility for the protocol or
                 * adding new messages to it.
                 */
                if (verbose)
                    krb5_warnx(context,
                               "Got a signal, updating slaves %lu to %lu",
                               (unsigned long)old_version,
                               (unsigned long)current_version);
		for (p = slaves; p != NULL; p = p->next) {
		    if (p->flags & SLAVE_F_DEAD)
			continue;
		    send_diffs(server_context, p, log_fd, database,
                               current_version);
		}
	    } else {
                if (verbose)
                    krb5_warnx(context,
                               "Got a signal, but no update in log version %lu",
                               (unsigned long)current_version);
	    }
        }

	for (p = slaves; p != NULL; p = p->next) {
            if (!(p->flags & SLAVE_F_DEAD) &&
                FD_ISSET(p->fd, &writeset) &&
                ((have_tail(p) && send_tail(context, p) == 0) ||
                 (!have_tail(p) && more_diffs(p)))) {
                send_diffs(server_context, p, log_fd, database,
                           current_version);
            }
        }

	for(p = slaves; p != NULL; p = p->next) {
	    if (p->flags & SLAVE_F_DEAD)
	        continue;
	    if (ret && FD_ISSET(p->fd, &readset)) {
		--ret;
		assert(ret >= 0);
                ret = process_msg(server_context, p, log_fd, database,
                                  current_version);
                if (ret && ret != EWOULDBLOCK)
		    slave_dead(context, p);
	    } else if (slave_gone_p (p))
		slave_dead(context, p);
	    else if (slave_missing_p (p))
		send_are_you_there (context, p);
	}

	if (ret && FD_ISSET(listen_fd, &readset)) {
	    add_slave (context, keytab, &slaves, listen_fd);
	    --ret;
	    assert(ret >= 0);
	}
	write_stats(context, slaves, current_version);
    }

    if(exit_flag == SIGINT || exit_flag == SIGTERM)
	krb5_warnx(context, "%s terminated", getprogname());
#ifdef SIGXCPU
    else if(exit_flag == SIGXCPU)
	krb5_warnx(context, "%s CPU time limit exceeded", getprogname());
#endif
    else
	krb5_warnx(context, "%s unexpected exit reason: %ld",
		   getprogname(), (long)exit_flag);

    write_master_down(context);

    return 0;
}
