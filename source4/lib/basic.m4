dnl # LIB BASIC subsystem

SMB_SUBSYSTEM(LIBBASIC,[lib/version.o],
		[lib/debug.o lib/fault.o \
		lib/getsmbpass.o lib/interface.o lib/md4.o \
		lib/interfaces.o lib/pidfile.o lib/replace.o \
		lib/signal.o lib/system.o lib/sendfile.o lib/time.o \
		lib/genrand.o lib/username.o \
		lib/util_getent.o lib/util_pw.o lib/smbrun.o \
		lib/bitmap.o lib/crc32.o lib/snprintf.o lib/dprintf.o \
		lib/xfile.o lib/wins_srv.o \
		lib/util_str.o lib/util_sid.o lib/util_uuid.o \
		lib/util_unistr.o lib/util_file.o lib/data_blob.o \
		lib/util.o lib/util_sock.o \
		lib/talloc.o lib/substitute.o lib/fsusage.o \
		lib/ms_fnmatch.o lib/select.o lib/messages.o \
		lib/tallocmsg.o lib/dmallocmsg.o \
		lib/md5.o lib/hmacmd5.o lib/smbpasswd.o \
		nsswitch/wb_client.o nsswitch/wb_common.o \
		lib/pam_errors.o intl/lang_tdb.o lib/account_pol.o \
		lib/gencache.o lib/module.o lib/mutex.o \
		lib/ldap_escape.o lib/events.o \
		lib/tdb/tdb.o lib/tdb/spinlock.o lib/tdb/tdbutil.o \$(CHARSET_OBJS)],
		lib/libbasic_public_proto.h)
