if test x"$with_ldap_support" = x"yes"; then
SMB_SUBSYSTEM(LIBLDB_LDAP,[lib/ldb/ldb_ldap/ldb_ldap.o])
fi

SMB_SUBSYSTEM(LIBLDB,[lib/ldb/common/ldb.o],
		[lib/ldb/common/ldb_ldif.o \
		lib/ldb/common/ldb_parse.o \
		lib/ldb/common/ldb_msg.o \
		lib/ldb/common/util.o \
		lib/ldb/common/ldb_utf8.o \
		lib/ldb/common/ldb_alloc.o \
		lib/ldb/ldb_tdb/ldb_search.o \
		lib/ldb/ldb_tdb/ldb_tdb.o \
		lib/ldb/ldb_tdb/ldb_pack.o \
		lib/ldb/ldb_tdb/ldb_index.o \
		lib/ldb/ldb_tdb/ldb_match.o \
		lib/ldb/ldb_tdb/ldb_cache.o \
	        \$(LIBLDB_LDAP_OBJS)],
		lib/ldb/include/ldb.h)

SMB_SUBSYSTEM(LDBADD,[],
		[lib/ldb/tools/ldbadd.o \
		\$(LIBBASIC_OBJS) \$(LIBSMB_OBJS) \$(CONFIG_OBJS) \$(LIBLDB_OBJS)],
		lib/ldb/include/proto.h)

SMB_SUBSYSTEM(LDBDEL,[],
		[lib/ldb/tools/ldbdel.o \
		\$(LIBBASIC_OBJS) \$(LIBSMB_OBJS) \$(CONFIG_OBJS) \$(LIBLDB_OBJS)],
		lib/ldb/include/proto.h)

SMB_SUBSYSTEM(LDBMODIFY,[],
		[lib/ldb/tools/ldbmodify.o \
		\$(LIBBASIC_OBJS) \$(LIBSMB_OBJS) \$(CONFIG_OBJS) \$(LIBLDB_OBJS)],
		lib/ldb/include/proto.h)

SMB_SUBSYSTEM(LDBSEARCH,[],
		[lib/ldb/tools/ldbsearch.o \
		\$(LIBBASIC_OBJS) \$(LIBSMB_OBJS) \$(CONFIG_OBJS) \$(LIBLDB_OBJS)],
		lib/ldb/include/proto.h)

SMB_SUBSYSTEM(LDBEDIT,[],
		[lib/ldb/tools/ldbedit.o \
		\$(LIBBASIC_OBJS) \$(LIBSMB_OBJS) \$(CONFIG_OBJS) \$(LIBLDB_OBJS)],
		lib/ldb/include/proto.h)
