[SUBSYSTEM::LIBWBCLIENT]
PUBLIC_DEPENDENCIES = LIBTALLOC

LIBWBCLIENT_OBJ_FILES = $(addprefix $(libwbclientsrcdir)/, wbc_guid.o \
								wbc_idmap.o \
								wbclient.o \
								wbc_pam.o \
								wbc_pwd.o \
								wbc_sid.o \
								wbc_util.o )

[SUBSYSTEM::LIBWBCLIENT_ASYNC]
PUBLIC_DEPENDENCIES = LIBASYNC_REQ \
		      LIBTEVENT \
		      LIBTALLOC \
		      UTIL_TEVENT \
		      LIBWBCLIENT

LIBWBCLIENT_ASYNC_OBJ_FILES = $(addprefix $(libwbclientsrcdir)/, wbc_async.o \
								wbc_idmap_async.o \
								wbc_pam_async.o \
								wbc_sid_async.o \
								wbc_util_async.o \
								wb_reqtrans.o )
