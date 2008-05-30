[SUBSYSTEM::TDR]
PUBLIC_DEPENDENCIES = LIBTALLOC LIBSAMBA-UTIL

TDR_OBJ_FILES = $(libtdrsrcdir)/tdr.o
$(TDR_OBJ_FILES): CFLAGS+=-I$(libtdrsrcdir)

$(eval $(call proto_header_template,$(libtdrsrcdir)/tdr_proto.h,$(TDR_OBJ_FILES:.o=.c)))

PUBLIC_HEADERS += $(libtdrsrcdir)/tdr.h
