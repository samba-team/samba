# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include $(INCLUDE_krb4)

CFLAGS = @CFLAGS@ $(WFLAGS)

noinst_PROGRAMS = pop_debug

libexec_PROGRAMS = popper

popper_SOURCES = \
	pop_dele.c pop_dropcopy.c pop_dropinfo.c \
	pop_get_command.c pop_init.c \
	pop_last.c pop_list.c pop_log.c \
	pop_msg.c pop_parse.c pop_pass.c pop_quit.c \
	pop_rset.c pop_send.c pop_stat.c pop_updt.c \
	pop_user.c pop_uidl.c pop_xover.c popper.c \
	maildir.c

LDADD = -L$(top_builddir)/lib/krb5 -lkrb5 $(LIB_otp) -L$(top_builddir)/lib/des -ldes $(LIB_krb4) -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/roken -lroken $(DBLIB)
