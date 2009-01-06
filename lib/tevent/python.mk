# TODO: Change python stuff to tevent
[PYTHON::swig_events]
LIBRARY_REALNAME = tevent.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = LIBTEVENT PYTALLOC LIBSAMBA-UTIL LIBREPLACE

swig_events_OBJ_FILES = $(libteventsrcdir)/pytevent.o

$(swig_events_OBJ_FILES): CFLAGS+=$(CFLAG_NO_CAST_QUAL)

PC_FILES += $(libteventsrcdir)/tevent.pc
