
BUILT_SOURCES = vi.h emacs.h common.h fcns.h help.h func.h

AHDR= vi.h emacs.h common.h 
ASRC= $(srcdir)/vi.c $(srcdir)/emacs.c $(srcdir)/common.c

vi.h: Makefile $(srcdir)/makelist $(srcdir)/vi.c
	AWK=$(AWK) sh $(srcdir)/makelist -h $(srcdir)/vi.c > $@

emacs.h: Makefile $(srcdir)/makelist $(srcdir)/emacs.c
	AWK=$(AWK) sh $(srcdir)/makelist -h $(srcdir)/emacs.c > $@

common.h: Makefile $(srcdir)/makelist $(srcdir)/common.c
	AWK=$(AWK) sh $(srcdir)/makelist -h $(srcdir)/common.c > $@

fcns.h: Makefile $(srcdir)/makelist $(AHDR)
	AWK=$(AWK) sh $(srcdir)/makelist -fh $(AHDR) > $@

func.h: Makefile $(srcdir)/makelist $(AHDR)
	AWK=$(AWK) sh $(srcdir)/makelist -fc $(AHDR) > $@

help.h: Makefile $(srcdir)/makelist $(ASRC)
	AWK=$(AWK) sh $(srcdir)/makelist -bh $(ASRC) > $@

CLEANFILES = $(BUILT_SOURCES)

lib_LTLIBRARIES    = libheimedit.la
libheimedit_la_SOURCES = \
    chared.c chartype.c common.c el.c eln.c emacs.c filecomplete.c getline.c hist.c \
    history.c historyn.c keymacro.c map.c parse.c prompt.c read.c readline.c \
    refresh.c search.c sig.c terminal.c tokenizer.c tokenizern.c tty.c \
    unvis.c vi.c vis.c wcsdup.c \
    chared.h chartype.h readline/readline.h el.h filecomplete.h \
    histedit.h hist.h keymacro.h map.h parse.h prompt.h read.h \
    refresh.h search.h sig.h sys.h terminal.h tty.h vis.h

EXTRA_DIST = makelist shlib_version
EXTRA_DIST += histedit.h readline/readline.h

nodist_libheimedit_la_SOURCES = $(BUILT_SOURCES)

libheimedit_la_LDFLAGS = -no-undefined -version-info $(LT_VERSION)

