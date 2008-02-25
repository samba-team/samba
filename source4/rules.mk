# Dependencies command
DEPENDS = $(CC) -M -MG -MP -MT $(<:.c=.o) -MT $@ \
    $(CFLAGS) $(CPPFLAGS) $(FIRST_PREREQ) -o $@
# Dependencies for host objects
HDEPENDS = $(CC) -M -MG -MP -MT $(<:.c=.ho) -MT $@ \
    $(HOSTCC_FLAGS) $(CPPFLAGS) $(FIRST_PREREQ) -o $@
# Dependencies for precompiled headers
PCHDEPENDS = $(CC) -M -MG -MT include/includes.h.gch -MT $@ \
    $(CFLAGS) $(CPPFLAGS) $(FIRST_PREREQ) -o $@

# $< is broken in older BSD versions:
# when $@ is foo/bar.o, $< could be torture/foo/bar.c
# if it also exists. So better use $* which is foo/bar
# and append .c manually to get foo/bar.c
#
# If we have GNU Make, it is safe to use $<, which also lets
# building with $srcdir != $builddir work.

# Run a static analysis checker
CHECK = $(CC_CHECKER) $(CFLAGS) $(PICFLAG) $(CPPLAGS) -c $(FIRST_PREREQ) -o $@

# Run the configured compiler
COMPILE = $(CC) $(CFLAGS) $(PICFLAG) \
		  $(CPPFLAGS) \
		  -c $(FIRST_PREREQ) -o $@

# Run the compiler for the build host
HCOMPILE = $(HOSTCC) $(HOSTCC_FLAGS) $(CPPFLAGS) -c $(FIRST_PREREQ) -o $@

# Precompile headers
PCHCOMPILE = @$(CC) -Ilib/replace \
    $(CFLAGS) $(PICFLAG) $(CPPFLAGS) -c $(FIRST_PREREQ) -o $@

# Partial linking
PARTLINK = @$(PROG_LD) -r

include/config.h:
	@echo "include/config.h not present"
	@echo "You need to rerun ./autogen.sh and ./configure"
	@/bin/false

$(srcdir)/version.h: $(srcdir)/VERSION
	@$(SHELL) script/mkversion.sh VERSION $(srcdir)/version.h $(srcdir)/

regen_version::
	@$(SHELL) script/mkversion.sh VERSION $(srcdir)/version.h $(srcdir)/

clean_pch::
	@echo "Removing precompiled headers"
	@-rm -f include/includes.h.gch

pch:: clean_pch include/includes.h.gch

clean:: clean_pch
	@echo Removing objects
	@-find . -name '*.o' -exec rm -f '{}' \;
	@echo Removing hostcc objects
	@-find . -name '*.ho' -exec rm -f '{}' \;
	@echo Removing binaries
	@-rm -f $(BIN_PROGS) $(SBIN_PROGS) $(BINARIES) $(TORTURE_PROGS)
	@echo Removing libraries
	@-rm -f $(STATIC_LIBRARIES) $(SHARED_LIBRARIES)
	@-rm -f bin/static/*.a bin/shared/*.$(SHLIBEXT) bin/mergedobj/*.o
	@echo Removing modules
	@-rm -f bin/modules/*/*.$(SHLIBEXT)
	@-rm -f bin/*_init_module.c
	@echo Removing dummy targets
	@-rm -f bin/.*_*
	@echo Removing generated files
	@-rm -f bin/*_init_module.c
	@-rm -rf librpc/gen_* 
	@echo Removing proto headers
	@-rm -f $(PROTO_HEADERS)

distclean:: clean
	-rm -f include/config.h include/config_tmp.h include/build.h
	-rm -f data.mk
	-rm -f config.status
	-rm -f config.log config.cache
	-rm -f config.pm config.mk
	-rm -f $(PC_FILES)

removebackup::
	-rm -f *.bak *~ */*.bak */*~ */*/*.bak */*/*~ */*/*/*.bak */*/*/*~

realdistclean:: distclean removebackup
	-rm -f include/config_tmp.h.in
	-rm -f version.h
	-rm -f configure
	-rm -f $(MANPAGES)

check:: test

unused_macros:
	$(srcdir)/script/find_unused_macros.pl `find . -name "*.[ch]"` | sort

# Create a static library
%.a:
	@echo Linking $@
	@rm -f $@
	@mkdir -p $(@D)
	@$(STLD) $(STLD_FLAGS) $@ $^

###############################################################################
# File types
###############################################################################

.SUFFIXES: .x .c .et .y .l .d .o .h .h.gch .a .$(SHLIBEXT) .1 .1.xml .3 .3.xml .5 .5.xml .7 .7.xml .8 .8.xml .ho .idl .hd

.c.d:
	@echo "Generating dependencies for $<"
	@$(DEPENDS)

.c.hd:
	@echo "Generating host-compiler dependencies for $<"
	@$(HDEPENDS)

include/includes.d: include/includes.h
	@echo "Generating dependencies for $<"
	@$(PCHDEPENDS)

.c.o:
	@if test -n "$(CC_CHECKER)"; then \
		echo "Checking  $< with '$(CC_CHECKER)'"; \
		$(CHECK) ; \
	fi
	@echo "Compiling $<"
	@-mkdir -p `dirname $@`
	@$(COMPILE) && exit 0 ; \
		echo "The following command failed:" 1>&2;\
		echo "$(COMPILE)" 1>&2;\
		$(COMPILE) >/dev/null 2>&1

.c.ho:
	@echo "Compiling $< with host compiler"
	@-mkdir -p `dirname $@`
	@$(HCOMPILE) && exit 0;\
		echo "The following command failed:" 1>&2;\
		echo "$(HCOMPILE)" 1>&2;\
		$(HCOMPILE) >/dev/null 2>&1

.h.h.gch:
	@echo "Precompiling $<"
	@$(PCHCOMPILE)

.y.c:
	@echo "Building $< with $(YACC)"
	@-$(srcdir)/script/yacc_compile.sh "$(YACC)" "$<" "$@"

.l.c:
	@echo "Building $< with $(LEX)"
	@-$(srcdir)/script/lex_compile.sh "$(LEX)" "$<" "$@"

DOCBOOK_MANPAGE_URL = http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl

.1.xml.1:
	$(XSLTPROC) -o $@ $(DOCBOOK_MANPAGE_URL) $<

.3.xml.3:
	$(XSLTPROC) -o $@ $(DOCBOOK_MANPAGE_URL) $<

.5.xml.5:
	$(XSLTPROC) -o $@ $(DOCBOOK_MANPAGE_URL) $<

.7.xml.7:
	$(XSLTPROC) -o $@ $(DOCBOOK_MANPAGE_URL) $<

.8.xml.8:
	$(XSLTPROC) -o $@ $(DOCBOOK_MANPAGE_URL) $<

dist:: idl_full manpages configure distclean 

configure: 
	./autogen.sh

showflags::
	@echo 'Samba will be compiled with flags:'
	@echo '  CPP        = $(CPP)'
	@echo '  CPPFLAGS   = $(CPPFLAGS)'
	@echo '  CC         = $(CC)'
	@echo '  CFLAGS     = $(CFLAGS)'
	@echo '  PICFLAG    = $(PICFLAG)'
	@echo '  BNLD       = $(BNLD)'
	@echo '  BNLD_FLAGS = $(BNLD_FLAGS)'
	@echo '  STLD       = $(STLD)'
	@echo '  STLD_FLAGS = $(STLD_FLAGS)'
	@echo '  SHLD       = $(SHLD)'
	@echo '  SHLD_FLAGS = $(SHLD_FLAGS)'
	@echo '  MDLD       = $(MDLD)'
	@echo '  MDLD_FLAGS = $(MDLD_FLAGS)'
	@echo '  SHLIBEXT   = $(SHLIBEXT)'

etags:
	etags `find $(srcdir) -name "*.[ch]"`

ctags:
	ctags `find $(srcdir) -name "*.[ch]"`
