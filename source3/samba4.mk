# samba 4 bits

PROG_LD = $(LD)
BNLD = $(CC)
HOSTLD = $(CC)
PARTLINK = $(PROG_LD) -r
MDLD = $(SHLD)
MDLD_FLAGS = $(LDSHFLAGS) 

samba4srcdir = $(call abspath,$(srcdir)/../source4)

# Flags used for the samba 4 files
# $(srcdir)/include is required for config.h
SAMBA4_CFLAGS = -I$(samba4srcdir) -I$(samba4srcdir)/include \
		 -I$(samba4srcdir)/../lib/replace -I$(samba4srcdir)/lib \
		 -I$(heimdalsrcdir)/lib/hcrypto -I$(tallocdir) \
		 -I$(srcdir)/include -D_SAMBA_BUILD_=4 -DHAVE_CONFIG_H

.SUFFIXES: .ho

# No cross compilation for now, thanks
.c.ho:
	@if (: >> $@ || : > $@) >/dev/null 2>&1; then rm -f $@; else \
	 dir=`echo $@ | sed 's,/[^/]*$$,,;s,^$$,.,'` $(MAKEDIR); fi
	@if test -n "$(CC_CHECKER)"; then \
	  echo "Checking  $*.c with '$(CC_CHECKER)'";\
	  $(CHECK_CC); \
	 fi
	@echo Compiling $*.c
	@$(COMPILE) && exit 0;\
		echo "The following command failed:" 1>&2;\
		echo "$(subst ",\",$(COMPILE_CC))" 1>&2;\
		$(COMPILE_CC) >/dev/null 2>&1

# The order really does matter here! GNU Make 3.80 will break if the more specific 
# overrides are not specified first.
ifeq ($(MAKE_VERSION),3.81)
%.o: CFLAGS+=$(FLAGS)
$(samba4srcdir)/%.o: CFLAGS=$(SAMBA4_CFLAGS)
$(samba4srcdir)/%.ho: CFLAGS=$(SAMBA4_CFLAGS)
$(heimdalsrcdir)/%.o: CFLAGS=-I$(heimdalbuildsrcdir) $(SAMBA4_CFLAGS) -I$(srcdir)
$(heimdalsrcdir)/%.ho: CFLAGS=-I$(heimdalbuildsrcdir) $(SAMBA4_CFLAGS) -I$(srcdir)
else
$(heimdalsrcdir)/%.o: CFLAGS=-I$(heimdalbuildsrcdir) $(SAMBA4_CFLAGS) -I$(srcdir)
$(heimdalsrcdir)/%.ho: CFLAGS=-I$(heimdalbuildsrcdir) $(SAMBA4_CFLAGS) -I$(srcdir)
$(samba4srcdir)/%.o: CFLAGS=$(SAMBA4_CFLAGS)
$(samba4srcdir)/%.ho: CFLAGS=$(SAMBA4_CFLAGS)
%.o: CFLAGS+=$(FLAGS)
endif

# Create a static library
%.a:
	@echo Linking $@
	@rm -f $@
	@mkdir -p $(@D)
	@$(AR) -rc $@ $^

INTERN_LDFLAGS = -L${builddir}/bin/static -L${builddir}/bin/shared

pidldir = $(samba4srcdir)/pidl
include $(pidldir)/config.mk
include samba4-config.mk
include samba4-templates.mk

zlibsrcdir := $(samba4srcdir)/lib/zlib
dynconfigsrcdir := $(samba4srcdir)/dynconfig
heimdalsrcdir := $(samba4srcdir)/heimdal
dsdbsrcdir := $(samba4srcdir)/dsdb
smbdsrcdir := $(samba4srcdir)/smbd
clustersrcdir := $(samba4srcdir)/cluster
libnetsrcdir := $(samba4srcdir)/libnet
authsrcdir := $(samba4srcdir)/auth
nsswitchsrcdir := $(samba4srcdir)/nsswitch
libsrcdir := $(samba4srcdir)/lib
libsocketsrcdir := $(samba4srcdir)/lib/socket
libcharsetsrcdir := $(samba4srcdir)/lib/charset
ldb_sambasrcdir := $(samba4srcdir)/lib/ldb-samba
libtlssrcdir := $(samba4srcdir)/lib/tls
libregistrysrcdir := $(samba4srcdir)/lib/registry
libmessagingsrcdir := $(samba4srcdir)/lib/messaging
libeventssrcdir := $(samba4srcdir)/lib/events
libcmdlinesrcdir := $(samba4srcdir)/lib/cmdline
poptsrcdir := $(samba4srcdir)/../lib/popt
socketwrappersrcdir := $(samba4srcdir)/../lib/socket_wrapper
nsswrappersrcdir := $(samba4srcdir)/../lib/nss_wrapper
appwebsrcdir := $(samba4srcdir)/lib/appweb
libstreamsrcdir := $(samba4srcdir)/lib/stream
libutilsrcdir := $(samba4srcdir)/lib/util
libtdrsrcdir := $(samba4srcdir)/lib/tdr
libdbwrapsrcdir := $(samba4srcdir)/lib/dbwrap
libcryptosrcdir := $(samba4srcdir)/lib/crypto
libtorturesrcdir := $(samba4srcdir)/lib/torture
libcompressionsrcdir := $(samba4srcdir)/../lib/compression
libgencachesrcdir := $(samba4srcdir)/lib
paramsrcdir := $(samba4srcdir)/param
smb_serversrcdir := $(samba4srcdir)/smb_server
rpc_serversrcdir := $(samba4srcdir)/rpc_server
ldap_serversrcdir := $(samba4srcdir)/ldap_server
web_serversrcdir := $(samba4srcdir)/web_server
winbindsrcdir := $(samba4srcdir)/winbind
nbt_serversrcdir := $(samba4srcdir)/nbt_server
wrepl_serversrcdir := $(samba4srcdir)/wrepl_server
cldap_serversrcdir := $(samba4srcdir)/cldap_server
librpcsrcdir := $(samba4srcdir)/librpc
torturesrcdir := $(samba4srcdir)/torture
utilssrcdir := $(samba4srcdir)/utils
ntvfssrcdir := $(samba4srcdir)/ntvfs
ntptrsrcdir := $(samba4srcdir)/ntptr
clientsrcdir := $(samba4srcdir)/client
libclisrcdir := $(samba4srcdir)/libcli
ejsscriptsrcdir := $(samba4srcdir)/scripting/ejs
pyscriptsrcdir := $(samba4srcdir)/scripting/python
kdcsrcdir := $(samba4srcdir)/kdc
smbreadlinesrcdir := $(samba4srcdir)/lib/smbreadline
ntp_signdsrcdir := $(samba4srcdir)/ntp_signd
tdbsrcdir := $(samba4srcdir)/../lib/tdb
ldbsrcdir := $(samba4srcdir)/lib/ldb
tallocsrcdir := $(samba4srcdir)/../lib/talloc
override ASN1C = bin/asn1_compile4
override ET_COMPILER = bin/compile_et4
include samba4-data.mk
include $(samba4srcdir)/static_deps.mk
include $(samba4srcdir)/build/make/python.mk

INSTALLPERMS = 0755

$(DESTDIR)$(bindir)/%: bin/%4 installdirs
	@mkdir -p $(@D)
	@echo Installing $(@F) as $@
	@if test -f $@; then rm -f $@.old; mv $@ $@.old; fi
	@cp $< $@
	@chmod $(INSTALLPERMS) $@

$(DESTDIR)$(sbindir)/%: bin/%4 installdirs
	@mkdir -p $(@D)
	@echo Installing $(@F) as $@
	@if test -f $@; then rm -f $@.old; mv $@ $@.old; fi
	@cp $< $@
	@chmod $(INSTALLPERMS) $@

clean:: 
	@echo Removing samba 4 objects
	@-find $(samba4srcdir) -name '*.o' -exec rm -f '{}' \;
	@echo Removing samba 4 hostcc objects
	@-find $(samba4srcdir) -name '*.ho' -exec rm -f '{}' \;
	@echo Removing samba 4 libraries
	@-rm -f $(STATIC_LIBS) $(SHARED_LIBS)
	@-rm -f bin/static/*.a bin/shared/*.$(SHLIBEXT) bin/mergedobj/*.o
	@echo Removing samba 4 modules
	@-rm -f bin/modules/*/*.$(SHLIBEXT)
	@-rm -f bin/*_init_module.c
	@echo Removing samba 4 dummy targets
	@-rm -f bin/.*_*
	@echo Removing samba 4 generated files
	@-rm -f bin/*_init_module.c
	@-rm -rf $(samba4srcdir)/librpc/gen_* 

proto:: $(PROTO_HEADERS)
modules:: $(PLUGINS)

all:: basics bin/smbd4 bin/regpatch4 bin/regdiff4 bin/regshell4 bin/regtree4 bin/smbclient4
torture:: basics bin/smbtorture4
everything:: basics $(patsubst %,%4,$(BINARIES))


etags::
	etags --append=yes `find $(samba4srcdir) -name "*.[ch]"`

ctags::
	ctags --append=yes `find $(samba4srcdir) -name "*.[ch]"`

