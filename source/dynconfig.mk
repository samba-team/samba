[SUBSYSTEM::DYNCONFIG]
OBJ_FILES = dynconfig.o

# set these to where to find various files
# These can be overridden by command line switches (see smbd(8))
# or in smb.conf (see smb.conf(5))
CONFIGFILE = $(CONFIGDIR)/smb.conf
PKGCONFIGDIR = $(LIBDIR)/pkgconfig
LMHOSTSFILE = $(CONFIGDIR)/lmhosts

PATH_FLAGS = -DCONFIGFILE=\"$(CONFIGFILE)\" \
	 -DBINDIR=\"$(BINDIR)\" -DLMHOSTSFILE=\"$(LMHOSTSFILE)\" \
	 -DLOCKDIR=\"$(LOCKDIR)\" -DPIDDIR=\"$(PIDDIR)\" -DDATADIR=\"$(DATADIR)\" \
	 -DLOGFILEBASE=\"$(LOGFILEBASE)\" \
	 -DCONFIGDIR=\"$(CONFIGDIR)\" -DNCALRPCDIR=\"$(NCALRPCDIR)\" \
	 -DSWATDIR=\"$(SWATDIR)\" -DSERVICESDIR=\"$(SERVICESDIR)\" \
	 -DPRIVATE_DIR=\"$(PRIVATEDIR)\" \
	 -DMODULESDIR=\"$(MODULESDIR)\" -DJSDIR=\"$(JSDIR)\" \
	 -DTORTUREDIR=\"$(TORTUREDIR)\" \
	 -DSETUPDIR=\"$(SETUPDIR)\" -DWINBINDD_SOCKET_DIR=\"$(WINBINDD_SOCKET_DIR)\"

dynconfig.o: dynconfig.c Makefile
	@echo Compiling $<
	@$(CC) `$(PERL) $(srcdir)/script/cflags.pl $@` $(CFLAGS) $(PICFLAG) $(PATH_FLAGS) -c $< -o $@
