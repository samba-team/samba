[LIBRARY::DYNCONFIG]
VERSION = 0.0.1
SO_VERSION = 0
OBJ_FILES = dynconfig.o

PATH_FLAGS = -DCONFIGFILE=\"$(CONFIGFILE)\" \
	 -DBINDIR=\"$(BINDIR)\" -DLMHOSTSFILE=\"$(LMHOSTSFILE)\" \
	 -DLOCKDIR=\"$(LOCKDIR)\" -DPIDDIR=\"$(PIDDIR)\" -DDATADIR=\"$(DATADIR)\" \
	 -DLOGFILEBASE=\"$(LOGFILEBASE)\" -DSHLIBEXT=\"$(SHLIBEXT)\" \
	 -DCONFIGDIR=\"$(CONFIGDIR)\" -DNCALRPCDIR=\"$(NCALRPCDIR)\" \
	 -DSWATDIR=\"$(SWATDIR)\" -DPRIVATE_DIR=\"$(PRIVATEDIR)\" \
	 -DMODULESDIR=\"$(MODULESDIR)\" -DJSDIR=\"$(JSDIR)\" \
	 -DTORTUREDIR=\"$(TORTUREDIR)\" \
	 -DSETUPDIR=\"$(SETUPDIR)\" -DWINBINDD_SOCKET_DIR=\"$(WINBINDD_SOCKET_DIR)\"

dynconfig.o: dynconfig.c Makefile
	@echo Compiling $<
	@$(CC) `$(PERL) $(srcdir)/script/cflags.pl $@` $(CFLAGS) $(PICFLAG) $(PATH_FLAGS) -c $< -o $@

# dynconfig defines used for binaries in bin/, when configure ran in developer 
# mode:

DEVEL_PATH_FLAGS = -DCONFIGFILE=\"$(CONFIGFILE)\" -DBINDIR=\"$(builddir)/bin\" \
     -DLMHOSTSFILE=\"$(LMHOSTSFILE)\" -DLOCKDIR=\"$(LOCKDIR)\" \
	 -DPIDDIR=\"$(PIDDIR)\" -DDATADIR=\"$(srcdir)/codepages\" \
	 -DLOGFILEBASE=\"$(LOGFILEBASE)\" -DSHLIBEXT=\"$(SHLIBEXT)\" \
	 -DCONFIGDIR=\"$(CONFIGDIR)\" -DNCALRPCDIR=\"$(NCALRPCDIR)\" \
	 -DSWATDIR=\"$(srcdir)/../swat\" -DPRIVATE_DIR=\"$(PRIVATEDIR)\" \
	 -DMODULESDIR=\"$(builddir)/bin/modules\" \
	 -DJSDIR=\"$(srcdir)/scripting/libjs\" \
	 -DSETUPDIR=\"$(srcdir)/setup\" \
	 -DWINBINDD_SOCKET_DIR=\"$(WINBINDD_SOCKET_DIR)\"

dynconfig-devel.o: dynconfig.c Makefile
	@echo Compiling $<
	@$(CC) `$(PERL) $(srcdir)/script/cflags.pl $@` $(CFLAGS) $(PICFLAG) $(DEVEL_PATH_FLAGS) -c $< -o $@
