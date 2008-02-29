[SUBSYSTEM::DYNCONFIG]
OBJ_FILES = dynconfig.o

# set these to where to find various files
# These can be overridden by command line switches (see smbd(8))
# or in smb.conf (see smb.conf(5))
CONFIGFILE = $(sysconfdir)/smb.conf
PKGCONFIGDIR = $(libdir)/pkgconfig
LMHOSTSFILE = $(sysconfdir)/lmhosts

PATH_FLAGS = -DCONFIGFILE=\"$(CONFIGFILE)\" \
	 -DBINDIR=\"$(bindir)\" -DLMHOSTSFILE=\"$(LMHOSTSFILE)\" \
	 -DLOCKDIR=\"$(lockdir)\" -DPIDDIR=\"$(piddir)\" -DDATADIR=\"$(datadir)\" \
	 -DLOGFILEBASE=\"$(logfilebase)\" \
	 -DCONFIGDIR=\"$(sysconfdir)\" -DNCALRPCDIR=\"$(NCALRPCDIR)\" \
	 -DSWATDIR=\"$(SWATDIR)\" \
	 -DPRIVATE_DIR=\"$(privatedir)\" \
	 -DMODULESDIR=\"$(modulesdir)\" -DJSDIR=\"$(JSDIR)\" \
	 -DTORTUREDIR=\"$(TORTUREDIR)\" \
	 -DSETUPDIR=\"$(SETUPDIR)\" -DWINBINDD_SOCKET_DIR=\"$(winbindd_socket_dir)\"

dynconfig.o: dynconfig.c Makefile
	@echo Compiling $<
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(PICFLAG) \
		$(PATH_FLAGS) -c $< -o $@
