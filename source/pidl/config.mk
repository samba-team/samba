$(pidldir)/Makefile: $(pidldir)/Makefile.PL
	cd $(pidldir) && $(PERL) Makefile.PL PREFIX=$(prefix)

pidl-testcov: $(pidldir)/Makefile
	cd $(pidldir) && cover -test

installpidl:: $(pidldir)/Makefile
	$(MAKE) -C $(pidldir) install_vendor VENDORPREFIX=$(prefix) \
		                           INSTALLVENDORLIB=$(datarootdir)/perl5 \
								   INSTALLVENDORBIN=$(bindir) \
								   INSTALLVENDORSCRIPT=$(bindir) \
								   INSTALLVENDORMAN1DIR=$(mandir)/man1 \
								   INSTALLVENDORMAN3DIR=$(mandir)/man3

ifeq ($(HAVE_PERL_EXTUTILS_MAKEMAKER),1)
install:: installpidl
endif

idl_full:: $(pidldir)/lib/Parse/Pidl/IDL.pm $(pidldir)/lib/Parse/Pidl/Expr.pm 
	@CPP="$(CPP)" PERL="$(PERL)" srcdir=$(srcdir) $(srcdir)/script/build_idl.sh FULL

idl:: $(pidldir)/lib/Parse/Pidl/IDL.pm $(pidldir)/lib/Parse/Pidl/Expr.pm 
	@CPP="$(CPP)" PERL="$(PERL)" srcdir=$(srcdir) $(srcdir)/script/build_idl.sh PARTIAL 

$(pidldir)/lib/Parse/Pidl/IDL.pm: $(pidldir)/idl.yp
	-$(YAPP) -m 'Parse::Pidl::IDL' -o $(pidldir)/lib/Parse/Pidl/IDL.pm $(pidldir)/idl.yp ||\
		touch $(pidldir)/lib/Parse/Pidl/IDL.pm 

$(pidldir)/lib/Parse/Pidl/Expr.pm: $(pidldir)/idl.yp
	-$(YAPP) -m 'Parse::Pidl::Expr' -o $(pidldir)/lib/Parse/Pidl/Expr.pm $(pidldir)/expr.yp ||\
		touch $(pidldir)/lib/Parse/Pidl/Expr.pm 

testcov-html:: pidl-testcov

$(IDL_HEADER_FILES) \
	$(IDL_NDR_PARSE_H_FILES) $(IDL_NDR_PARSE_C_FILES) \
	$(IDL_NDR_CLIENT_C_FILES) $(IDL_NDR_CLIENT_H_FILES) \
	$(IDL_NDR_SERVER_C_FILES) $(IDL_SWIG_FILES) \
	$(IDL_NDR_EJS_C_FILES) $(IDL_NDR_EJS_H_FILES) \
	$(IDL_NDR_PY_C_FILES) $(IDL_NDR_PY_H_FILES): idl


