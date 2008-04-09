pidl/Makefile: pidl/Makefile.PL
	cd pidl && $(PERL) Makefile.PL 

pidl-testcov: pidl/Makefile
	cd pidl && cover -test

installpidl:: pidl/Makefile
	$(MAKE) -C pidl install_vendor VENDORPREFIX=$(prefix)

ifeq ($(HAVE_PERL_EXTUTILS_MAKEMAKER),1)
install:: installpidl
endif

idl_full:: pidl/lib/Parse/Pidl/IDL.pm pidl/lib/Parse/Pidl/Expr.pm 
	@CPP="$(CPP)" PERL="$(PERL)" srcdir=$(srcdir) $(srcdir)/script/build_idl.sh FULL

idl:: pidl/lib/Parse/Pidl/IDL.pm pidl/lib/Parse/Pidl/Expr.pm 
	@CPP="$(CPP)" PERL="$(PERL)" srcdir=$(srcdir) $(srcdir)/script/build_idl.sh PARTIAL 

pidl/lib/Parse/Pidl/IDL.pm: pidl/idl.yp
	-$(YAPP) -m 'Parse::Pidl::IDL' -o pidl/lib/Parse/Pidl/IDL.pm pidl/idl.yp ||\
		touch pidl/lib/Parse/Pidl/IDL.pm 

pidl/lib/Parse/Pidl/Expr.pm: pidl/idl.yp
	-$(YAPP) -m 'Parse::Pidl::Expr' -o pidl/lib/Parse/Pidl/Expr.pm pidl/expr.yp ||\
		touch pidl/lib/Parse/Pidl/Expr.pm 

testcov-html:: pidl-testcov

$(IDL_HEADER_FILES) \
	$(IDL_NDR_PARSE_H_FILES) $(IDL_NDR_PARSE_C_FILES) \
	$(IDL_NDR_CLIENT_C_FILES) $(IDL_NDR_CLIENT_H_FILES) \
	$(IDL_NDR_SERVER_C_FILES) $(IDL_SWIG_FILES) \
	$(IDL_NDR_EJS_C_FILES) $(IDL_NDR_EJS_H_FILES) \
	$(IDL_NDR_PY_C_FILES) $(IDL_NDR_PY_H_FILES): idl


