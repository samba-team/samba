###########################################################
### SMB Build System					###
### - create output for Makefile			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

sub _prepare_command_interpreters($)
{
	my $ctx = shift;
	my $output;

	$output = "
SHELL=/bin/sh
PERL=\@PERL\@
";
	return $output;
}

sub _prepare_path_vars($)
{
	my $ctx = shift;
	my $output;

	$output = "
prefix=\@prefix\@
exec_prefix=\@exec_prefix\@
VPATH=\@srcdir\@
srcdir=\@srcdir\@
builddir=\@builddir\@
";
	return $output;
}

sub _prepare_compiler_linker($)
{
	my $ctx = shift;
	my $output;

	$output = "
CC=\@CC\@
CC_FLAGS=\@CFLAGS\@ \@CPPFLAGS\@

LD=\@CC\@
LD_FLAGS=\@LDFLAGS\@ \@CFLAGS\@

STLD=ar
STLD_FLAGS=-rc

SHLD=\@CC\@
SHLD_FLAGS=\@LDSHFLAGS\@ \@LDFLAGS\@
";
	return $output;
}

sub _prepare_default_rule($)
{
	my $ctx = shift;
	my $output;

	$output = "
default: all
";
	return $output;
}

sub _prepare_SUFFIXES($)
{
	my $ctx = shift;
	my $output;

	$output = "
.SUFFIXES:
.SUFFIXES: .c .o .h .gch .a .so
";
	return $output;
}

sub _prepare_dummy_MAKEDIR()
{
	my $ctx = shift;
	my $output;

	$output = "
MAKEDIR = || exec false; \\
	  if test -d \"\$\$dir\"; then :; else \\
	  echo mkdir \"\$\$dir\"; \\
	  mkdir -p \"\$\$dir\" >/dev/null 2>&1 || \\
	  test -d \"\$\$dir\" || \\
	  mkdir \"\$\$dir\" || \\
	  exec false; fi || exec false

bin/.dummy:
	\@if (: >> \$\@ || : > \$\@) >/dev/null 2>&1; then :; else \\
	  dir=bin \$(MAKEDIR); fi
	\@: >> \$\@ || : > \$\@
";
	return $output;
}

###########################################################
# This function creates a standard make rule which is using $(CC)
#
# $output = _prepare_std_CC_rule($srcext,$destext,$message,$comment)
#
# $srcext -	sourcefile extension
#
# $destext -	destinationfile extension
#
# $message -	logmessage which is echoed while running this rule
#
# $comment -	just a comment what this rule should do
#
# $output -		the resulting output buffer
sub _prepare_std_CC_rule($$$$)
{
	my $src = shift;
	my $dst = shift;
	my $message = shift;
	my $comment = shift;
	my $output;

	$output = "
###################################
# Start $comment
.$src.$dst:
	\@if (: >> \$\@ || : > \$\@) >/dev/null 2>&1; then rm -f \$\@; else \\
	 dir=`echo \$\@ | sed 's,/[^/]*\$\$,,;s,^\$\$,.,'` \$(MAKEDIR); fi
	\@echo $message \$*.$src
	\@\$(CC) \$(CC_FLAGS) -c \$< -o \$\@
\@BROKEN_CC\@	-mv `echo \$\@ | sed 's%^.*/%%g'` \$\@
#End $comment
###################################
";

	return $output;
}

sub array2oneperline($)
{
	my $array = shift;
	my $i;
	my $output = "";

	foreach my $str (@{$array}) {
		if (!defined($str)) {
			next;
		}

		$output .= " \\\n\t";
		$output .= $str;
	}

	return $output;
}

###########################################################
# This function creates a object file list for a module
#
# $output = _prepare_module_obj_list($module_ctx)
#
# $module_ctx -		the module context
#
# $module_ctx->{MODULE} -	the module binary name
# $module_ctx->{OBJ_LIST} -	the list of objectfiles which sould be linked to this module
#
# $output -		the resulting output buffer
sub _prepare_module_obj_list($)
{
	my $ctx = shift;
	my $tmplist;
	my $output;

	$tmplist = array2oneperline($ctx->{OBJ_LIST});

	$output = "
###################################
# Start Module $ctx->{MODULE} OBJ LIST
MODULE_$ctx->{MODULE}_OBJS =$tmplist
# End Module $ctx->{MODULE} OBJ LIST
###################################
";

	return $output;
}

###########################################################
# This function creates a make rule for linking a module
#
# $output = _prepare_module_rule($module_ctx)
#
# $module_ctx -		the module context
#
# $module_ctx->{MODULE} -	the module binary name
# $module_ctx->{DEPEND_LIST} -	the list of rules on which this module depends
# $module_ctx->{LINK_LIST} -	the list of objectfiles and external libraries
#				which sould be linked to this module
# $module_ctx->{LINK_FLAGS} -	linker flags used by this module
#
# $output -		the resulting output buffer
sub _prepare_module_rule($)
{
	my $ctx = shift;
	my $output;

	$output = "
###################################
# Start Module $ctx->{MODULE}
bin/$ctx->{MODULE}: $ctx->{DEPEND_LIST} bin/.dummy
	\@echo Linking \$\@
	\@\$(SHLD) \$(SHLD_FLAGS) -o \$\@ \\
		$ctx->{LINK_FLAGS} \\
		$ctx->{LINK_LIST}
# Module $ctx->{MODULE}
###################################
";

	return $output;
}

###########################################################
# This function creates a object file list for a library
#
# $output = _prepare_library_obj_list($library_ctx)
#
# $library_ctx -		the library context
#
# $library_ctx->{LIBRARY} -	the library binary name
# $library_ctx->{OBJ_LIST} -	the list of objectfiles which sould be linked to this library
#
# $output -		the resulting output buffer
sub _prepare_library_obj_list($)
{
	my $ctx = shift;
	my $tmplist;
	my $output;

	$tmplist = array2oneperline($ctx->{OBJ_LIST});

	$output = "
###################################
# Start Library $ctx->{LIBRARY} OBJ LIST
LIBRARY_$ctx->{LIBRARY}_OBJS =$tmplist
# End Library $ctx->{LIBRARY} OBJ LIST
###################################
";

	return $output;
}

###########################################################
# This function creates a make rule for linking a library
#
# $output = _prepare_library_rule($library_ctx)
#
# $library_ctx -		the library context
#
# $library_ctx->{LIBRARY} -		the library name
# $library_ctx->{STATIC_LIBRARY} -	the static library name
# $library_ctx->{SHARED_LIBRARY} -	the shared library name
# $library_ctx->{DEPEND_LIST} -		the list of rules on which this library depends
# $library_ctx->{STATIC_LINK_LIST} -	the list of objectfiles	which sould be linked
#					to this static library
# $library_ctx->{STATIC_LINK_FLAGS} -	linker flags used by this static library
# $library_ctx->{SHARED_LINK_LIST} -	the list of objectfiles and external libraries
#					which sould be linked to this shared library
# $library_ctx->{SHARED_LINK_FLAGS} -	linker flags used by this shared library
#
# $output -		the resulting output buffer
sub _prepare_library_rule($)
{
	my $ctx = shift;
	my $output;

	$output = "
###################################
# Start Library $ctx->{LIBRARY}
#
# Static $ctx->{STATIC_LIBRARY}
bin/$ctx->{STATIC_LIBRARY}: $ctx->{DEPEND_LIST} bin/.dummy
	\@echo Linking \$\@
	\@\$(STLD) \$(STLD_FLAGS) \$\@ \\
		$ctx->{STATIC_LINK_FLAGS} \\
		$ctx->{STATIC_LINK_LIST}";

	if (defined($ctx->{SHARED_LIBRARY})) {
		$output .= "
# Shared $ctx->{SHARED_LIBRARY}
bin/$ctx->{SHARED_LIBRARY}: $ctx->{DEPEND_LIST} bin/.dummy
	\@echo Linking \$\@
	\@\$(SHLD) \$(SHLD_FLAGS) -o \$\@ \\
		$ctx->{SHARED_LINK_FLAGS} \\
		$ctx->{SHARED_LINK_LIST}";
	}
$output .= "
# End Library $ctx->{LIBRARY}
###################################
";

	return $output;
}

###########################################################
# This function creates a object file list for a binary
#
# $output = _prepare_binary_obj_list($binary_ctx)
#
# $binary_ctx -		the binary context
#
# $binary_ctx->{BINARY} -	the binary binary name
# $binary_ctx->{OBJ_LIST} -	the list of objectfiles which sould be linked to this binary
#
# $output -		the resulting output buffer
sub _prepare_binary_obj_list($)
{
	my $ctx = shift;
	my $tmplist;
	my $output;

	$tmplist = array2oneperline($ctx->{OBJ_LIST});

	$output = "
###################################
# Start Binary $ctx->{BINARY} OBJ LIST
BINARY_$ctx->{BINARY}_OBJS =$tmplist
# End Binary $ctx->{BINARY} OBJ LIST
###################################
";

	return $output;
}

###########################################################
# This function creates a make rule for linking a binary
#
# $output = _prepare_binary_rule($binary_ctx)
#
# $binary_ctx -		the binary context
#
# $binary_ctx->{BINARY} -	the binary name
# $binary_ctx->{DEPEND_LIST} -	the list of rules on which this binary depends
# $binary_ctx->{LINK_LIST} -	the list of objectfiles and external libraries
#				which sould be linked to this binary
# $binary_ctx->{LINK_FLAGS} -	linker flags used by this binary
#
# $output -		the resulting output buffer
sub _prepare_binary_rule($)
{
	my $ctx = shift;
	my $output;

	$output = "
###################################
# Start Binary $ctx->{BINARY}
bin/$ctx->{BINARY}: $ctx->{DEPEND_LIST} bin/.dummy
	\@echo Linking \$\@
	\@\$(LD) \$(LD_FLAGS) -o \$\@ \\
		$ctx->{LINK_FLAGS} \\
		$ctx->{LINK_LIST}
# End Binary $ctx->{BINARY}
###################################
";

	return $output;
}

sub _prepare_make_target($)
{
	my $ctx = shift;
	my $output;

	$output = "
###################################
# Start Target $ctx->{TARGET}
$ctx->{TARGET}: $ctx->{DEPEND_LIST}
# End Target $ctx->{TARGET}
###################################
";

	return $output;
}

sub _prepare_obj_lists($)
{
	my $CTX = shift;
	my $output = "";

	foreach my $key (sort keys %{$CTX->{OUTPUT}{SHARED_MODULES}}) {

		$CTX->{OUTPUT}{SHARED_MODULES}{$key}{MODULE} = $CTX->{OUTPUT}{SHARED_MODULES}{$key}{NAME};
		@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{OBJ_LIST}} = ();
		push(@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{OBJ_LIST}},@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{INIT_OBJ_FILES}});
		push(@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{OBJ_LIST}},@{$CTX->{OUTPUT}{SHARED_MODULES}{$key}{ADD_OBJ_FILES}});

		$output .= _prepare_module_obj_list(\%{$CTX->{OUTPUT}{SHARED_MODULES}{$key}});
	}

	foreach my $key (sort keys %{$CTX->{OUTPUT}{BINARIES}}) {

		$CTX->{OUTPUT}{BINARIES}{$key}{BINARY} = $CTX->{OUTPUT}{BINARIES}{$key}{NAME};
		@{$CTX->{OUTPUT}{BINARIES}{$key}{OBJ_LIST}} = @{$CTX->{OUTPUT}{BINARIES}{$key}{OBJ_FILES}};

		$output .= _prepare_binary_obj_list(\%{$CTX->{OUTPUT}{BINARIES}{$key}});
	}

	return $output;
}

sub _prepare_depend_lists($)
{
	my $CTX = shift;
	my $output = "";

	return $output;
}

sub _prepare_rule_lists($)
{
	my $CTX = shift;
	my $output = "";

	return $output;
}

###########################################################
# This function prepares the output for Makefile
#
# $output = _prepare_makefile_in($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
#
# $output -		the resulting output buffer
sub _prepare_makefile_in($)
{
	my $CTX = shift;
	my $output;

	$output  = "########################################\n";
	$output .= "# Autogenerated by config.smb_build.pl #\n";
	$output .= "########################################\n";

	my $cmd_ctx;
	$output .= _prepare_command_interpreters($cmd_ctx);

	my $path_ctx;
	$output .= _prepare_path_vars($path_ctx);

	my $compiler_ctx;
	$output .= _prepare_compiler_linker($compiler_ctx);

	my $rules_ctx;
	$output .= _prepare_default_rule($rules_ctx);

	my $suffix_ctx;
	$output .= _prepare_SUFFIXES($suffix_ctx);

	$output .= _prepare_dummy_MAKEDIR();

	$output .= _prepare_std_CC_rule("c","o","Compiling","Rule for std objectfiles");
	$output .= _prepare_std_CC_rule("h","gch","Precompiling","Rule for precompiled headerfiles");

	$output .= _prepare_obj_lists($CTX);

	$output .= _prepare_depend_lists($CTX);

	$output .= _prepare_rule_lists($CTX);

	my $libldb_ldap_ctx;
	$libldb_ldap_ctx->{MODULE} = "libldb_ldap.so";
	$libldb_ldap_ctx->{DEPEND_LIST} = "\$(MODULE_libldb_ldap_OBJS)";
	$libldb_ldap_ctx->{LINK_LIST} = "\$(MODULE_libldb_ldap_OBJS) \$(MODULE_libldb_ldap_LIBS)";
	$libldb_ldap_ctx->{LINK_FLAGS} = "-Wl,-soname=libldb_ldap.so";
	$output .= _prepare_module_rule($libldb_ldap_ctx);

	my $libsmb_ctx;
	$libsmb_ctx->{LIBRARY} = "libsmb";
	$libsmb_ctx->{STATIC_LIBRARY} = "libsmb.a";
	$libsmb_ctx->{SHARED_LIBRARY} = "libsmb.so";
	$libsmb_ctx->{DEPEND_LIST} = "\$(LIBRARY_libsmb_OBJS)";
	$libsmb_ctx->{STATIC_LINK_LIST} = "\$(LIBRARY_libsmb_OBJS)";
	$libsmb_ctx->{STATIC_LINK_FLAGS} = "";
	$libsmb_ctx->{SHARED_LINK_LIST} = "\$(LIBRARY_libsmb_OBJS) \$(LIBRARY_libsmb_LIBS)";
	$libsmb_ctx->{SHARED_LINK_FLAGS} = "-Wl,-soname=libsmb.so.1.0.0";
	$output .= _prepare_library_rule($libsmb_ctx);

	my $smbd_ctx;
	$smbd_ctx->{BINARY} = "smbd";
	$smbd_ctx->{DEPEND_LIST} = "\$(BINARY_smbd_OBJS) build/tests/trivial.o";
	$smbd_ctx->{LINK_LIST} = "\$(BINARY_smbd_OBJS) build/tests/trivial.o \$(BINARY_smbd_LIBS)";
	$smbd_ctx->{LINK_FLAGS} = "";
	$output .= _prepare_binary_rule($smbd_ctx);

	my $target_ctx;
	$target_ctx->{TARGET} = "all";
	$target_ctx->{DEPEND_LIST} = "bin/libldb_ldap.so bin/libsmb.a bin/libsmb.so bin/smbd";
	$output .= _prepare_make_target($target_ctx);

	return $output;
}

###########################################################
# This function creates Makefile.in from the SMB_BUILD 
# context
#
# create_makefile_in($SMB_BUILD_CTX)
#
# $SMB_BUILD_CTX -	the global SMB_BUILD context
#
# $output -		the resulting output buffer
sub create_makefile_in($)
{
	my $CTX = shift;
	my $output;

	$output = _prepare_makefile_in($CTX);

	open(MAKEFILE_IN,"> Makefile.in") || die ("Can't open Makefile.in\n");

	print MAKEFILE_IN $output;

	close(MAKEFILE_IN);

	print "config.smb_build.pl: creating Makefile.in\n";
	return;	
}
