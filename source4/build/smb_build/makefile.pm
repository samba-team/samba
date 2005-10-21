###########################################################
### SMB Build System					###
### - create output for Makefile			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Copyright (C) Jelmer Vernooij 2005			###
###  Released under the GNU GPL				###
###########################################################

package makefile;
use strict;

sub _prepare_path_vars($)
{
	my ($env) = @_;
	my $output;

	$output = << "__EOD__";
prefix = $env->{config}->{prefix}
exec_prefix = $env->{config}->{exec_prefix}
selftest_prefix = $env->{config}->{selftest_prefix}
VPATH = $env->{config}->{srcdir}
srcdir = $env->{config}->{srcdir}
builddir = $env->{config}->{builddir}

BASEDIR = $env->{config}->{prefix}
BINDIR = $env->{config}->{bindir}
SBINDIR = $env->{config}->{sbindir}
datadir = $env->{config}->{datadir}
LIBDIR = $env->{config}->{libdir}
CONFIGDIR = $env->{config}->{configdir}
localstatedir = $env->{config}->{localstatedir}
SWATDIR = $env->{config}->{swatdir}
VARDIR = $env->{config}->{localstatedir}
LOGFILEBASE = $env->{config}->{logfilebase}
NCALRPCDIR = $env->{config}->{localstatedir}/ncalrpc
LOCKDIR = $env->{config}->{lockdir}
PIDDIR = $env->{config}->{piddir}
MANDIR = $env->{config}->{mandir}
PRIVATEDIR = $env->{config}->{privatedir}

__EOD__
	
	$output.= << '__EOD__';

# The permissions to give the executables
INSTALLPERMS = 0755

# set these to where to find various files
# These can be overridden by command line switches (see smbd(8))
# or in smb.conf (see smb.conf(5))
CONFIGFILE = $(CONFIGDIR)/smb.conf
LMHOSTSFILE = $(CONFIGDIR)/lmhosts

PATH_FLAGS = -DCONFIGFILE=\"$(CONFIGFILE)\"  -DSBINDIR=\"$(SBINDIR)\" \
	 -DBINDIR=\"$(BINDIR)\" -DLMHOSTSFILE=\"$(LMHOSTSFILE)\" \
	 -DLOCKDIR=\"$(LOCKDIR)\" -DPIDDIR=\"$(PIDDIR)\" -DLIBDIR=\"$(LIBDIR)\" \
	 -DLOGFILEBASE=\"$(LOGFILEBASE)\" -DSHLIBEXT=\"$(SHLIBEXT)\" \
	 -DCONFIGDIR=\"$(CONFIGDIR)\" -DNCALRPCDIR=\"$(NCALRPCDIR)\" \
	 -DSWATDIR=\"$(SWATDIR)\" -DPRIVATE_DIR=\"$(PRIVATEDIR)\"
__EOD__

	return $output;
}

sub _prepare_compiler_linker($)
{
	my ($env) = @_;

	return << "__EOD__";
SHELL=$env->{config}->{SHELL}

PERL=$env->{config}->{PERL}

CC=$env->{config}->{CC}
CFLAGS=-I\$(srcdir)/include -I\$(srcdir) -I\$(srcdir)/lib -D_SAMBA_BUILD_ -DHAVE_CONFIG_H $env->{config}->{CFLAGS} $env->{config}->{CPPFLAGS}
PICFLAG=$env->{config}->{PICFLAG}
HOSTCC=$env->{config}->{HOSTCC}

CPP=$env->{config}->{CPP}
CPPFLAGS=$env->{config}->{CPPFLAGS}

LD=$env->{config}->{LD}
LD_FLAGS=$env->{config}->{LDFLAGS} 

STLD=$env->{config}->{AR}
STLD_FLAGS=-rc

SHLD=$env->{config}->{CC}
SHLD_FLAGS=$env->{config}->{LDSHFLAGS}
SONAMEFLAG=$env->{config}->{SONAMEFLAG}
SHLIBEXT=$env->{config}->{SHLIBEXT}

XSLTPROC=$env->{config}->{XSLTPROC}

LEX=$env->{config}->{LEX}
YACC=$env->{config}->{YACC}
YAPP=$env->{config}->{YAPP}
PIDL_ARGS=$env->{config}->{PIDL_ARGS}

GCOV=$env->{config}->{GCOV}

DEFAULT_TEST_TARGET=$env->{config}->{DEFAULT_TEST_TARGET}

__EOD__
}

sub _prepare_default_rule()
{
	return << '__EOD__';
default: all

__EOD__
}

sub _prepare_SUFFIXES()
{
	return << '__EOD__';
.SUFFIXES: .x .c .et .y .l .d .o .h .h.gch .a .so .1 .1.xml .3 .3.xml .5 .5.xml .7 .7.xml .ho

__EOD__
}

sub _prepare_man_rule($)
{
	my $suffix = shift;

	return << "__EOD__";
.$suffix.xml.$suffix:
	\$(XSLTPROC) -o \$@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl \$<

__EOD__
}

sub _prepare_config_status()
{
	my @parsed_files = @smb_build::config_mk::parsed_files;
	my $deps = "";
	
	foreach (@parsed_files) {
		/^([^ |]+)/;
		$deps.= " $1";
	}

	return "

Makefile: config.status $deps
	./config.status

";
}

sub _prepare_binaries($)
{
	my $ctx = shift;

	my @bbn_list = ();
	my @sbn_list = ();

	foreach (values %$ctx) {
		next unless defined $_->{OUTPUT_TYPE};
		next unless ($_->{OUTPUT_TYPE} eq "BINARY");

		next unless defined($_->{INSTALLDIR});

		push(@sbn_list, $_->{OUTPUT}) if ($_->{INSTALLDIR} eq "SBINDIR");
		push(@bbn_list, $_->{OUTPUT}) if ($_->{INSTALLDIR} eq "BINDIR");
	}

	my $bbn = array2oneperline(\@bbn_list);
	my $sbn = array2oneperline(\@sbn_list);
	return << "__EOD__";
BIN_PROGS = $bbn
SBIN_PROGS = $sbn
__EOD__
}

sub _prepare_manpages($)
{
	my $ctx = shift;

	my @mp_list = ();

	foreach (values %$ctx) {
		my $dir = $_->{BASEDIR};
		next unless defined($dir);
		$dir =~ s/^\.\///g;
		push (@mp_list, "$dir/$_->{MANPAGE}") if (defined($_->{MANPAGE}) and $_->{MANPAGE} ne "");
	}
	
	my $mp = array2oneperline(\@mp_list);
	return << "__EOD__";
MANPAGES = $mp

__EOD__
}

sub _prepare_dummy_MAKEDIR($$)
{
	my ($env,$ctx) = @_;

	my $ret = << '__EOD__';
bin/.dummy:
	@: >> $@ || : > $@

dynconfig.o: dynconfig.c Makefile
	@echo Compiling $*.c
	@$(CC) $(CFLAGS) $(PICFLAG) $(PATH_FLAGS) -c $< -o $@
__EOD__
	if ($env->{config}->{BROKEN_CC} eq "yes") {
		$ret .= '	-mv `echo $@ | sed \'s%^.*/%%g\'` $@
';
	}
	return $ret."\n";
}

sub _prepare_depend_CC_rule()
{
	return << '__EOD__';

.c.d:
	@echo "Generating dependencies for $<"
	@$(CC) -MM -MG -MT $(<:.c=.o) -MF $@ $(CFLAGS) $<

__EOD__
}

###########################################################
# This function creates a standard make rule which is using $(CC)
#
# $output = _prepare_std_CC_rule($srcext,$destext,$flags,$message,$comment)
#
# $srcext -	sourcefile extension
#
# $destext -	destinationfile extension
#
# $flags -	additional compiler flags
#
# $message -	logmessage which is echoed while running this rule
#
# $comment -	just a comment what this rule should do
#
# $output -		the resulting output buffer
sub _prepare_std_CC_rule($$$$$$)
{
	my ($env,$src,$dst,$flags,$message,$comment) = @_;

	my $ret = << "__EOD__";
# $comment
.$src.$dst:
	\@echo $message \$\*.$src
	\@\$(CC) `script/cflags.sh \$\@` \$(CFLAGS) $flags -c \$< -o \$\@
__EOD__
	if ($env->{config}->{BROKEN_CC} eq "yes") {
		$ret.= '	-mv `echo $@ | sed \'s%^.*/%%g\'` $@
';
	}
	return $ret."\n";
}

sub _prepare_hostcc_rule($)
{
	my ($env) = @_;
	
	my $ret = << "__EOD__";
.c.ho:
	\@echo Compiling \$\*.c with host compiler
	\@\$(HOSTCC) `script/cflags.sh \$\@` \$(CFLAGS) -c \$< -o \$\@
__EOD__
	if ($env->{config}->{BROKEN_CC} eq "yes") {
		$ret .= '	-mv `echo $@ | sed \'s%^.*/%%g\' -e \'s%\.ho$$%.o%\'` $@
';
	}

	return $ret."\n";
}



sub array2oneperline($)
{
	my $array = shift;
	my $output = "";

	foreach (@$array) {
		next unless defined($_);

		$output .= " \\\n\t\t$_";
	}

	return $output;
}

###########################################################
# This function creates a object file list
#
# $output = _prepare_var_obj_list($var, $var_ctx)
#
# $var_ctx -		the subsystem context
#
# $var_ctx->{NAME} 	-	the <var> name
# $var_ctx->{OBJ_LIST} 	-	the list of objectfiles which sould be linked to this <var>
#
# $output -		the resulting output buffer
sub _prepare_obj_list($$)
{
	my ($var,$ctx) = @_;

	my $tmplist = array2oneperline($ctx->{OBJ_LIST});
	return "" if ($tmplist eq "");

	return << "__EOD__";
$var\_$ctx->{NAME}_OBJS =$tmplist
__EOD__
}

sub _prepare_cflags($$)
{
	my ($var,$ctx) = @_;

	my $tmplist = array2oneperline($ctx->{CFLAGS});
	return "" if ($tmplist eq "");

	return << "__EOD__";
$var\_$ctx->{NAME}_CFLAGS =$tmplist

__EOD__
}

###########################################################
# This function creates a make rule for linking a library
#
# $output = _prepare_shared_library_rule($library_ctx)
#
# $library_ctx -		the library context
#
# $library_ctx->{NAME} -		the library name
#
# $library_ctx->{DEPEND_LIST} -		the list of rules on which this library depends
#
# $library_ctx->{LIBRARY_NAME} -	the shared library name
# $library_ctx->{LIBRARY_REALNAME} -	the shared library real name
# $library_ctx->{LIBRARY_SONAME} - the shared library soname
# $library_ctx->{LINK_LIST} -	the list of objectfiles and external libraries
#					which sould be linked to this shared library
# $library_ctx->{LINK_FLAGS} -	linker flags used by this shared library
#
# $output -		the resulting output buffer
sub _prepare_shared_library_rule($)
{
	my $ctx = shift;
	my $output;

	my $tmpdepend = array2oneperline($ctx->{DEPEND_LIST});
	my $tmpshlink = array2oneperline($ctx->{LINK_LIST});
	my $tmpshflag = array2oneperline($ctx->{LINK_FLAGS});

	$output = << "__EOD__";
LIBRARY_$ctx->{NAME}_DEPEND_LIST =$tmpdepend
LIBRARY_$ctx->{NAME}_SHARED_LINK_LIST =$tmpshlink
LIBRARY_$ctx->{NAME}_SHARED_LINK_FLAGS =$tmpshflag
#

$ctx->{TARGET}: \$(LIBRARY_$ctx->{NAME}_DEPEND_LIST) \$(LIBRARY_$ctx->{NAME}_OBJS) bin/.dummy
	\@echo Linking \$\@
	\@\$(SHLD) \$(SHLD_FLAGS) -o \$\@ \\
		\$(LIBRARY_$ctx->{NAME}_SHARED_LINK_FLAGS) \\
		\$(LIBRARY_$ctx->{NAME}_SHARED_LINK_LIST)

__EOD__

	if (defined($ctx->{LIBRARY_SONAME})) {
	    $output .= << "__EOD__";
# Symlink $ctx->{LIBRARY_SONAME}
bin/$ctx->{LIBRARY_SONAME}: bin/$ctx->{LIBRARY_REALNAME} bin/.dummy
	\@echo Symlink \$\@
	\@ln -sf $ctx->{LIBRARY_REALNAME} \$\@
# Symlink $ctx->{LIBRARY_NAME}
bin/$ctx->{LIBRARY_NAME}: bin/$ctx->{LIBRARY_SONAME} bin/.dummy
	\@echo Symlink \$\@
	\@ln -sf $ctx->{LIBRARY_SONAME} \$\@

__EOD__
	}

$output .= << "__EOD__";
library_$ctx->{NAME}: basics bin/lib$ctx->{LIBRARY_NAME}

__EOD__

	return $output;
}

sub _prepare_mergedobj_rule($)
{
	my $ctx = shift;

	return "" unless $ctx->{TARGET};

	my $tmpdepend = array2oneperline($ctx->{DEPEND_LIST});

	my $output = "$ctx->{TYPE}_$ctx->{NAME}_DEPEND_LIST = $tmpdepend\n";

	$output .= "$ctx->{TARGET}: \$($ctx->{TYPE}_$ctx->{NAME}_OBJS)\n";

	$output .= "\t\@echo \"Pre-Linking $ctx->{TYPE} $ctx->{NAME}\"\n";
	$output .= "\t@\$(LD) -r \$($ctx->{TYPE}_$ctx->{NAME}_OBJS) -o $ctx->{TARGET}\n";
	$output .= "\n";

	return $output;
}

sub _prepare_objlist_rule($)
{
	my $ctx = shift;
	my $tmpdepend = array2oneperline($ctx->{DEPEND_LIST});

	return "" unless $ctx->{TARGET};

	my $output = "$ctx->{TYPE}_$ctx->{NAME}_DEPEND_LIST = $tmpdepend\n";
	$output .= "$ctx->{TARGET}: ";
	$output .= "\$($ctx->{TYPE}_$ctx->{NAME}_DEPEND_LIST) \$($ctx->{TYPE}_$ctx->{NAME}_OBJS)\n";
	$output .= "\t\@touch $ctx->{TARGET}\n";

	return $output;
}

###########################################################
# This function creates a make rule for linking a library
#
# $output = _prepare_static_library_rule($library_ctx)
#
# $library_ctx -		the library context
#
# $library_ctx->{NAME} -		the library name
#
# $library_ctx->{DEPEND_LIST} -		the list of rules on which this library depends
#
# $library_ctx->{LIBRARY_NAME} -	the static library name
# $library_ctx->{LINK_LIST} -	the list of objectfiles	which sould be linked
#					to this static library
# $library_ctx->{LINK_FLAGS} -	linker flags used by this static library
#
# $output -		the resulting output buffer
sub _prepare_static_library_rule($)
{
	my $ctx = shift;
	my $output;

	my $tmpdepend = array2oneperline($ctx->{DEPEND_LIST});
	my $tmpstlink = array2oneperline($ctx->{LINK_LIST});
	my $tmpstflag = array2oneperline($ctx->{LINK_FLAGS});

	$output = << "__EOD__";
LIBRARY_$ctx->{NAME}_DEPEND_LIST =$tmpdepend
#
LIBRARY_$ctx->{NAME}_STATIC_LINK_LIST =$tmpstlink
#
$ctx->{TARGET}: \$(LIBRARY_$ctx->{NAME}_DEPEND_LIST) \$(LIBRARY_$ctx->{NAME}_OBJS) bin/.dummy
	\@echo Linking \$@
	\@\$(STLD) \$(STLD_FLAGS) \$@ \\
		\$(LIBRARY_$ctx->{NAME}_STATIC_LINK_LIST)

library_$ctx->{NAME}: basics $ctx->{TARGET}

__EOD__

	return $output;
}

###########################################################
# This function creates a make rule for linking a binary
#
# $output = _prepare_binary_rule($binary_ctx)
#
# $binary_ctx -		the binary context
#
# $binary_ctx->{NAME} -		the binary name
# $binary_ctx->{BINARY} -	the binary binary name
#
# $binary_ctx->{DEPEND_LIST} -	the list of rules on which this binary depends
# $binary_ctx->{LINK_LIST} -	the list of objectfiles and external libraries
#				which sould be linked to this binary
# $binary_ctx->{LINK_FLAGS} -	linker flags used by this binary
#
# $output -		the resulting output buffer
sub _prepare_binary_rule($)
{
	my $ctx = shift;

	my $tmpdepend = array2oneperline($ctx->{DEPEND_LIST});
	my $tmplink = array2oneperline($ctx->{LINK_LIST});
	my $tmpflag = array2oneperline($ctx->{LINK_FLAGS});

	my $output = << "__EOD__";
#
BINARY_$ctx->{NAME}_DEPEND_LIST =$tmpdepend
BINARY_$ctx->{NAME}_LINK_LIST =$tmplink
BINARY_$ctx->{NAME}_LINK_FLAGS =$tmpflag
#
bin/$ctx->{BINARY}: bin/.dummy \$(BINARY_$ctx->{NAME}_DEPEND_LIST) \$(BINARY_$ctx->{NAME}_OBJS)
	\@echo Linking \$\@
	\@\$(CC) \$(LD_FLAGS) -o \$\@ \\
		\$\(BINARY_$ctx->{NAME}_LINK_FLAGS) \\
		\$\(BINARY_$ctx->{NAME}_LINK_LIST) \\
		\$\(BINARY_$ctx->{NAME}_LINK_FLAGS)
binary_$ctx->{BINARY}: basics bin/$ctx->{BINARY}

__EOD__

	return $output;
}

sub _prepare_custom_rule($)
{
	my $ctx = shift;
	return "
$ctx->{NAME}: bin/.TARGET_$ctx->{NAME}

bin/.TARGET_$ctx->{NAME}:
	$ctx->{CMD}
	touch bin/.TARGET_$ctx->{NAME}
";
}

sub _prepare_clean_rules($)
{
	my ($env) = @_;
	my $output = << '__EOD__';
clean: heimdal_clean
	@echo Removing headers
	@-rm -f include/proto.h
	@echo Removing objects
	@-find . -name '*.o' -exec rm -f '{}' \;
	@echo Removing binaries
	@-rm -f $(BIN_PROGS) $(SBIN_PROGS)
	@echo Removing dummy targets
	@-rm -f bin/.*_*
	@echo Removing generated files
	@-rm -rf librpc/gen_* 
	@-rm -f lib/registry/regf.h lib/registry/tdr_regf*

distclean: clean
	-rm -f bin/.dummy
	-rm -f include/config.h include/smb_build.h
	-rm -f Makefile 
	-rm -f config.status
	-rm -f config.log config.cache
	-rm -f samba4-deps.dot
	-rm -f config.pm config.mk
	-rm -f lib/registry/winregistry.pc
__EOD__

	if ($env->{config}->{developer} eq "yes") {
		$output .= "\t\@-rm -f \$(_ALL_OBJS_OBJS:.o=.d)\n";
	}

	$output .= << '__EOD__';

removebackup:
	-rm -f *.bak *~ */*.bak */*~ */*/*.bak */*/*~ */*/*/*.bak */*/*/*~

realdistclean: distclean removebackup
	-rm -f include/config.h.in
	-rm -f include/version.h
	-rm -f configure
	-rm -f $(MANPAGES)
__EOD__

	return $output;
}

sub _prepare_make_target($)
{
	my $ctx = shift;
	my $tmpdepend;

	$tmpdepend = array2oneperline($ctx->{DEPEND_LIST});

	return << "__EOD__";
$ctx->{TARGET}: basics $tmpdepend

__EOD__
}

sub _prepare_target_settings($)
{
	my $CTX = shift;
	my $output = "";

	foreach my $key (values %$CTX) {
		if (defined($key->{OBJ_LIST})) {
			$output .= _prepare_obj_list($key->{TYPE}, $key);
			$output .= _prepare_cflags($key->{TYPE}, $key);
		}
	}

	return $output;
}

sub _prepare_rule_lists($$)
{
	my ($env,$depend) = @_;
	my $output = "";

	foreach my $key (values %{$depend}) {
		next unless defined $key->{OUTPUT_TYPE};

		($output .= _prepare_mergedobj_rule($key)) if $key->{OUTPUT_TYPE} eq "MERGEDOBJ";
		($output .= _prepare_objlist_rule($key)) if $key->{OUTPUT_TYPE} eq "OBJLIST";
		($output .= _prepare_static_library_rule($key)) if $key->{OUTPUT_TYPE} eq "STATIC_LIBRARY";
		($output .= _prepare_shared_library_rule($key)) if $key->{OUTPUT_TYPE} eq "SHARED_LIBRARY";
		($output .= _prepare_binary_rule($key)) if $key->{OUTPUT_TYPE} eq "BINARY";
		($output .= _prepare_custom_rule($key) ) if $key->{TYPE} eq "TARGET";
	}

	$output .= _prepare_clean_rules($env);

	return $output;
}

###########################################################
# This function prepares the output for Makefile
#
# $output = _prepare_makefile($OUTPUT)
#
# $OUTPUT -	the global OUTPUT context
#
# $output -		the resulting output buffer
sub _prepare_makefile($$)
{
	my ($env,$CTX) = @_;
	my $output;

	$output  = "############################################\n";
	$output .= "# Autogenerated by build/smb_build/main.pl #\n";
	$output .= "############################################\n";
	$output .= "\n";

	$output .= _prepare_path_vars($env);
	$output .= _prepare_compiler_linker($env);
	$output .= _prepare_default_rule();
	$output .= _prepare_SUFFIXES();
	$output .= _prepare_dummy_MAKEDIR($env, $CTX);
	$output .= _prepare_hostcc_rule($env);
	$output .= _prepare_std_CC_rule($env, "c","o",'$(PICFLAG)',"Compiling","Rule for std objectfiles");
	$output .= _prepare_std_CC_rule($env, "h","h.gch",'$(PICFLAG)',"Precompiling","Rule for precompiled headerfiles");

	$output .= _prepare_depend_CC_rule();
	
	$output .= _prepare_man_rule("1");
	$output .= _prepare_man_rule("3");
	$output .= _prepare_man_rule("5");
	$output .= _prepare_man_rule("7");
	$output .= _prepare_manpages($CTX);
	$output .= _prepare_binaries($CTX);
	$output .= _prepare_target_settings($CTX);
	$output .= _prepare_rule_lists($env, $CTX);
	$output .= _prepare_config_status();

	if ($env->{config}->{developer} eq "yes") {
		$output .= <<__EOD__
#-include \$(_ALL_OBJS_OBJS:.o=.d)
IDL_FILES = \$(wildcard librpc/idl/*.idl)
\$(patsubst librpc/idl/%.idl,librpc/gen_ndr/ndr_%.c,\$(IDL_FILES)) \\
\$(patsubst librpc/idl/%.idl,librpc/gen_ndr/ndr_\%_c.c,\$(IDL_FILES)) \\
\$(patsubst librpc/idl/%.idl,librpc/gen_ndr/ndr_%.h,\$(IDL_FILES)): idl
__EOD__
	}

	return $output;
}

###########################################################
# This function creates Makefile from the OUTPUT 
# context
#
# create_makefile($OUTPUT)
#
# $OUTPUT	-	the global OUTPUT context
#
# $output -		the resulting output buffer
sub create_makefile($$$$)
{
	my ($CTX, $env, $mk, $file) = @_;

	open(MAKEFILE,">$file") || die ("Can't open $file\n");
	print MAKEFILE _prepare_makefile($env, $CTX) . $mk;
	close(MAKEFILE);

	print "build/smb_build/main.pl: creating $file\n";
	return;	
}

1;
