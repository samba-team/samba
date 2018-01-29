#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2010 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2007-2009 Stefan Metzmacher <metze@samba.org>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;

use FindBin qw($RealBin $Script);
use File::Spec;
use File::Temp qw(tempfile);
use Getopt::Long;
use POSIX;
use Cwd qw(abs_path);
use lib "$RealBin";
use Subunit;
use SocketWrapper;
use target::Samba;

eval {
require Time::HiRes;
Time::HiRes->import("time");
};
if ($@) {
	print "You don't have Time::Hires installed !\n";
}

my $opt_help = 0;
my $opt_target = "samba";
my $opt_quick = 0;
my $opt_socket_wrapper = 0;
my $opt_socket_wrapper_pcap = undef;
my $opt_socket_wrapper_keep_pcap = undef;
my $opt_random_order = 0;
my $opt_one = 0;
my @opt_exclude = ();
my @opt_include = ();
my @opt_exclude_env = ();
my @opt_include_env = ();
my $opt_testenv = 0;
my $opt_list = 0;
my $opt_mitkrb5 = 0;
my $ldap = undef;
my $opt_resetup_env = undef;
my $opt_load_list = undef;
my $opt_libnss_wrapper_so_path = "";
my $opt_libresolv_wrapper_so_path = "";
my $opt_libsocket_wrapper_so_path = "";
my $opt_libuid_wrapper_so_path = "";
my $opt_use_dns_faking = 0;
my @testlists = ();

my $srcdir = ".";
my $bindir = "./bin";
my $prefix = "./st";

my @includes = ();
my @excludes = ();

sub find_in_list($$)
{
	my ($list, $fullname) = @_;

	foreach (@$list) {
		if ($fullname =~ /$$_[0]/) {
			 return ($$_[1]) if ($$_[1]);
			 return "";
		}
	}

	return undef;
}

sub skip
{
	my ($name, $envname) = @_;
	my ($env_basename, $env_localpart) = split(/:/, $envname);

	if ($opt_target eq "samba3" && $Samba::ENV_NEEDS_AD_DC{$env_basename}) {
		return "environment $envname is disabled as this build does not include an AD DC";
	}

	if (@opt_include_env && !(grep {$_ eq $env_basename} @opt_include_env)) {
		return "environment $envname is disabled (via --include-env command line option) in this test run - skipping";
	} elsif (@opt_exclude_env && grep {$_ eq $env_basename} @opt_exclude_env) {
		return "environment $envname is disabled (via --exclude-env command line option) in this test run - skipping";
	}

	return find_in_list(\@excludes, $name);
}

sub getlog_env($);

sub setup_pcap($)
{
	my ($name) = @_;

	return unless ($opt_socket_wrapper_pcap);
	return unless defined($ENV{SOCKET_WRAPPER_PCAP_DIR});

	my $fname = $name;
	$fname =~ s%[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\-]%_%g;

	my $pcap_file = "$ENV{SOCKET_WRAPPER_PCAP_DIR}/$fname.pcap";

	SocketWrapper::setup_pcap($pcap_file);

	return $pcap_file;
}

sub cleanup_pcap($$)
{
	my ($pcap_file, $exitcode) = @_;

	return unless ($opt_socket_wrapper_pcap);
	return if ($opt_socket_wrapper_keep_pcap);
	return unless ($exitcode == 0);
	return unless defined($pcap_file);

	unlink($pcap_file);
}

# expand strings from %ENV
sub expand_environment_strings($)
{
	my $s = shift;
	# we use a reverse sort so we do the longer ones first
	foreach my $k (sort { $b cmp $a } keys %ENV) {
		$s =~ s/\$$k/$ENV{$k}/g;
	}
	return $s;
}

sub run_testsuite($$$$$)
{
	my ($envname, $name, $cmd, $i, $totalsuites) = @_;
	my $pcap_file = setup_pcap($name);

	Subunit::start_testsuite($name);
	Subunit::progress_push();
	Subunit::report_time(time());
	system($cmd);
	Subunit::report_time(time());
	Subunit::progress_pop();

	if ($? == -1) {
		print "command: $cmd\n";
		printf "expanded command: %s\n", expand_environment_strings($cmd);
		Subunit::end_testsuite($name, "error", "Unable to run $cmd: $!");
		exit(1);
	} elsif ($? & 127) {
		print "command: $cmd\n";
		printf "expanded command: %s\n", expand_environment_strings($cmd);
		Subunit::end_testsuite($name, "error",
			sprintf("%s died with signal %d, %s coredump\n", $cmd, ($? & 127),  ($? & 128) ? 'with' : 'without'));
		exit(1);
	}

	my $exitcode = $? >> 8;

	my $envlog = getlog_env($envname);
	if ($envlog ne "") {
		print "envlog: $envlog\n";
	}

	print "command: $cmd\n";
	printf "expanded command: %s\n", expand_environment_strings($cmd);

	if ($exitcode == 0) {
		Subunit::end_testsuite($name, "success");
	} else {
		Subunit::end_testsuite($name, "failure", "Exit code was $exitcode");
	}

	cleanup_pcap($pcap_file, $exitcode);

	if (not $opt_socket_wrapper_keep_pcap and defined($pcap_file)) {
		print "PCAP FILE: $pcap_file\n";
	}

	if ($exitcode != 0) {
		exit(1) if ($opt_one);
	}

	return $exitcode;
}

sub ShowHelp()
{
	print "Samba test runner
Copyright (C) Jelmer Vernooij <jelmer\@samba.org>
Copyright (C) Stefan Metzmacher <metze\@samba.org>

Usage: $Script [OPTIONS] TESTNAME-REGEX [TESTNAME-REGEX...]

Generic options:
 --help                     this help page
 --target=samba[3]|win      Samba version to target
 --testlist=FILE            file to read available tests from
 --exclude=FILE             Exclude tests listed in the file
 --include=FILE             Include tests listed in the file
 --exclude-env=ENV          Exclude tests for the specified environment
 --include-env=ENV          Include tests for the specified environment

Paths:
 --prefix=DIR               prefix to run tests in [st]
 --srcdir=DIR               source directory [.]
 --bindir=DIR               binaries directory [./bin]

Preload cwrap:
 --nss_wrapper_so_path=FILE the nss_wrapper library to preload
 --resolv_wrapper_so_path=FILE the resolv_wrapper library to preload
 --socket_wrapper_so_path=FILE the socket_wrapper library to preload
 --uid_wrapper_so_path=FILE the uid_wrapper library to preload

DNS:
  --use-dns-faking          Fake DNS entries rather than talking to our
                            DNS implementation.

Target Specific:
 --socket-wrapper-pcap      save traffic to pcap directories
 --socket-wrapper-keep-pcap keep all pcap files, not just those for tests that 
                            failed
 --socket-wrapper           enable socket wrapper

Samba4 Specific:
 --ldap=openldap|fedora-ds  back samba onto specified ldap server

Behaviour:
 --quick                    run quick overall test
 --one                      abort when the first test fails
 --testenv                  run a shell in the requested test environment
 --list                     list available tests
";
	exit(0);
}

my $result = GetOptions (
		'help|h|?' => \$opt_help,
		'target=s' => \$opt_target,
		'prefix=s' => \$prefix,
		'socket-wrapper' => \$opt_socket_wrapper,
		'socket-wrapper-pcap' => \$opt_socket_wrapper_pcap,
		'socket-wrapper-keep-pcap' => \$opt_socket_wrapper_keep_pcap,
		'quick' => \$opt_quick,
		'one' => \$opt_one,
		'exclude=s' => \@opt_exclude,
		'include=s' => \@opt_include,
		'exclude-env=s' => \@opt_exclude_env,
		'include-env=s' => \@opt_include_env,
		'srcdir=s' => \$srcdir,
		'bindir=s' => \$bindir,
		'testenv' => \$opt_testenv,
		'list' => \$opt_list,
		'mitkrb5' => \$opt_mitkrb5,
		'ldap:s' => \$ldap,
		'resetup-environment' => \$opt_resetup_env,
		'testlist=s' => \@testlists,
		'random-order' => \$opt_random_order,
		'load-list=s' => \$opt_load_list,
		'nss_wrapper_so_path=s' => \$opt_libnss_wrapper_so_path,
		'resolv_wrapper_so_path=s' => \$opt_libresolv_wrapper_so_path,
		'socket_wrapper_so_path=s' => \$opt_libsocket_wrapper_so_path,
		'uid_wrapper_so_path=s' => \$opt_libuid_wrapper_so_path,
		'use-dns-faking' => \$opt_use_dns_faking
	    );

exit(1) if (not $result);

ShowHelp() if ($opt_help);

die("--list and --testenv are mutually exclusive") if ($opt_list and $opt_testenv);

# we want unbuffered output
$| = 1;

my @tests = @ARGV;

# quick hack to disable rpc validation when using valgrind - its way too slow
unless (defined($ENV{VALGRIND})) {
	$ENV{VALIDATE} = "validate";
	$ENV{MALLOC_CHECK_} = 3;
}

# make all our python scripts unbuffered
$ENV{PYTHONUNBUFFERED} = 1;

my $bindir_abs = abs_path($bindir);

# Backwards compatibility:
if (defined($ENV{TEST_LDAP}) and $ENV{TEST_LDAP} eq "yes") {
	if (defined($ENV{FEDORA_DS_ROOT})) {
		$ldap = "fedora-ds";
	} else {
		$ldap = "openldap";
	}
}

my $torture_maxtime = ($ENV{TORTURE_MAXTIME} or 1200);
if ($ldap) {
	# LDAP is slow
	$torture_maxtime *= 2;
}

$prefix =~ s+//+/+;
$prefix =~ s+/./+/+;
$prefix =~ s+/$++;

die("using an empty prefix isn't allowed") unless $prefix ne "";

# Ensure we have the test prefix around.
#
# We need restrictive
# permissions on this as some subdirectories in this tree will have
# wider permissions (ie 0777) and this would allow other users on the
# host to subvert the test process.
umask 0077;
mkdir($prefix, 0700) unless -d $prefix;
chmod 0700, $prefix;
# We need to have no umask limitations for the tests.
umask 0000;

my $prefix_abs = abs_path($prefix);
my $tmpdir_abs = abs_path("$prefix/tmp");
mkdir($tmpdir_abs, 0777) unless -d $tmpdir_abs;

my $srcdir_abs = abs_path($srcdir);

die("using an empty absolute prefix isn't allowed") unless $prefix_abs ne "";
die("using '/' as absolute prefix isn't allowed") unless $prefix_abs ne "/";

$ENV{SAMBA_SELFTEST} = "1";

$ENV{PREFIX} = $prefix;
$ENV{PREFIX_ABS} = $prefix_abs;
$ENV{SRCDIR} = $srcdir;
$ENV{SRCDIR_ABS} = $srcdir_abs;
$ENV{GNUPGHOME} = "$srcdir_abs/selftest/gnupg";
$ENV{BINDIR} = $bindir_abs;

my $tls_enabled = not $opt_quick;
$ENV{TLS_ENABLED} = ($tls_enabled?"yes":"no");

sub prefix_pathvar($$)
{
	my ($name, $newpath) = @_;
	if (defined($ENV{$name})) {
		$ENV{$name} = "$newpath:$ENV{$name}";
	} else {
		$ENV{$name} = $newpath;
	}
}
prefix_pathvar("PKG_CONFIG_PATH", "$bindir_abs/pkgconfig");
prefix_pathvar("PYTHONPATH", "$bindir_abs/python");

if ($opt_socket_wrapper_keep_pcap) {
	# Socket wrapper keep pcap implies socket wrapper pcap
	$opt_socket_wrapper_pcap = 1;
}

if ($opt_socket_wrapper_pcap) {
	# Socket wrapper pcap implies socket wrapper
	$opt_socket_wrapper = 1;
}

my $ld_preload = $ENV{LD_PRELOAD};

if ($opt_libnss_wrapper_so_path) {
	if ($ld_preload) {
		$ld_preload = "$ld_preload:$opt_libnss_wrapper_so_path";
	} else {
		$ld_preload = "$opt_libnss_wrapper_so_path";
	}
}

if ($opt_libresolv_wrapper_so_path) {
	if ($ld_preload) {
		$ld_preload = "$ld_preload:$opt_libresolv_wrapper_so_path";
	} else {
		$ld_preload = "$opt_libresolv_wrapper_so_path";
	}
}

if ($opt_libsocket_wrapper_so_path) {
	if ($ld_preload) {
		$ld_preload = "$ld_preload:$opt_libsocket_wrapper_so_path";
	} else {
		$ld_preload = "$opt_libsocket_wrapper_so_path";
	}
}

if ($opt_libuid_wrapper_so_path) {
	if ($ld_preload) {
		$ld_preload = "$ld_preload:$opt_libuid_wrapper_so_path";
	} else {
		$ld_preload = "$opt_libuid_wrapper_so_path";
	}
}

$ENV{LD_PRELOAD} = $ld_preload;
print "LD_PRELOAD=$ENV{LD_PRELOAD}\n";

# Enable uid_wrapper globally
$ENV{UID_WRAPPER} = 1;

# Disable RTLD_DEEPBIND hack for Samba bind dlz module
#
# This is needed in order to allow the ldb_*ldap module
# to work with a preloaded socket wrapper.
$ENV{LDB_MODULES_DISABLE_DEEPBIND} = 1;

my $socket_wrapper_dir;
if ($opt_socket_wrapper) {
	$socket_wrapper_dir = SocketWrapper::setup_dir("$prefix_abs/w", $opt_socket_wrapper_pcap);
	print "SOCKET_WRAPPER_DIR=$socket_wrapper_dir\n";
} elsif (not $opt_list) {
	 unless ($< == 0) {
		 warn("not using socket wrapper, but also not running as root. Will not be able to listen on proper ports");
	 }
}

if ($opt_use_dns_faking) {
	print "DNS: Faking nameserver\n";
	$ENV{SAMBA_DNS_FAKING} = 1;
}

my $target;
my $testenv_default = "none";

if ($opt_mitkrb5 == 1) {
	$ENV{MITKRB5} = $opt_mitkrb5;
}

# After this many seconds, the server will self-terminate.  All tests
# must terminate in this time, and testenv will only stay alive this
# long

my $server_maxtime;
if ($opt_testenv) {
    # 1 year should be enough :-)
    $server_maxtime = 365 * 24 * 60 * 60;
} else {
    # make test should run under 5 hours
    $server_maxtime = 5 * 60 * 60;
}

if (defined($ENV{SMBD_MAXTIME}) and $ENV{SMBD_MAXTIME} ne "") {
    $server_maxtime = $ENV{SMBD_MAXTIME};
}

$target = new Samba($bindir, $ldap, $srcdir, $server_maxtime);
unless ($opt_list) {
	if ($opt_target eq "samba") {
		$testenv_default = "ad_dc";
	} elsif ($opt_target eq "samba3") {
		$testenv_default = "nt4_member";
	}
}

sub read_test_regexes($)
{
	my ($name) = @_;
	my @ret = ();
	open(LF, "<$name") or die("unable to read $name: $!");
	while (<LF>) { 
		chomp; 
		next if (/^#/);
		if (/^(.*?)([ \t]+)\#([\t ]*)(.*?)$/) {
			push (@ret, [$1, $4]);
		} else {
			s/^(.*?)([ \t]+)\#([\t ]*)(.*?)$//;
			push (@ret, [$_, undef]); 
		}
	}
	close(LF);
	return @ret;
}

foreach (@opt_exclude) {
	push (@excludes, read_test_regexes($_));
}

foreach (@opt_include) {
	push (@includes, read_test_regexes($_));
}

my $interfaces = join(',', ("127.0.0.11/8",
			    "127.0.0.12/8",
			    "127.0.0.13/8",
			    "127.0.0.14/8",
			    "127.0.0.15/8",
			    "127.0.0.16/8"));

my $clientdir = "$prefix_abs/client";

my $conffile = "$clientdir/client.conf";
$ENV{SMB_CONF_PATH} = $conffile;

sub write_clientconf($$$)
{
	my ($conffile, $clientdir, $vars) = @_;

	mkdir("$clientdir", 0777) unless -d "$clientdir";

	if ( -d "$clientdir/private" ) {
	        unlink <$clientdir/private/*>;
	} else {
	        mkdir("$clientdir/private", 0777);
	}

	if ( -d "$clientdir/bind-dns" ) {
	        unlink <$clientdir/bind-dns/*>;
	} else {
	        mkdir("$clientdir/bind-dns", 0777);
	}

	if ( -d "$clientdir/lockdir" ) {
	        unlink <$clientdir/lockdir/*>;
	} else {
	        mkdir("$clientdir/lockdir", 0777);
	}

	if ( -d "$clientdir/statedir" ) {
	        unlink <$clientdir/statedir/*>;
	} else {
	        mkdir("$clientdir/statedir", 0777);
	}

	if ( -d "$clientdir/cachedir" ) {
	        unlink <$clientdir/cachedir/*>;
	} else {
	        mkdir("$clientdir/cachedir", 0777);
	}

	# this is ugly, but the ncalrpcdir needs exactly 0755
	# otherwise tests fail.
	my $mask = umask;
	umask 0022;
	if ( -d "$clientdir/ncalrpcdir/np" ) {
	        unlink <$clientdir/ncalrpcdir/np/*>;
		rmdir "$clientdir/ncalrpcdir/np";
	}
	if ( -d "$clientdir/ncalrpcdir" ) {
	        unlink <$clientdir/ncalrpcdir/*>;
		rmdir "$clientdir/ncalrpcdir";
	}
	mkdir("$clientdir/ncalrpcdir", 0755);
	umask $mask;

	my $cadir = "$ENV{SRCDIR_ABS}/selftest/manage-ca/CA-samba.example.com";
	my $cacert = "$cadir/Public/CA-samba.example.com-cert.pem";
	my $cacrl_pem = "$cadir/Public/CA-samba.example.com-crl.pem";
	my $ca_users_dir = "$cadir/Users";

	if ( -d "$clientdir/pkinit" ) {
	        unlink <$clientdir/pkinit/*>;
	} else {
	        mkdir("$clientdir/pkinit", 0700);
	}

	# each user has a USER-${USER_PRINCIPAL_NAME}-cert.pem and
	# USER-${USER_PRINCIPAL_NAME}-private-key.pem symlink
	# We make a copy here and make the certificated easily
	# accessable in the client environment.
	my $mask = umask;
	umask 0077;
	opendir USERS, "${ca_users_dir}" or die "Could not open dir '${ca_users_dir}': $!";
	for my $d (readdir USERS) {
		my $user_dir = "${ca_users_dir}/${d}";
		next if ${d} =~ /^\./;
		next if (! -d "${user_dir}");
		opendir USER, "${user_dir}" or die "Could not open dir '${user_dir}': $!";
		for my $l (readdir USER) {
			my $user_link = "${user_dir}/${l}";
			next if ${l} =~ /^\./;
			next if (! -l "${user_link}");

			my $dest = "${clientdir}/pkinit/${l}";
			Samba::copy_file_content(${user_link}, ${dest});
		}
		closedir USER;
	}
	closedir USERS;
	umask $mask;

	open(CF, ">$conffile");
	print CF "[global]\n";
	print CF "\tnetbios name = client\n";
	if (defined($vars->{DOMAIN})) {
		print CF "\tworkgroup = $vars->{DOMAIN}\n";
	}
	if (defined($vars->{REALM})) {
		print CF "\trealm = $vars->{REALM}\n";
	}
	if ($opt_socket_wrapper) {
		print CF "\tinterfaces = $interfaces\n";
	}
	print CF "
	private dir = $clientdir/private
	binddns dir = $clientdir/bind-dns
	lock dir = $clientdir/lockdir
	state directory = $clientdir/statedir
	cache directory = $clientdir/cachedir
	ncalrpc dir = $clientdir/ncalrpcdir
	panic action = $RealBin/gdb_backtrace \%d
	max xmit = 32K
	notify:inotify = false
	ldb:nosync = true
	system:anonymous = true
	client lanman auth = Yes
	log level = 1
	torture:basedir = $clientdir
#We don't want to pass our self-tests if the PAC code is wrong
	gensec:require_pac = true
#We don't want to run 'speed' tests for very long
        torture:timelimit = 1
        winbind separator = /
	tls cafile = ${cacert}
	tls crlfile = ${cacrl_pem}
	tls verify peer = no_check
	include system krb5 conf = no
";
	close(CF);
}

my @todo = ();

sub should_run_test($)
{
	my $name = shift;
	if ($#tests == -1) {
		return 1;
	}
	for (my $i=0; $i <= $#tests; $i++) {
		if ($name =~ /$tests[$i]/i) {
			return 1;
		}
	}
	return 0;
}

sub read_testlist($)
{
	my ($filename) = @_;

	my @ret = ();
	open(IN, $filename) or die("Unable to open $filename: $!");

	while (<IN>) {
		if (/-- TEST(-LOADLIST|) --\n/) {
			my $supports_loadlist = (defined($1) and $1 eq "-LOADLIST");
			my $name = <IN>;
			$name =~ s/\n//g;
			my $env = <IN>;
			$env =~ s/\n//g;
			my $loadlist;
			if ($supports_loadlist) {
				$loadlist = <IN>;
				$loadlist =~ s/\n//g;
			}
			my $cmdline = <IN>;
			$cmdline =~ s/\n//g;
			if (should_run_test($name) == 1) {
				push (@ret, [$name, $env, $cmdline, $loadlist]);
			}
		} else {
			print;
		}
	}
	close(IN) or die("Error creating recipe from $filename");
	return @ret;
}

if ($#testlists == -1) {
	die("No testlists specified");
}

$ENV{SELFTEST_PREFIX} = "$prefix_abs";
$ENV{SELFTEST_TMPDIR} = "$tmpdir_abs";
$ENV{TMPDIR} = "$tmpdir_abs";
$ENV{TEST_DATA_PREFIX} = "$tmpdir_abs";
if ($opt_socket_wrapper) {
	$ENV{SELFTEST_INTERFACES} = $interfaces;
} else {
	$ENV{SELFTEST_INTERFACES} = "";
}
if ($opt_quick) {
	$ENV{SELFTEST_QUICK} = "1";
} else {
	$ENV{SELFTEST_QUICK} = "";
}
$ENV{SELFTEST_MAXTIME} = $torture_maxtime;

my $selftest_krbt_ccache_path = "$tmpdir_abs/selftest.krb5_ccache";
$ENV{KRB5CCNAME} = "FILE:${selftest_krbt_ccache_path}.global";

my @available = ();
foreach my $fn (@testlists) {
	foreach (read_testlist($fn)) {
		my $name = $$_[0];
		next if (@includes and not defined(find_in_list(\@includes, $name)));
		push (@available, $_);
	}
}

my $restricted = undef;
my $restricted_used = {};

if ($opt_load_list) {
	$restricted = [];
	open(LOAD_LIST, "<$opt_load_list") or die("Unable to open $opt_load_list");
	while (<LOAD_LIST>) {
		chomp;
		push (@$restricted, $_);
	}
	close(LOAD_LIST);
}

my $individual_tests = undef;
$individual_tests = {};

foreach my $testsuite (@available) {
	my $name = $$testsuite[0];
	my $skipreason = skip(@$testsuite);
	if (defined($restricted)) {
		# Find the testsuite for this test
		my $match = undef;
		foreach my $r (@$restricted) {
			if ($r eq $name) {
				$individual_tests->{$name} = [];
				$match = $r;
				$restricted_used->{$r} = 1;
			} elsif (substr($r, 0, length($name)+1) eq "$name.") {
				push(@{$individual_tests->{$name}}, $r);
				$match = $r;
				$restricted_used->{$r} = 1;
			}
		}
		if ($match) {
			if (defined($skipreason)) {
				if (not $opt_list) {
					Subunit::skip_testsuite($name, $skipreason);
				}
			} else {
				push(@todo, $testsuite);
			}
		}
	} elsif (defined($skipreason)) {
		if (not $opt_list) {
			Subunit::skip_testsuite($name, $skipreason);
		}
	} else {
		push(@todo, $testsuite);
	}
}

if (defined($restricted)) {
	foreach (@$restricted) {
		unless (defined($restricted_used->{$_})) {
			print "No test or testsuite found matching $_\n";
		}
	}
} elsif ($#todo == -1) {
	print STDERR "No tests to run\n";
	exit(1);
}

my $suitestotal = $#todo + 1;

unless ($opt_list) {
	Subunit::progress($suitestotal);
	Subunit::report_time(time());
}

my $i = 0;
$| = 1;

my %running_envs = ();

sub get_running_env($)
{
	my ($name) = @_;

	my $envname = $name;

	$envname =~ s/:.*//;

	return $running_envs{$envname};
}

my @exported_envvars = (
	# domain stuff
	"DOMAIN",
	"REALM",

	# stuff related to a trusted domain
	"TRUST_SERVER",
	"TRUST_SERVER_IP",
	"TRUST_SERVER_IPV6",
	"TRUST_NETBIOSNAME",
	"TRUST_USERNAME",
	"TRUST_PASSWORD",
	"TRUST_DOMAIN",
	"TRUST_REALM",

	# domain controller stuff
	"DC_SERVER",
	"DC_SERVER_IP",
	"DC_SERVER_IPV6",
	"DC_NETBIOSNAME",
	"DC_NETBIOSALIAS",

	# domain member
	"MEMBER_SERVER",
	"MEMBER_SERVER_IP",
	"MEMBER_SERVER_IPV6",
	"MEMBER_NETBIOSNAME",
	"MEMBER_NETBIOSALIAS",

	# rpc proxy controller stuff
	"RPC_PROXY_SERVER",
	"RPC_PROXY_SERVER_IP",
	"RPC_PROXY_SERVER_IPV6",
	"RPC_PROXY_NETBIOSNAME",
	"RPC_PROXY_NETBIOSALIAS",

	# domain controller stuff for Vampired DC
	"VAMPIRE_DC_SERVER",
	"VAMPIRE_DC_SERVER_IP",
	"VAMPIRE_DC_SERVER_IPV6",
	"VAMPIRE_DC_NETBIOSNAME",
	"VAMPIRE_DC_NETBIOSALIAS",

	# domain controller stuff for RODC
	"RODC_DC_SERVER",
	"RODC_DC_SERVER_IP",
	"RODC_DC_SERVER_IPV6",
	"RODC_DC_NETBIOSNAME",

	# domain controller stuff for FL 2000 Vampired DC
	"VAMPIRE_2000_DC_SERVER",
	"VAMPIRE_2000_DC_SERVER_IP",
	"VAMPIRE_2000_DC_SERVER_IPV6",
	"VAMPIRE_2000_DC_NETBIOSNAME",
	"VAMPIRE_2000_DC_NETBIOSALIAS",

	"PROMOTED_DC_SERVER",
	"PROMOTED_DC_SERVER_IP",
	"PROMOTED_DC_SERVER_IPV6",
	"PROMOTED_DC_NETBIOSNAME",
	"PROMOTED_DC_NETBIOSALIAS",

	# server stuff
	"SERVER",
	"SERVER_IP",
	"SERVER_IPV6",
	"NETBIOSNAME",
	"NETBIOSALIAS",

	# user stuff
	"USERNAME",
	"USERID",
	"PASSWORD",
	"DC_USERNAME",
	"DC_PASSWORD",

	# UID/GID for rfc2307 mapping tests
	"UID_RFC2307TEST",
	"GID_RFC2307TEST",

	# misc stuff
	"KRB5_CONFIG",
	"KRB5CCNAME",
	"SELFTEST_WINBINDD_SOCKET_DIR",
	"NMBD_SOCKET_DIR",
	"LOCAL_PATH",
	"DNS_FORWARDER1",
	"DNS_FORWARDER2",
	"RESOLV_CONF",
	"UNACCEPTABLE_PASSWORD",
	"LOCK_DIR",
	"SMBD_TEST_LOG",

	# nss_wrapper
	"NSS_WRAPPER_PASSWD",
	"NSS_WRAPPER_GROUP",
	"NSS_WRAPPER_HOSTS",
	"NSS_WRAPPER_HOSTNAME",
	"NSS_WRAPPER_MODULE_SO_PATH",
	"NSS_WRAPPER_MODULE_FN_PREFIX",

	# resolv_wrapper
	"RESOLV_WRAPPER_CONF",
	"RESOLV_WRAPPER_HOSTS",
);

sub sighandler($)
{
	my $signame = shift;

	$SIG{INT} = $SIG{QUIT} = $SIG{TERM} = 'DEFAULT';
	$SIG{PIPE} = 'IGNORE';

	open(STDOUT, ">&STDERR") or die "can't dup STDOUT to STDERR: $!";

	print "$0: PID[$$]: Got SIG${signame} teardown environments.\n";
	teardown_env($_) foreach(keys %running_envs);
	system("pstree -p $$");
	print "$0: PID[$$]: Exiting...\n";
	exit(1);
};

$SIG{INT} = $SIG{QUIT} = $SIG{TERM} = $SIG{PIPE} = \&sighandler;

sub setup_env($$)
{
	my ($name, $prefix) = @_;

	my $testenv_vars = undef;

	my $envname = $name;
	my $option = $name;

	$envname =~ s/:.*//;
	$option =~ s/^[^:]*//;
	$option =~ s/^://;

	$option = "client" if $option eq "";

	# Initially clear out the environment for the provision, so previous envs'
	# variables don't leak in. Provisioning steps must explicitly set their
	# necessary variables when calling out to other executables
	foreach (@exported_envvars) {
		unless ($_ == "NSS_WRAPPER_HOSTS" ||
		        $_ == "RESOLV_WRAPPER_HOSTS")
		{
			delete $ENV{$_};
		}
	}
	delete $ENV{SOCKET_WRAPPER_DEFAULT_IFACE};
	delete $ENV{SMB_CONF_PATH};

	$ENV{KRB5CCNAME} = "FILE:${selftest_krbt_ccache_path}.${envname}/ignore";

	if (defined(get_running_env($envname))) {
		$testenv_vars = get_running_env($envname);
		if (not $testenv_vars->{target}->check_env($testenv_vars)) {
			print $testenv_vars->{target}->getlog_env($testenv_vars);
			$testenv_vars = undef;
		}
	} else {
		$testenv_vars = $target->setup_env($envname, $prefix);
		if (defined($testenv_vars) and $testenv_vars eq "UNKNOWN") {
		    return $testenv_vars;
		} elsif (defined($testenv_vars) && not defined($testenv_vars->{target})) {
		        $testenv_vars->{target} = $target;
		}
		if (not defined($testenv_vars)) {
			warn("$opt_target can't start up known environment '$envname'");
		}
	}

	return undef unless defined($testenv_vars);

	$running_envs{$envname} = $testenv_vars;

	if ($option eq "local") {
		SocketWrapper::set_default_iface($testenv_vars->{SOCKET_WRAPPER_DEFAULT_IFACE});
		$ENV{SMB_CONF_PATH} = $testenv_vars->{SERVERCONFFILE};
	} elsif ($option eq "client") {
		SocketWrapper::set_default_iface(11);
		write_clientconf($conffile, $clientdir, $testenv_vars);
		$ENV{SMB_CONF_PATH} = $conffile;
	} else {
		die("Unknown option[$option] for envname[$envname]");
	}

	foreach (@exported_envvars) {
		if (defined($testenv_vars->{$_})) {
			$ENV{$_} = $testenv_vars->{$_};
		} else {
			delete $ENV{$_};
		}
	}

	my $krb5_ccache_path = "${selftest_krbt_ccache_path}.${envname}.${option}";
	unlink($krb5_ccache_path);
	$ENV{KRB5CCNAME} = "FILE:${krb5_ccache_path}";
	return $testenv_vars;
}

sub exported_envvars_str($)
{
	my ($testenv_vars) = @_;
	my $out = "";

	foreach (@exported_envvars) {
		next unless defined($testenv_vars->{$_});
		$out .= $_."=".$testenv_vars->{$_}."\n";
	}

	return $out;
}

sub getlog_env($)
{
	my ($envname) = @_;
	return "" if ($envname eq "none");
	my $env = get_running_env($envname);
	return $env->{target}->getlog_env($env);
}

sub check_env($)
{
	my ($envname) = @_;
	my $env = get_running_env($envname);
	return $env->{target}->check_env($env);
}

sub teardown_env($)
{
	my ($envname) = @_;
	return if ($envname eq "none");
	print STDERR "teardown_env($envname)\n";
	my $env = get_running_env($envname);
	$env->{target}->teardown_env($env);
	delete $running_envs{$envname};
}

# This 'global' file needs to be empty when we start
unlink("$prefix_abs/dns_host_file");
unlink("$prefix_abs/hosts");

if ($opt_random_order) {
	require List::Util;
	my @newtodo = List::Util::shuffle(@todo);
	@todo = @newtodo;
}

if ($opt_testenv) {
	my $testenv_name = $ENV{SELFTEST_TESTENV};
	$testenv_name = $testenv_default unless defined($testenv_name);

	my $testenv_vars = setup_env($testenv_name, $prefix);

	if (not $testenv_vars or $testenv_vars eq "UNKNOWN") {
		die("Unable to setup environment $testenv_name");
	}

	$ENV{PIDDIR} = $testenv_vars->{PIDDIR};
	$ENV{ENVNAME} = $testenv_name;

	my $envvarstr = exported_envvars_str($testenv_vars);

	my @term_args = ("echo -e \"
Welcome to the Samba4 Test environment '$testenv_name'

This matches the client environment used in make test
server is pid `cat \$PIDDIR/samba.pid`

Some useful environment variables:
TORTURE_OPTIONS=\$TORTURE_OPTIONS
SMB_CONF_PATH=\$SMB_CONF_PATH

$envvarstr
\" && LD_LIBRARY_PATH=$ENV{LD_LIBRARY_PATH} bash");
	my @term = ();
	if ($ENV{TERMINAL}) {
	    @term = ($ENV{TERMINAL});
	} else {
	    @term = ("xterm", "-e");
	    unshift(@term_args, ("bash", "-c"));
	}

	system(@term, @term_args);

	teardown_env($testenv_name);
} elsif ($opt_list) {
	foreach (@todo) {
		my $name = $$_[0];
		my $envname = $$_[1];
		my $cmd = $$_[2];
		my $listcmd = $$_[3];

		unless (defined($listcmd)) {
			warn("Unable to list tests in $name");
			# Rather than ignoring this testsuite altogether, just pretend the entire testsuite is
			# a single "test".
			print "$name\n";
			next;
		}

		system($listcmd);

		if ($? == -1) {
			die("Unable to run $listcmd: $!");
		} elsif ($? & 127) {
			die(sprintf("%s died with signal %d, %s coredump\n", $listcmd, ($? & 127),  ($? & 128) ? 'with' : 'without'));
		}

		my $exitcode = $? >> 8;
		if ($exitcode != 0) {
			die("$cmd exited with exit code $exitcode");
		}
	}
} else {
	foreach (@todo) {
		$i++;
		my $cmd = $$_[2];
		my $name = $$_[0];
		my $envname = $$_[1];
		my $envvars = setup_env($envname, $prefix);

		if (not defined($envvars)) {
			Subunit::start_testsuite($name);
			Subunit::end_testsuite($name, "error",
				"unable to set up environment $envname - exiting");
			next;
		} elsif ($envvars eq "UNKNOWN") {
			Subunit::start_testsuite($name);
			Subunit::end_testsuite($name, "error",
				"environment $envname is unknown - exiting");
			next;
		}

		# Generate a file with the individual tests to run, if the 
		# test runner for this test suite supports it.
		if ($individual_tests and $individual_tests->{$name}) {
			if ($$_[3]) {
				my ($fh, $listid_file) = tempfile(UNLINK => 0);
				foreach my $test (@{$individual_tests->{$name}}) {
					print $fh substr($test, length($name)+1) . "\n";
				}
				$cmd =~ s/\$LOADLIST/--load-list=$listid_file/g;
			} else {
				warn("Unable to run individual tests in $name, it does not support --loadlist.");
			}
		}

		run_testsuite($envname, $name, $cmd, $i, $suitestotal);

		teardown_env($envname) if ($opt_resetup_env);
	}
}

print "\n";

teardown_env($_) foreach (keys %running_envs);

my $failed = 0;

# if there were any valgrind failures, show them
foreach (<$prefix/valgrind.log*>) {
	next unless (-s $_);
	print "VALGRIND FAILURE\n";
	$failed++;
	system("cat $_");
}
exit 0;
