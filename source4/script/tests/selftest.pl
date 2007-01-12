#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.
use strict;
use warnings;

use FindBin qw($RealBin $Script);
use File::Spec;
use POSIX;
use Cwd;

sub slapd_start($$) {
	my ($conf, $uri) = @_;
    my $oldpath = $ENV{PATH};
    $ENV{PATH} = "/usr/local/sbin:/usr/sbin:/sbin:$ENV{PATH}";
	# running slapd in the background means it stays in the same process group, so it can be
	# killed by timelimit
    system("slapd -d0 -f $conf -h $uri &");
    $ENV{PATH} = $oldpath;
    return $? >> 8;
}

sub smbd_check_or_start($$$$$$) 
{
	my ($bindir, $test_fifo, $test_log, $socket_wrapper_dir, $max_time, $conffile) = @_;
	return 0 if ( -p $test_fifo );

	if (defined($socket_wrapper_dir)) {
		if ( -d $socket_wrapper_dir ) {
			unlink <$socket_wrapper_dir/*>;
		} else {
			mkdir($socket_wrapper_dir);
		}
	}

	unlink($test_fifo);
	system("mkfifo $test_fifo");

	unlink($test_log);
	
	my $valgrind = "";
	if (defined($ENV{SMBD_VALGRIND})) {
		$valgrind = $ENV{SMBD_VALGRIND};
	} 

	print "STARTING SMBD...";
	my $pid = fork();
	if ($pid == 0) {
		my $ret = system("$valgrind $bindir/smbd --maximum-runtime=$max_time -s $conffile -M single -i --leak-report-full < $test_fifo > $test_log");
		open LOG, ">>$test_log";
		if ($? == -1) {
			print LOG "Unable to start smbd: $ret: $!\n";
			print "Unable to start smbd: $ret: $!\n";
			exit 1;
		}
		unlink($test_fifo);
		unlink(<$socket_wrapper_dir/*>) if (defined($socket_wrapper_dir) and -d $socket_wrapper_dir);
		my $exit = $? >> 8;
		if ( $ret == 0 ) {
			print "smbd exits with status $exit\n";
			print LOG "smbd exits with status $exit\n";
		} elsif ( $ret & 127 ) {
			print "smbd got signal ".($ret & 127)." and exits with $exit!\n";
			print LOG "smbd got signal".($ret & 127). " and exits with $exit!\n";
		} else {
			$ret = $? >> 8;
			print "smbd failed with status $exit!\n";
			print LOG "smbd failed with status $exit!\n";
		}
		close(LOG);
		exit $exit;
	}
	print "DONE\n";

	return $pid;
}

sub teststatus($$) {
	my ($name, $failed) = @_;

	print "TEST STATUS: $failed failures\n";
	if ($failed > 0) {
print <<EOF	    
************************
*** TESTSUITE FAILED ***
************************
EOF
;
	}
	exit $failed;
}

die("Usage: $Script PREFIX TESTS [SOCKET_WRAPPER]") if ( $#ARGV == -1);

my $prefix = shift;
my $tests = shift;
my $socket_wrapper = shift;

my $torture_maxtime = $ENV{TORTURE_MAXTIME};
unless (defined($torture_maxtime)) {
	$torture_maxtime = 1200;
}

# disable rpc validation when using valgrind - its way too slow
my $valgrind = $ENV{VALGRIND};
my $validate = undef;
unless (defined($valgrind)) {
	$validate = "validate";
}

my $old_pwd = "$RealBin/../..";
my $ldap = (defined($ENV{TEST_LDAP}) and ($ENV{TEST_LDAP} eq "yes"))?1:0;

$prefix =~ s+//+/+;
$ENV{PREFIX} = $prefix;

my $srcdir = "$RealBin/../..";
if (defined($ENV{srcdir})) {
	$srcdir = $ENV{srcdir};
}
$ENV{SRCDIR} = $srcdir;

my $bindir = "$srcdir/bin";
my $setupdir = "$srcdir/setup";
my $testsdir = "$srcdir/script/tests";

my $tls_enabled = 0;
if ($tests eq "all") {
	$tls_enabled = 1;
}

$ENV{TLS_ENABLED} = ($tls_enabled?"yes":"no");
$ENV{LD_LDB_MODULE_PATH} = "$old_pwd/bin/modules/ldb";
$ENV{LD_SAMBA_MODULE_PATH} = "$old_pwd/bin/modules";
if (defined($ENV{LD_LIBRARY_PATH})) {
	$ENV{LD_LIBRARY_PATH} = "$old_pwd/bin/shared:$ENV{LD_LIBRARY_PATH}";
} else {
	$ENV{LD_LIBRARY_PATH} = "$old_pwd/bin/shared";
}
$ENV{PKG_CONFIG_PATH} = "$old_pwd/bin/pkgconfig:$ENV{PKG_CONFIG_PATH}";
$ENV{PATH} = "$old_pwd/bin:$ENV{PATH}";

print "PROVISIONING...";
open(IN, "$RealBin/mktestsetup.sh $prefix|") or die("Unable to setup");
while (<IN>) {
	next unless (/^([A-Z_]+)=(.*)$/);
	$ENV{$1} = $2;
}
close(IN);

my $socket_wrapper_dir = undef;

if ( defined($socket_wrapper) and $socket_wrapper eq "SOCKET_WRAPPER")
{
	$socket_wrapper_dir = "$prefix/w";
	$ENV{SOCKET_WRAPPER_DIR} = $socket_wrapper_dir;
	print "SOCKET_WRAPPER_DIR=$ENV{SOCKET_WRAPPER_DIR}\n";
} else {
	print "NOT USING SOCKET_WRAPPER\n";
}

#Start slapd before smbd
if ($ldap) {
    slapd_start($ENV{SLAPD_CONF}, $ENV{LDAPI_ESCAPE}) or die("couldn't start slapd");
    print "LDAP PROVISIONING...";
    system("$bindir/smbscript $setupdir/provision $ENV{PROVISION_OPTIONS} --ldap-backend=$ENV{LDAPI}") or
		die("LDAP PROVISIONING failed: $bindir/smbscript $setupdir/provision $ENV{PROVISION_OPTIONS} --ldap-backend=$ENV{LDAPI}");

    #LDAP is slow
	$torture_maxtime *= 2;
}

my $test_fifo = "$prefix/smbd_test.fifo";

$ENV{SMBD_TEST_FIFO} = $test_fifo;
$ENV{SMBD_TEST_LOG} = "$prefix/smbd_test.log";

$ENV{SOCKET_WRAPPER_DEFAULT_IFACE} = 1;
my $max_time = 5400;
if (defined($ENV{SMBD_MAX_TIME})) {
	$max_time = $ENV{SMBD_MAX_TIME};
}
smbd_check_or_start($bindir, $test_fifo, $ENV{SMBD_TEST_LOG}, $socket_wrapper_dir, $max_time, $ENV{CONFFILE});

$ENV{SOCKET_WRAPPER_DEFAULT_IFACE} = 6;
$ENV{TORTURE_INTERFACES} = '127.0.0.6/8,127.0.0.7/8,127.0.0.8/8,127.0.0.9/8,127.0.0.10/8,127.0.0.11/8';

my @torture_options = ("--option=interfaces=$ENV{TORTURE_INTERFACES} $ENV{CONFIGURATION}");
# ensure any one smbtorture call doesn't run too long
push (@torture_options, "--maximum-runtime=$torture_maxtime");
push (@torture_options, "--target=samba4");
push (@torture_options, "--option=torture:progress=no") 
	if (defined($ENV{RUN_FROM_BUILD_FARM}) and $ENV{RUN_FROM_BUILD_FARM} eq "yes");

$ENV{TORTURE_OPTIONS} = join(' ', @torture_options);
print "OPTIONS $ENV{TORTURE_OPTIONS}\n";

my $start = time();

open(DATA, ">$test_fifo");

# give time for nbt server to register its names
print "delaying for nbt name registration\n";
sleep(4);

# This will return quickly when things are up, but be slow if we need to wait for (eg) SSL init 
system("bin/nmblookup $ENV{CONFIGURATION} $ENV{SERVER}");
system("bin/nmblookup $ENV{CONFIGURATION} -U $ENV{SERVER} $ENV{SERVER}");
system("bin/nmblookup $ENV{CONFIGURATION} $ENV{SERVER}");
system("bin/nmblookup $ENV{CONFIGURATION} -U $ENV{SERVER} $ENV{NETBIOSNAME}");
system("bin/nmblookup $ENV{CONFIGURATION} $ENV{NETBIOSNAME}");
system("bin/nmblookup $ENV{CONFIGURATION} -U $ENV{SERVER} $ENV{NETBIOSNAME}");

# start off with 0 failures
$ENV{failed} = 0;
$ENV{totalfailed} = 0;

system("$testsdir/tests_$tests.sh");

close(DATA);

my $failed = $? >> 8;

if (-f "$ENV{PIDDIR}/smbd.pid" ) {
	open(IN, "<$ENV{PIDDIR}/smbd.pid") or die("unable to open smbd pid file");
	kill 9, <IN>;
	close(IN);
}

if ($ldap) {
    open(IN, "<$ENV{PIDDIR}/slapd.pid") or die("unable to open slapd pid file");
	kill 9, <IN>;
	close(IN);
}

my $end=time();
print "DURATION: " . ($end-$start). " seconds\n";

# if there were any valgrind failures, show them
foreach (<$prefix/valgrind.log*>) {
	next unless (-s $_);
	system("grep DWARF2.CFI.reader $_ > /dev/null");
	if ($? >> 8 == 0) {
	    print "VALGRIND FAILURE\n";
	    $failed++;
	    system("cat $_");
	}
}

teststatus($Script, $failed);

exit $failed;
