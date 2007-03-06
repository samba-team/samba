#!/usr/bin/perl

use FindBin qw($RealBin);
use lib "$RealBin";

use Samba4;
use SocketWrapper;

my $vars = Samba4::provision("st");
foreach (keys %$vars) { $ENV{$_} = $vars->{$_}; }
SocketWrapper::set_default_iface(1);
my $test_fifo = "st/smb_test.fifo";
my $socket_wrapper_dir = SocketWrapper::setup_dir("$vars->{PREFIX_ABS}/w");
Samba4::smbd_check_or_start("bin", $test_fifo, $ENV{SMBD_TEST_LOG}, $socket_wrapper_dir, undef, $ENV{CONFFILE});
SocketWrapper::set_default_iface(6);
my $interfaces = join(',', ("127.0.0.6/8", 
		                 "127.0.0.7/8",
						 "127.0.0.8/8",
						 "127.0.0.9/8",
						 "127.0.0.10/8",
						 "127.0.0.11/8"));

push (@torture_options, "--option=interfaces=$interfaces", 
	                    $ENV{CONFIGURATION}, 
						"--target=samba4");

$ENV{TORTURE_OPTIONS} = join(' ', @torture_options);

open(DATA, ">$test_fifo");
Samba4::wait_for_start();
system("xterm -e 'echo -e \"Welcome to the Samba4 Test environment
This matches the client environment used in make test
smbd is pid `cat \$PIDDIR/smbd.pid`

Some useful environment variables:
AUTH=\$AUTH
TORTURE_OPTIONS=\$TORTURE_OPTIONS
CONFIGURATION=\$CONFIGURATION
SERVER=\$SERVER
NETBIOSNAME=\$NETBIOSNAME\" && bash'");
close(DATA);

