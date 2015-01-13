#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

package Samba3;

use strict;
use Cwd qw(abs_path);
use FindBin qw($RealBin);
use POSIX;
use target::Samba;

sub have_ads($) {
        my ($self) = @_;
	my $found_ads = 0;
        my $smbd_build_options = Samba::bindir_path($self, "smbd") . " -b|";
        open(IN, $smbd_build_options) or die("Unable to run $smbd_build_options: $!");

        while (<IN>) {
                if (/WITH_ADS/) {
                       $found_ads = 1;
                }
        }
	close IN;

	# If we were not built with ADS support, pretend we were never even available
	print "smbd does not have ADS support\n" unless $found_ads;
	return $found_ads;
}

# return smb.conf parameters applicable to @path, based on the underlying
# filesystem type
sub get_fs_specific_conf($$)
{
	my ($self, $path) = @_;
	my $mods = "";
	my $stat_out = `stat --file-system $path` or return "";

	if ($stat_out =~ m/Type:\s+btrfs/) {
		$mods .= "btrfs ";
	}

	if ($mods) {
		return "vfs objects = $mods";
	}

	return undef;
}

sub new($$) {
	my ($classname, $bindir, $binary_mapping, $srcdir, $server_maxtime) = @_;
	my $self = { vars => {},
		     bindir => $bindir,
		     binary_mapping => $binary_mapping,
		     srcdir => $srcdir,
		     server_maxtime => $server_maxtime
	};
	bless $self;
	return $self;
}

sub teardown_env($$)
{
	my ($self, $envvars) = @_;
	my $count = 0;

	# This should cause smbd to terminate gracefully
	close($envvars->{STDIN_PIPE});

	my $smbdpid = $envvars->{SMBD_TL_PID};
	my $nmbdpid = $envvars->{NMBD_TL_PID};
	my $winbinddpid = $envvars->{WINBINDD_TL_PID};

	# This should give it time to write out the gcov data
	until ($count > 20) {
	    my $smbdchild = Samba::cleanup_child($smbdpid, "smbd");
	    my $nmbdchild = Samba::cleanup_child($nmbdpid, "nmbd");
	    my $winbinddchild = Samba::cleanup_child($winbinddpid, "winbindd");
	    if ($smbdchild == -1
		&& $nmbdchild == -1
		&& $winbinddchild == -1) {
		last;
	    }
	    sleep(1);
	    $count++;
	}

	if ($count <= 20 && kill(0, $smbdpid, $nmbdpid, $winbinddpid) == 0) {
	    return;
	}

	$self->stop_sig_term($smbdpid);
	$self->stop_sig_term($nmbdpid);
	$self->stop_sig_term($winbinddpid);

	$count = 0;
	until ($count > 10) {
	    my $smbdchild = Samba::cleanup_child($smbdpid, "smbd");
	    my $nmbdchild = Samba::cleanup_child($nmbdpid, "nmbd");
	    my $winbinddchild = Samba::cleanup_child($winbinddpid, "winbindd");
	    if ($smbdchild == -1
		&& $nmbdchild == -1
		&& $winbinddchild == -1) {
		last;
	    }
	    sleep(1);
	    $count++;
	}

	if ($count <= 10 && kill(0, $smbdpid, $nmbdpid, $winbinddpid) == 0) {
	    return;
	}

	warn("timelimit process did not quit on SIGTERM, sending SIGKILL");
	$self->stop_sig_kill($smbdpid);
	$self->stop_sig_kill($nmbdpid);
	$self->stop_sig_kill($winbinddpid);

	return 0;
}

sub getlog_env_app($$$)
{
	my ($self, $envvars, $name) = @_;

	my $title = "$name LOG of: $envvars->{NETBIOSNAME}\n";
	my $out = $title;

	open(LOG, "<".$envvars->{$name."_TEST_LOG"});

	seek(LOG, $envvars->{$name."_TEST_LOG_POS"}, SEEK_SET);
	while (<LOG>) {
		$out .= $_;
	}
	$envvars->{$name."_TEST_LOG_POS"} = tell(LOG);
	close(LOG);

	return "" if $out eq $title;
 
	return $out;
}

sub getlog_env($$)
{
	my ($self, $envvars) = @_;
	my $ret = "";

	$ret .= $self->getlog_env_app($envvars, "SMBD");
	$ret .= $self->getlog_env_app($envvars, "NMBD");
	$ret .= $self->getlog_env_app($envvars, "WINBINDD");

	return $ret;
}

sub check_env($$)
{
	my ($self, $envvars) = @_;

	my $childpid = waitpid(-1, WNOHANG);

	# TODO ...
	return 1;
}

sub setup_env($$$)
{
	my ($self, $envname, $path) = @_;

	$ENV{ENVNAME} = $envname;

	if (defined($self->{vars}->{$envname})) {
	        return $self->{vars}->{$envname};
	}

	if ($envname eq "s3dc") {
		return $self->setup_s3dc("$path/s3dc");
	} elsif ($envname eq "simpleserver") {
		return $self->setup_simpleserver("$path/simpleserver");
	} elsif ($envname eq "maptoguest") {
		return $self->setup_maptoguest("$path/maptoguest");
	} elsif ($envname eq "ktest") {
		return $self->setup_ktest("$path/ktest");
	} elsif ($envname eq "member") {
		if (not defined($self->{vars}->{s3dc})) {
			if (not defined($self->setup_s3dc("$path/s3dc"))) {
			        return undef;
			}
		}
		return $self->setup_member("$path/member", $self->{vars}->{s3dc});
	} else {
		return "UNKNOWN";
	}
}

sub setup_s3dc($$)
{
	my ($self, $path) = @_;

	print "PROVISIONING S3DC...";

	my $s3dc_options = "
	domain master = yes
	domain logons = yes
	lanman auth = yes

	rpc_server:epmapper = external
	rpc_server:spoolss = external
	rpc_server:lsarpc = external
	rpc_server:samr = external
	rpc_server:netlogon = external
	rpc_server:register_embedded_np = yes

	rpc_daemon:epmd = fork
	rpc_daemon:spoolssd = fork
	rpc_daemon:lsasd = fork
";

	my $vars = $self->provision($path,
				    "LOCALS3DC2",
				    "locals3dc2pass",
				    $s3dc_options);

	$vars or return undef;

	if (not $self->check_or_start($vars, "yes", "yes", "yes")) {
	       return undef;
	}

	$vars->{DC_SERVER} = $vars->{SERVER};
	$vars->{DC_SERVER_IP} = $vars->{SERVER_IP};
	$vars->{DC_SERVER_IPV6} = $vars->{SERVER_IPV6};
	$vars->{DC_NETBIOSNAME} = $vars->{NETBIOSNAME};
	$vars->{DC_USERNAME} = $vars->{USERNAME};
	$vars->{DC_PASSWORD} = $vars->{PASSWORD};

	$self->{vars}->{s3dc} = $vars;

	return $vars;
}

sub setup_member($$$)
{
	my ($self, $prefix, $s3dcvars) = @_;

	print "PROVISIONING MEMBER...";

	my $member_options = "
	security = domain
	server signing = on
	dbwrap_tdb_mutexes:* = yes
";
	my $ret = $self->provision($prefix,
				   "LOCALMEMBER3",
				   "localmember3pass",
				   $member_options);

	$ret or return undef;

	my $net = Samba::bindir_path($self, "net");
	my $cmd = "";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	$cmd .= "$net join $ret->{CONFIGURATION} $s3dcvars->{DOMAIN} member";
	$cmd .= " -U$s3dcvars->{USERNAME}\%$s3dcvars->{PASSWORD}";

	if (system($cmd) != 0) {
	    warn("Join failed\n$cmd");
	    return undef;
	}

	if (not $self->check_or_start($ret, "yes", "yes", "yes")) {
	       return undef;
	}

	$ret->{DC_SERVER} = $s3dcvars->{SERVER};
	$ret->{DC_SERVER_IP} = $s3dcvars->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $s3dcvars->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $s3dcvars->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $s3dcvars->{USERNAME};
	$ret->{DC_PASSWORD} = $s3dcvars->{PASSWORD};

	return $ret;
}

sub setup_admember($$$$)
{
	my ($self, $prefix, $dcvars) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->have_ads()) {
	        return "UNKNOWN";
	}

	print "PROVISIONING S3 AD MEMBER...";

	my $member_options = "
	security = ads
	server signing = on
        workgroup = $dcvars->{DOMAIN}
        realm = $dcvars->{REALM}
";

	my $ret = $self->provision($prefix,
				   "LOCALADMEMBER",
				   "loCalMemberPass",
				   $member_options);

	$ret or return undef;

	close(USERMAP);
	$ret->{DOMAIN} = $dcvars->{DOMAIN};
	$ret->{REALM} = $dcvars->{REALM};

	my $ctx;
	my $prefix_abs = abs_path($prefix);
	$ctx = {};
	$ctx->{krb5_conf} = "$prefix_abs/lib/krb5.conf";
	$ctx->{domain} = $dcvars->{DOMAIN};
	$ctx->{realm} = $dcvars->{REALM};
	$ctx->{dnsname} = lc($dcvars->{REALM});
	$ctx->{kdc_ipv4} = $dcvars->{SERVER_IP};
	Samba::mk_krb5_conf($ctx, "");

	$ret->{KRB5_CONFIG} = $ctx->{krb5_conf};

	my $net = Samba::bindir_path($self, "net");
	my $cmd = "";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "$net join $ret->{CONFIGURATION}";
	$cmd .= " -U$dcvars->{USERNAME}\%$dcvars->{PASSWORD}";

	if (system($cmd) != 0) {
	    warn("Join failed\n$cmd");
	    return undef;
	}

	# We need world access to this share, as otherwise the domain
	# administrator from the AD domain provided by Samba4 can't
	# access the share for tests.
	chmod 0777, "$prefix/share";

	if (not $self->check_or_start($ret, "yes", "yes", "yes")) {
		return undef;
	}

	$ret->{DC_SERVER} = $dcvars->{SERVER};
	$ret->{DC_SERVER_IP} = $dcvars->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $dcvars->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $dcvars->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $dcvars->{USERNAME};
	$ret->{DC_PASSWORD} = $dcvars->{PASSWORD};

	# Special case, this is called from Samba4.pm but needs to use the Samba3 check_env and get_log_env
	$ret->{target} = $self;

	return $ret;
}

sub setup_admember_rfc2307($$$$)
{
	my ($self, $prefix, $dcvars) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->have_ads()) {
	        return "UNKNOWN";
	}

	print "PROVISIONING S3 AD MEMBER WITH idmap_rfc2307 config...";

	my $member_options = "
	security = ads
	server signing = on
        workgroup = $dcvars->{DOMAIN}
        realm = $dcvars->{REALM}
        idmap config $dcvars->{DOMAIN} : backend = rfc2307
        idmap config $dcvars->{DOMAIN} : range = 2000000-2999999
        idmap config $dcvars->{DOMAIN} : ldap_server = ad
        idmap config $dcvars->{DOMAIN} : bind_path_user = ou=idmap,dc=samba,dc=example,dc=com
        idmap config $dcvars->{DOMAIN} : bind_path_group = ou=idmap,dc=samba,dc=example,dc=com
";

	my $ret = $self->provision($prefix,
				   "RFC2307MEMBER",
				   "loCalMemberPass",
				   $member_options);

	$ret or return undef;

	close(USERMAP);
	$ret->{DOMAIN} = $dcvars->{DOMAIN};
	$ret->{REALM} = $dcvars->{REALM};

	my $ctx;
	my $prefix_abs = abs_path($prefix);
	$ctx = {};
	$ctx->{krb5_conf} = "$prefix_abs/lib/krb5.conf";
	$ctx->{domain} = $dcvars->{DOMAIN};
	$ctx->{realm} = $dcvars->{REALM};
	$ctx->{dnsname} = lc($dcvars->{REALM});
	$ctx->{kdc_ipv4} = $dcvars->{SERVER_IP};
	Samba::mk_krb5_conf($ctx, "");

	$ret->{KRB5_CONFIG} = $ctx->{krb5_conf};

	my $net = Samba::bindir_path($self, "net");
	my $cmd = "";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "$net join $ret->{CONFIGURATION}";
	$cmd .= " -U$dcvars->{USERNAME}\%$dcvars->{PASSWORD}";

	if (system($cmd) != 0) {
	    warn("Join failed\n$cmd");
	    return undef;
	}

	# We need world access to this share, as otherwise the domain
	# administrator from the AD domain provided by Samba4 can't
	# access the share for tests.
	chmod 0777, "$prefix/share";

	if (not $self->check_or_start($ret, "yes", "yes", "yes")) {
		return undef;
	}

	$ret->{DC_SERVER} = $dcvars->{SERVER};
	$ret->{DC_SERVER_IP} = $dcvars->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $dcvars->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $dcvars->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $dcvars->{USERNAME};
	$ret->{DC_PASSWORD} = $dcvars->{PASSWORD};

	# Special case, this is called from Samba4.pm but needs to use the Samba3 check_env and get_log_env
	$ret->{target} = $self;

	return $ret;
}

sub setup_simpleserver($$)
{
	my ($self, $path) = @_;

	print "PROVISIONING server with security=share...";

	my $prefix_abs = abs_path($path);

	my $simpleserver_options = "
	lanman auth = yes
	vfs objects = xattr_tdb streams_depot

[vfs_aio_fork]
	path = $prefix_abs/share
        vfs objects = aio_fork
        read only = no
        vfs_aio_fork:erratic_testing_mode=yes
";

	my $vars = $self->provision($path,
				    "LOCALSHARE4",
				    "local4pass",
				    $simpleserver_options);

	$vars or return undef;

	if (not $self->check_or_start($vars, "yes", "no", "yes")) {
	       return undef;
	}

	$self->{vars}->{simpleserver} = $vars;

	return $vars;
}

sub setup_ktest($$$)
{
	my ($self, $prefix) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->have_ads()) {
	        return "UNKNOWN";
	}

	print "PROVISIONING server with security=ads...";

	my $ktest_options = "
        workgroup = KTEST
        realm = ktest.samba.example.com
	security = ads
        username map = $prefix/lib/username.map
        server signing = required
";

	my $ret = $self->provision($prefix,
				   "LOCALKTEST6",
				   "localktest6pass",
				   $ktest_options);

	$ret or return undef;

	my $ctx;
	my $prefix_abs = abs_path($prefix);
	$ctx = {};
	$ctx->{krb5_conf} = "$prefix_abs/lib/krb5.conf";
	$ctx->{domain} = "KTEST";
	$ctx->{realm} = "KTEST.SAMBA.EXAMPLE.COM";
	$ctx->{dnsname} = lc($ctx->{realm});
	$ctx->{kdc_ipv4} = "0.0.0.0";
	Samba::mk_krb5_conf($ctx, "");

	$ret->{KRB5_CONFIG} = $ctx->{krb5_conf};

	open(USERMAP, ">$prefix/lib/username.map") or die("Unable to open $prefix/lib/username.map");
	print USERMAP "
$ret->{USERNAME} = KTEST\\Administrator
";
	close(USERMAP);

#This is the secrets.tdb created by 'net ads join' from Samba3 to a
#Samba4 DC with the same parameters as are being used here.  The
#domain SID is S-1-5-21-1071277805-689288055-3486227160

	system("cp $self->{srcdir}/source3/selftest/ktest-secrets.tdb $prefix/private/secrets.tdb");
	chmod 0600, "$prefix/private/secrets.tdb";

#Make sure there's no old ntdb file.
	system("rm -f $prefix/private/secrets.ntdb");

#This uses a pre-calculated krb5 credentials cache, obtained by running Samba4 with:
# "--option=kdc:service ticket lifetime=239232" "--option=kdc:user ticket lifetime=239232" "--option=kdc:renewal lifetime=239232"
#
#and having in krb5.conf:
# ticket_lifetime = 799718400
# renew_lifetime = 799718400
#
# The commands for the -2 keytab where were:
# kinit administrator@KTEST.SAMBA.EXAMPLE.COM
# kvno host/localktest6@KTEST.SAMBA.EXAMPLE.COM
# kvno cifs/localktest6@KTEST.SAMBA.EXAMPLE.COM
# kvno host/LOCALKTEST6@KTEST.SAMBA.EXAMPLE.COM
# kvno cifs/LOCALKTEST6@KTEST.SAMBA.EXAMPLE.COM
#
# and then for the -3 keytab, I did
#
# net changetrustpw; kdestroy and the same again.
#
# This creates a credential cache with a very long lifetime (2036 at
# at 2011-04), and shows that running 'net changetrustpw' does not
# break existing logins (for the secrets.tdb method at least).
#

	$ret->{KRB5_CCACHE}="FILE:$prefix/krb5_ccache";

	system("cp $self->{srcdir}/source3/selftest/ktest-krb5_ccache-2 $prefix/krb5_ccache-2");
	chmod 0600, "$prefix/krb5_ccache-2";

	system("cp $self->{srcdir}/source3/selftest/ktest-krb5_ccache-3 $prefix/krb5_ccache-3");
	chmod 0600, "$prefix/krb5_ccache-3";

	# We need world access to this share, as otherwise the domain
	# administrator from the AD domain provided by ktest can't
	# access the share for tests.
	chmod 0777, "$prefix/share";

	if (not $self->check_or_start($ret, "yes", "no", "yes")) {
	       return undef;
	}
	return $ret;
}

sub setup_maptoguest($$)
{
	my ($self, $path) = @_;

	print "PROVISIONING maptoguest...";

	my $options = "
map to guest = bad user
";

	my $vars = $self->provision($path,
				    "maptoguest",
				    "maptoguestpass",
				    $options);

	$vars or return undef;

	if (not $self->check_or_start($vars, "yes", "no", "yes")) {
	       return undef;
	}

	$self->{vars}->{s3maptoguest} = $vars;

	return $vars;
}

sub stop_sig_term($$) {
	my ($self, $pid) = @_;
	kill("USR1", $pid) or kill("ALRM", $pid) or warn("Unable to kill $pid: $!");
}

sub stop_sig_kill($$) {
	my ($self, $pid) = @_;
	kill("ALRM", $pid) or warn("Unable to kill $pid: $!");
}

sub write_pid($$$)
{
	my ($env_vars, $app, $pid) = @_;

	open(PID, ">$env_vars->{PIDDIR}/timelimit.$app.pid");
	print PID $pid;
	close(PID);
}

sub read_pid($$)
{
	my ($env_vars, $app) = @_;

	open(PID, "<$env_vars->{PIDDIR}/timelimit.$app.pid");
	my $pid = <PID>;
	close(PID);
	return $pid;
}

sub check_or_start($$$$$) {
	my ($self, $env_vars, $nmbd, $winbindd, $smbd) = @_;

	# use a pipe for stdin in the child processes. This allows
	# those processes to monitor the pipe for EOF to ensure they
	# exit when the test script exits
	pipe(STDIN_READER, $env_vars->{STDIN_PIPE});

	unlink($env_vars->{NMBD_TEST_LOG});
	print "STARTING NMBD...";
	my $pid = fork();
	if ($pid == 0) {
		open STDOUT, ">$env_vars->{NMBD_TEST_LOG}";
		open STDERR, '>&STDOUT';

		SocketWrapper::set_default_iface($env_vars->{SOCKET_WRAPPER_DEFAULT_IFACE});

		$ENV{KRB5_CONFIG} = $env_vars->{KRB5_CONFIG};
		$ENV{SELFTEST_WINBINDD_SOCKET_DIR} = $env_vars->{SELFTEST_WINBINDD_SOCKET_DIR};
		$ENV{NMBD_SOCKET_DIR} = $env_vars->{NMBD_SOCKET_DIR};

		$ENV{NSS_WRAPPER_PASSWD} = $env_vars->{NSS_WRAPPER_PASSWD};
		$ENV{NSS_WRAPPER_GROUP} = $env_vars->{NSS_WRAPPER_GROUP};
		$ENV{NSS_WRAPPER_HOSTS} = $env_vars->{NSS_WRAPPER_HOSTS};
		$ENV{NSS_WRAPPER_MODULE_SO_PATH} = $env_vars->{NSS_WRAPPER_MODULE_SO_PATH};
		$ENV{NSS_WRAPPER_MODULE_FN_PREFIX} = $env_vars->{NSS_WRAPPER_MODULE_FN_PREFIX};

		$ENV{ENVNAME} = "$ENV{ENVNAME}.nmbd";

		if ($nmbd ne "yes") {
			$SIG{USR1} = $SIG{ALRM} = $SIG{INT} = $SIG{QUIT} = $SIG{TERM} = sub {
				my $signame = shift;
				print("Skip nmbd received signal $signame");
				exit 0;
			};
			sleep($self->{server_maxtime});
			exit 0;
		}

		$ENV{MAKE_TEST_BINARY} = Samba::bindir_path($self, "nmbd");
		my @optargs = ("-d0");
		if (defined($ENV{NMBD_OPTIONS})) {
			@optargs = split(/ /, $ENV{NMBD_OPTIONS});
		}
		my @preargs = (Samba::bindir_path($self, "timelimit"), $self->{server_maxtime});
		if(defined($ENV{NMBD_VALGRIND})) { 
			@preargs = split(/ /, $ENV{NMBD_VALGRIND});
		}
		my @args = ("-F", "--no-process-group",
			    "-s", $env_vars->{SERVERCONFFILE},
			    "-l", $env_vars->{LOGDIR});
		if (not defined($ENV{NMBD_DONT_LOG_STDOUT})) {
			push(@args, "--log-stdout");
		}

		close($env_vars->{STDIN_PIPE});
		open STDIN, ">&", \*STDIN_READER or die "can't dup STDIN_READER to STDIN: $!";

		exec(@preargs, $ENV{MAKE_TEST_BINARY}, @args, @optargs)
			or die("Unable to start $ENV{MAKE_TEST_BINARY}: $!");
	}
	$env_vars->{NMBD_TL_PID} = $pid;
	write_pid($env_vars, "nmbd", $pid);
	print "DONE\n";

	unlink($env_vars->{WINBINDD_TEST_LOG});
	print "STARTING WINBINDD...";
	$pid = fork();
	if ($pid == 0) {
		open STDOUT, ">$env_vars->{WINBINDD_TEST_LOG}";
		open STDERR, '>&STDOUT';

		SocketWrapper::set_default_iface($env_vars->{SOCKET_WRAPPER_DEFAULT_IFACE});

		$ENV{KRB5_CONFIG} = $env_vars->{KRB5_CONFIG};
		$ENV{SELFTEST_WINBINDD_SOCKET_DIR} = $env_vars->{SELFTEST_WINBINDD_SOCKET_DIR};
		$ENV{NMBD_SOCKET_DIR} = $env_vars->{NMBD_SOCKET_DIR};

		$ENV{NSS_WRAPPER_PASSWD} = $env_vars->{NSS_WRAPPER_PASSWD};
		$ENV{NSS_WRAPPER_GROUP} = $env_vars->{NSS_WRAPPER_GROUP};
		$ENV{NSS_WRAPPER_HOSTS} = $env_vars->{NSS_WRAPPER_HOSTS};
		$ENV{NSS_WRAPPER_MODULE_SO_PATH} = $env_vars->{NSS_WRAPPER_MODULE_SO_PATH};
		$ENV{NSS_WRAPPER_MODULE_FN_PREFIX} = $env_vars->{NSS_WRAPPER_MODULE_FN_PREFIX};

		$ENV{ENVNAME} = "$ENV{ENVNAME}.winbindd";

		if ($winbindd ne "yes") {
			$SIG{USR1} = $SIG{ALRM} = $SIG{INT} = $SIG{QUIT} = $SIG{TERM} = sub {
				my $signame = shift;
				print("Skip winbindd received signal $signame");
				exit 0;
			};
			sleep($self->{server_maxtime});
			exit 0;
		}

		$ENV{MAKE_TEST_BINARY} = Samba::bindir_path($self, "winbindd");
		my @optargs = ("-d0");
		if (defined($ENV{WINBINDD_OPTIONS})) {
			@optargs = split(/ /, $ENV{WINBINDD_OPTIONS});
		}
		my @preargs = (Samba::bindir_path($self, "timelimit"), $self->{server_maxtime});
		if(defined($ENV{WINBINDD_VALGRIND})) {
			@preargs = split(/ /, $ENV{WINBINDD_VALGRIND});
		}
		my @args = ("-F", "--no-process-group",
			    "-s", $env_vars->{SERVERCONFFILE},
			    "-l", $env_vars->{LOGDIR});
		if (not defined($ENV{WINBINDD_DONT_LOG_STDOUT})) {
			push(@args, "--stdout");
		}

		close($env_vars->{STDIN_PIPE});
		open STDIN, ">&", \*STDIN_READER or die "can't dup STDIN_READER to STDIN: $!";

		exec(@preargs, $ENV{MAKE_TEST_BINARY}, @args, @optargs)
			or die("Unable to start $ENV{MAKE_TEST_BINARY}: $!");
	}
	$env_vars->{WINBINDD_TL_PID} = $pid;
	write_pid($env_vars, "winbindd", $pid);
	print "DONE\n";

	unlink($env_vars->{SMBD_TEST_LOG});
	print "STARTING SMBD...";
	$pid = fork();
	if ($pid == 0) {
		open STDOUT, ">$env_vars->{SMBD_TEST_LOG}";
		open STDERR, '>&STDOUT';

		SocketWrapper::set_default_iface($env_vars->{SOCKET_WRAPPER_DEFAULT_IFACE});

		$ENV{KRB5_CONFIG} = $env_vars->{KRB5_CONFIG};
		$ENV{SELFTEST_WINBINDD_SOCKET_DIR} = $env_vars->{SELFTEST_WINBINDD_SOCKET_DIR};
		$ENV{NMBD_SOCKET_DIR} = $env_vars->{NMBD_SOCKET_DIR};

		$ENV{NSS_WRAPPER_PASSWD} = $env_vars->{NSS_WRAPPER_PASSWD};
		$ENV{NSS_WRAPPER_GROUP} = $env_vars->{NSS_WRAPPER_GROUP};
		$ENV{NSS_WRAPPER_HOSTS} = $env_vars->{NSS_WRAPPER_HOSTS};
		$ENV{NSS_WRAPPER_MODULE_SO_PATH} = $env_vars->{NSS_WRAPPER_MODULE_SO_PATH};
		$ENV{NSS_WRAPPER_MODULE_FN_PREFIX} = $env_vars->{NSS_WRAPPER_MODULE_FN_PREFIX};

		$ENV{ENVNAME} = "$ENV{ENVNAME}.smbd";

		if ($smbd ne "yes") {
			$SIG{USR1} = $SIG{ALRM} = $SIG{INT} = $SIG{QUIT} = $SIG{TERM} = sub {
				my $signame = shift;
				print("Skip smbd received signal $signame");
				exit 0;
			};
			sleep($self->{server_maxtime});
			exit 0;
		}

		$ENV{MAKE_TEST_BINARY} = Samba::bindir_path($self, "smbd");
		my @optargs = ("-d0");
		if (defined($ENV{SMBD_OPTIONS})) {
			@optargs = split(/ /, $ENV{SMBD_OPTIONS});
		}
		my @preargs = (Samba::bindir_path($self, "timelimit"), $self->{server_maxtime});
		if(defined($ENV{SMBD_VALGRIND})) {
			@preargs = split(/ /,$ENV{SMBD_VALGRIND});
		}
		my @args = ("-F", "--no-process-group",
			    "-s", $env_vars->{SERVERCONFFILE},
			    "-l", $env_vars->{LOGDIR});
		if (not defined($ENV{SMBD_DONT_LOG_STDOUT})) {
			push(@args, "--log-stdout");
		}

		close($env_vars->{STDIN_PIPE});
		open STDIN, ">&", \*STDIN_READER or die "can't dup STDIN_READER to STDIN: $!";

		exec(@preargs, $ENV{MAKE_TEST_BINARY}, @args, @optargs)
			or die("Unable to start $ENV{MAKE_TEST_BINARY}: $!");
	}
	$env_vars->{SMBD_TL_PID} = $pid;
	write_pid($env_vars, "smbd", $pid);
	print "DONE\n";

	close(STDIN_READER);

	return $self->wait_for_start($env_vars, $nmbd, $winbindd, $smbd);
}

sub provision($$$$$$)
{
	my ($self, $prefix, $server, $password, $extra_options, $no_delete_prefix) = @_;

	##
	## setup the various environment variables we need
	##

	my $swiface = Samba::get_interface($server);
	my %ret = ();
	my $server_ip = "127.0.0.$swiface";
	my $server_ipv6 = sprintf("fd00:0000:0000:0000:0000:0000:5357:5f%02x", $swiface);
	my $domain = "SAMBA-TEST";

	my $unix_name = ($ENV{USER} or $ENV{LOGNAME} or `PATH=/usr/ucb:$ENV{PATH} whoami`);
	chomp $unix_name;
	my $unix_uid = $>;
	my $unix_gids_str = $);
	my @unix_gids = split(" ", $unix_gids_str);

	my $prefix_abs = abs_path($prefix);
	my $bindir_abs = abs_path($self->{bindir});

	my $dns_host_file = "$ENV{SELFTEST_PREFIX}/dns_host_file";

	my @dirs = ();

	my $shrdir="$prefix_abs/share";
	push(@dirs,$shrdir);

	my $libdir="$prefix_abs/lib";
	push(@dirs,$libdir);

	my $piddir="$prefix_abs/pid";
	push(@dirs,$piddir);

	my $privatedir="$prefix_abs/private";
	push(@dirs,$privatedir);

	my $lockdir="$prefix_abs/lockdir";
	push(@dirs,$lockdir);

	my $eventlogdir="$prefix_abs/lockdir/eventlog";
	push(@dirs,$eventlogdir);

	my $logdir="$prefix_abs/logs";
	push(@dirs,$logdir);

	my $driver32dir="$shrdir/W32X86";
	push(@dirs,$driver32dir);

	my $driver64dir="$shrdir/x64";
	push(@dirs,$driver64dir);

	my $driver40dir="$shrdir/WIN40";
	push(@dirs,$driver40dir);

	my $ro_shrdir="$shrdir/root-tmp";
	push(@dirs,$ro_shrdir);

	my $msdfs_shrdir="$shrdir/msdfsshare";
	push(@dirs,$msdfs_shrdir);

	my $msdfs_deeppath="$msdfs_shrdir/deeppath";
	push(@dirs,$msdfs_deeppath);

	my $badnames_shrdir="$shrdir/badnames";
	push(@dirs,$badnames_shrdir);

	my $lease1_shrdir="$shrdir/SMB2_10";
	push(@dirs,$lease1_shrdir);

	my $lease2_shrdir="$shrdir/SMB3_00";
	push(@dirs,$lease2_shrdir);

	# this gets autocreated by winbindd
	my $wbsockdir="$prefix_abs/winbindd";
	my $wbsockprivdir="$lockdir/winbindd_privileged";

	my $nmbdsockdir="$prefix_abs/nmbd";
	unlink($nmbdsockdir);

	## 
	## create the test directory layout
	##
	die ("prefix_abs = ''") if $prefix_abs eq "";
	die ("prefix_abs = '/'") if $prefix_abs eq "/";

	mkdir($prefix_abs, 0777);
	print "CREATE TEST ENVIRONMENT IN '$prefix'...";
	if (not defined($no_delete_prefix) or not $no_delete_prefix) {
	    system("rm -rf $prefix_abs/*");
	}
	mkdir($_, 0777) foreach(@dirs);

	my $fs_specific_conf = $self->get_fs_specific_conf($shrdir);

	##
	## lockdir and piddir must be 0755
	##
	chmod 0755, $lockdir;
	chmod 0755, $piddir;


	##
	## create ro and msdfs share layout
	##

	chmod 0755, $ro_shrdir;
	my $unreadable_file = "$ro_shrdir/unreadable_file";
	unless (open(UNREADABLE_FILE, ">$unreadable_file")) {
	        warn("Unable to open $unreadable_file");
		return undef;
	}
	close(UNREADABLE_FILE);
	chmod 0600, $unreadable_file;

	my $msdfs_target = "$ro_shrdir/msdfs-target";
	unless (open(MSDFS_TARGET, ">$msdfs_target")) {
	        warn("Unable to open $msdfs_target");
		return undef;
	}
	close(MSDFS_TARGET);
	chmod 0666, $msdfs_target;
	symlink "msdfs:$server_ip\\ro-tmp", "$msdfs_shrdir/msdfs-src1";
	symlink "msdfs:$server_ipv6\\ro-tmp", "$msdfs_shrdir/deeppath/msdfs-src2";

	##
	## create bad names in $badnames_shrdir
	##
	## (An invalid name, would be mangled to 8.3).
        my $badname_target = "$badnames_shrdir/\340|\231\216\377\177";
        unless (open(BADNAME_TARGET, ">$badname_target")) {
                warn("Unable to open $badname_target");
                return undef;
        }
        close(BADNAME_TARGET);
        chmod 0666, $badname_target;

	## (A bad name, would not be mangled to 8.3).
        my $badname_target = "$badnames_shrdir/\240\276\346\327\377\177";
        unless (open(BADNAME_TARGET, ">$badname_target")) {
                warn("Unable to open $badname_target");
                return undef;
        }
        close(BADNAME_TARGET);
        chmod 0666, $badname_target;

	## (A bad good name).
        my $badname_target = "$badnames_shrdir/blank.txt";
        unless (open(BADNAME_TARGET, ">$badname_target")) {
                warn("Unable to open $badname_target");
                return undef;
        }
        close(BADNAME_TARGET);
        chmod 0666, $badname_target;

	my $conffile="$libdir/server.conf";

	my $nss_wrapper_pl = "$ENV{PERL} $self->{srcdir}/lib/nss_wrapper/nss_wrapper.pl";
	my $nss_wrapper_passwd = "$privatedir/passwd";
	my $nss_wrapper_group = "$privatedir/group";
	my $nss_wrapper_hosts = "$ENV{SELFTEST_PREFIX}/hosts";

	my $mod_printer_pl = "$ENV{PERL} $self->{srcdir}/source3/script/tests/printing/modprinter.pl";

	my @eventlog_list = ("dns server", "application");

	##
	## calculate uids and gids
	##

	my ($max_uid, $max_gid);
	my ($uid_nobody, $uid_root, $uid_pdbtest, $uid_pdbtest2);
	my ($gid_nobody, $gid_nogroup, $gid_root, $gid_domusers, $gid_domadmins);

	if ($unix_uid < 0xffff - 4) {
		$max_uid = 0xffff;
	} else {
		$max_uid = $unix_uid;
	}

	$uid_root = $max_uid - 1;
	$uid_nobody = $max_uid - 2;
	$uid_pdbtest = $max_uid - 3;
	$uid_pdbtest2 = $max_uid - 4;

	if ($unix_gids[0] < 0xffff - 5) {
		$max_gid = 0xffff;
	} else {
		$max_gid = $unix_gids[0];
	}

	$gid_nobody = $max_gid - 1;
	$gid_nogroup = $max_gid - 2;
	$gid_root = $max_gid - 3;
	$gid_domusers = $max_gid - 4;
	$gid_domadmins = $max_gid - 5;

	##
	## create conffile
	##

	unless (open(CONF, ">$conffile")) {
	        warn("Unable to open $conffile");
		return undef;
	}
	print CONF "
[global]
	netbios name = $server
	interfaces = $server_ip/8 $server_ipv6/64
	bind interfaces only = yes
	panic action = cd $self->{srcdir} && $self->{srcdir}/selftest/gdb_backtrace %d %\$(MAKE_TEST_BINARY)
	smbd:suicide mode = yes

	workgroup = $domain

	private dir = $privatedir
	pid directory = $piddir
	lock directory = $lockdir
	log file = $logdir/log.\%m
	log level = 1
	debug pid = yes
        max log size = 0

	state directory = $lockdir
	cache directory = $lockdir

	passdb backend = tdbsam

	time server = yes

	add user script =		$nss_wrapper_pl --passwd_path $nss_wrapper_passwd --type passwd --action add --name %u --gid $gid_nogroup
	add group script =		$nss_wrapper_pl --group_path  $nss_wrapper_group  --type group  --action add --name %g
	add machine script =		$nss_wrapper_pl --passwd_path $nss_wrapper_passwd --type passwd --action add --name %u --gid $gid_nogroup
	add user to group script =	$nss_wrapper_pl --passwd_path $nss_wrapper_passwd --type member --action add --member %u --name %g --group_path $nss_wrapper_group
	delete user script =		$nss_wrapper_pl --passwd_path $nss_wrapper_passwd --type passwd --action delete --name %u
	delete group script =		$nss_wrapper_pl --group_path  $nss_wrapper_group  --type group  --action delete --name %g
	delete user from group script = $nss_wrapper_pl --passwd_path $nss_wrapper_passwd --type member --action delete --member %u --name %g --group_path $nss_wrapper_group

	addprinter command =		$mod_printer_pl -a -s $conffile --
	deleteprinter command =		$mod_printer_pl -d -s $conffile --

	eventlog list = application \"dns server\"

	kernel oplocks = no
	kernel change notify = no
	smb2 leases = yes

	syslog = no
	printing = bsd
	printcap name = /dev/null

	winbindd socket directory = $wbsockdir
	nmbd:socket dir = $nmbdsockdir
	idmap config * : range = 100000-200000
	winbind enum users = yes
	winbind enum groups = yes
	winbind separator = /

#	min receivefile size = 4000

	read only = no
	server signing = auto

	smbd:sharedelay = 100000
	smbd:writetimeupdatedelay = 500000
	map hidden = no
	map system = no
	map readonly = no
	store dos attributes = yes
	create mask = 755
	dos filemode = yes
	strict rename = yes
	vfs objects = acl_xattr fake_acls xattr_tdb streams_depot

	printing = vlp
	print command = $bindir_abs/vlp tdbfile=$lockdir/vlp.tdb print %p %s
	lpq command = $bindir_abs/vlp tdbfile=$lockdir/vlp.tdb lpq %p
	lp rm command = $bindir_abs/vlp tdbfile=$lockdir/vlp.tdb lprm %p %j
	lp pause command = $bindir_abs/vlp tdbfile=$lockdir/vlp.tdb lppause %p %j
	lp resume command = $bindir_abs/vlp tdbfile=$lockdir/vlp.tdb lpresume %p %j
	queue pause command = $bindir_abs/vlp tdbfile=$lockdir/vlp.tdb queuepause %p
	queue resume command = $bindir_abs/vlp tdbfile=$lockdir/vlp.tdb queueresume %p
	lpq cache time = 0
	print notify backchannel = yes

	ncalrpc dir = $prefix_abs/ncalrpc
        resolv:host file = $dns_host_file

        # The samba3.blackbox.smbclient_s3 test uses this to test that
        # sending messages works, and that the %m sub works.
        message command = mv %s $shrdir/message.%m

	# Begin extra options
	$extra_options
	# End extra options

	#Include user defined custom parameters if set
";

	if (defined($ENV{INCLUDE_CUSTOM_CONF})) {
		print CONF "\t$ENV{INCLUDE_CUSTOM_CONF}\n";
	}

	print CONF "
[tmp]
	path = $shrdir
        comment = smb username is [%U]
[tmpsort]
	path = $shrdir
	comment = Load dirsort module
	vfs objects = dirsort acl_xattr fake_acls xattr_tdb streams_depot
[tmpenc]
	path = $shrdir
	comment = encrypt smb username is [%U]
	smb encrypt = required
	vfs objects = dirsort
[tmpguest]
	path = $shrdir
        guest ok = yes
[guestonly]
	path = $shrdir
        guest only = yes
        guest ok = yes
[forceuser]
	path = $shrdir
        force user = $unix_name
        guest ok = yes
[forceuser_unixonly]
	path = $shrdir
	force user = pdbtest
	guest ok = yes
[forcegroup]
	path = $shrdir
        force group = nogroup
        guest ok = yes
[ro-tmp]
	path = $ro_shrdir
	guest ok = yes
[write-list-tmp]
	path = $shrdir
        read only = yes
	write list = $unix_name
[valid-users-tmp]
	path = $shrdir
	valid users = $unix_name
[msdfs-share]
	path = $msdfs_shrdir
	msdfs root = yes
	guest ok = yes
[hideunread]
	copy = tmp
	hide unreadable = yes
[tmpcase]
	copy = tmp
	case sensitive = yes
[hideunwrite]
	copy = tmp
	hide unwriteable files = yes
[durable]
	copy = tmp
	kernel share modes = no
	kernel oplocks = no
	posix locking = no
[fs_specific]
	copy = tmp
	$fs_specific_conf
[print1]
	copy = tmp
	printable = yes

[print2]
	copy = print1
[print3]
	copy = print1
	default devmode = no
[lp]
	copy = print1

[nfs4acl_simple]
	path = $shrdir
	comment = smb username is [%U]
	nfs4:mode = simple
	vfs objects = nfs4acl_xattr xattr_tdb

[nfs4acl_special]
	path = $shrdir
	comment = smb username is [%U]
	nfs4:mode = special
	vfs objects = nfs4acl_xattr xattr_tdb

[xcopy_share]
	path = $shrdir
	comment = smb username is [%U]
	create mask = 777
	force create mode = 777
[posix_share]
	path = $shrdir
	comment = smb username is [%U]
	create mask = 0777
	force create mode = 0
	directory mask = 0777
	force directory mode = 0
	vfs objects = xattr_tdb
[aio]
	copy = tmp
	aio read size = 1
	aio write size = 1

[print\$]
	copy = tmp

[vfs_fruit]
	path = $shrdir
	vfs objects = catia fruit streams_xattr
	fruit:ressource = file
	fruit:metadata = netatalk
	fruit:locking = netatalk
	fruit:encoding = native

[badname-tmp]
	path = $badnames_shrdir
	guest ok = yes

[dynamic_share]
	path = $shrdir/%R
	guest ok = yes
	";
	close(CONF);

	##
	## create a test account
	##

	unless (open(PASSWD, ">$nss_wrapper_passwd")) {
           warn("Unable to open $nss_wrapper_passwd");
           return undef;
        } 
	print PASSWD "nobody:x:$uid_nobody:$gid_nobody:nobody gecos:$prefix_abs:/bin/false
$unix_name:x:$unix_uid:$unix_gids[0]:$unix_name gecos:$prefix_abs:/bin/false
pdbtest:x:$uid_pdbtest:$gid_nogroup:pdbtest gecos:$prefix_abs:/bin/false
pdbtest2:x:$uid_pdbtest2:$gid_nogroup:pdbtest gecos:$prefix_abs:/bin/false
";
	if ($unix_uid != 0) {
		print PASSWD "root:x:$uid_root:$gid_root:root gecos:$prefix_abs:/bin/false
";
	}
	close(PASSWD);

	unless (open(GROUP, ">$nss_wrapper_group")) {
             warn("Unable to open $nss_wrapper_group");
             return undef;
        }
	print GROUP "nobody:x:$gid_nobody:
nogroup:x:$gid_nogroup:nobody
$unix_name-group:x:$unix_gids[0]:
domusers:X:$gid_domusers:
domadmins:X:$gid_domadmins:
";
	if ($unix_gids[0] != 0) {
		print GROUP "root:x:$gid_root:
";
	}

	close(GROUP);

	## hosts
	my $hostname = lc($server);
	unless (open(HOSTS, ">>$nss_wrapper_hosts")) {
		warn("Unable to open $nss_wrapper_hosts");
		return undef;
	}
	print HOSTS "${server_ip} ${hostname}.samba.example.com ${hostname}\n";
	print HOSTS "${server_ipv6} ${hostname}.samba.example.com ${hostname}\n";
	close(HOSTS);


	foreach my $evlog (@eventlog_list) {
		my $evlogtdb = "$eventlogdir/$evlog.tdb";
		open(EVENTLOG, ">$evlogtdb") or die("Unable to open $evlogtdb");
		close(EVENTLOG);
	}

	$ENV{NSS_WRAPPER_PASSWD} = $nss_wrapper_passwd;
	$ENV{NSS_WRAPPER_GROUP} = $nss_wrapper_group;
	$ENV{NSS_WRAPPER_HOSTS} = $nss_wrapper_hosts;

        my $cmd = "UID_WRAPPER_ROOT=1 " . Samba::bindir_path($self, "smbpasswd")." -c $conffile -L -s -a $unix_name > /dev/null";
	unless (open(PWD, "|$cmd")) {
             warn("Unable to set password for test account\n$cmd");
             return undef;
        }
	print PWD "$password\n$password\n";
	unless (close(PWD)) {
             warn("Unable to set password for test account\n$cmd");
             return undef; 
        }
	print "DONE\n";

	open(DNS_UPDATE_LIST, ">$prefix/dns_update_list") or die("Unable to open $$prefix/dns_update_list");
	print DNS_UPDATE_LIST "A $server. $server_ip\n";
	print DNS_UPDATE_LIST "AAAA $server. $server_ipv6\n";
	close(DNS_UPDATE_LIST);

        if (system("$ENV{SRCDIR_ABS}/source4/scripting/bin/samba_dnsupdate --all-interfaces --use-file=$dns_host_file -s $conffile --update-list=$prefix/dns_update_list --update-cache=$prefix/dns_update_cache --no-substiutions --no-credentials") != 0) {
                die "Unable to update hostname into $dns_host_file";
        }

	$ret{SERVER_IP} = $server_ip;
	$ret{SERVER_IPV6} = $server_ipv6;
	$ret{NMBD_TEST_LOG} = "$prefix/nmbd_test.log";
	$ret{NMBD_TEST_LOG_POS} = 0;
	$ret{WINBINDD_TEST_LOG} = "$prefix/winbindd_test.log";
	$ret{WINBINDD_TEST_LOG_POS} = 0;
	$ret{SMBD_TEST_LOG} = "$prefix/smbd_test.log";
	$ret{SMBD_TEST_LOG_POS} = 0;
	$ret{SERVERCONFFILE} = $conffile;
	$ret{CONFIGURATION} ="-s $conffile";
	$ret{SERVER} = $server;
	$ret{USERNAME} = $unix_name;
	$ret{USERID} = $unix_uid;
	$ret{DOMAIN} = $domain;
	$ret{NETBIOSNAME} = $server;
	$ret{PASSWORD} = $password;
	$ret{PIDDIR} = $piddir;
	$ret{SELFTEST_WINBINDD_SOCKET_DIR} = $wbsockdir;
	$ret{WINBINDD_PRIV_PIPE_DIR} = $wbsockprivdir;
	$ret{NMBD_SOCKET_DIR} = $nmbdsockdir;
	$ret{SOCKET_WRAPPER_DEFAULT_IFACE} = $swiface;
	$ret{NSS_WRAPPER_PASSWD} = $nss_wrapper_passwd;
	$ret{NSS_WRAPPER_GROUP} = $nss_wrapper_group;
	$ret{NSS_WRAPPER_HOSTS} = $nss_wrapper_hosts;
	$ret{NSS_WRAPPER_MODULE_SO_PATH} = Samba::nss_wrapper_winbind_so_path($self);
	$ret{NSS_WRAPPER_MODULE_FN_PREFIX} = "winbind";
	$ret{LOCAL_PATH} = "$shrdir";
        $ret{LOGDIR} = $logdir;

	return \%ret;
}

sub wait_for_start($$$$$)
{
	my ($self, $envvars, $nmbd, $winbindd, $smbd) = @_;
	my $ret;

	if ($nmbd eq "yes") {
		my $count = 0;

		# give time for nbt server to register its names
		print "checking for nmbd\n";

		# This will return quickly when things are up, but be slow if we need to wait for (eg) SSL init
		my $nmblookup = Samba::bindir_path($self, "nmblookup");

		do {
			$ret = system("$nmblookup $envvars->{CONFIGURATION} $envvars->{SERVER}");
			if ($ret != 0) {
				sleep(1);
			} else {
				system("$nmblookup $envvars->{CONFIGURATION} -U $envvars->{SERVER_IP} __SAMBA__");
				system("$nmblookup $envvars->{CONFIGURATION} __SAMBA__");
				system("$nmblookup $envvars->{CONFIGURATION} -U 127.255.255.255 __SAMBA__");
				system("$nmblookup $envvars->{CONFIGURATION} -U $envvars->{SERVER_IP} $envvars->{SERVER}");
			}
			$count++;
		} while ($ret != 0 && $count < 10);
		if ($count == 10) {
			print "NMBD not reachable after 10 retries\n";
			teardown_env($self, $envvars);
			return 0;
		}
	}

	if ($winbindd eq "yes") {
	    print "checking for winbindd\n";
	    my $count = 0;
	    do {
		$ret = system("SELFTEST_WINBINDD_SOCKET_DIR=" . $envvars->{SELFTEST_WINBINDD_SOCKET_DIR} . " " . Samba::bindir_path($self, "wbinfo") . " --ping-dc");
		if ($ret != 0) {
		    sleep(2);
		}
		$count++;
	    } while ($ret != 0 && $count < 10);
	    if ($count == 10) {
		print "WINBINDD not reachable after 20 seconds\n";
		teardown_env($self, $envvars);
		return 0;
	    }
	}

	if ($smbd eq "yes") {
	    # make sure smbd is also up set
	    print "wait for smbd\n";

	    my $count = 0;
	    do {
		$ret = system(Samba::bindir_path($self, "smbclient3") ." $envvars->{CONFIGURATION} -L $envvars->{SERVER} -U% -p 139");
		if ($ret != 0) {
		    sleep(2);
		}
		$count++
	    } while ($ret != 0 && $count < 10);
	    if ($count == 10) {
		print "SMBD failed to start up in a reasonable time (20sec)\n";
		teardown_env($self, $envvars);
		return 0;
	    }
	}

	# Ensure we have domain users mapped.
	$ret = system(Samba::bindir_path($self, "net") ." $envvars->{CONFIGURATION} groupmap add rid=513 unixgroup=domusers type=domain");
	if ($ret != 0) {
	    return 1;
	}
	$ret = system(Samba::bindir_path($self, "net") ." $envvars->{CONFIGURATION} groupmap add rid=512 unixgroup=domadmins type=domain");
	if ($ret != 0) {
	    return 1;
	}

	if ($winbindd eq "yes") {
	    # note: creating builtin groups requires winbindd for the
	    # unix id allocator
	    $ret = system("SELFTEST_WINBINDD_SOCKET_DIR=" . $envvars->{SELFTEST_WINBINDD_SOCKET_DIR} . " " . Samba::bindir_path($self, "net") ." $envvars->{CONFIGURATION} sam createbuiltingroup Users");
	    if ($ret != 0) {
	        print "Failed to create BUILTIN\\Users group\n";
	        return 0;
	    }
	    my $count = 0;
	    do {
		system(Samba::bindir_path($self, "net") . " $envvars->{CONFIGURATION} cache flush");
		$ret = system("SELFTEST_WINBINDD_SOCKET_DIR=" . $envvars->{SELFTEST_WINBINDD_SOCKET_DIR} . " " . Samba::bindir_path($self, "wbinfo") . " --sid-to-gid=S-1-5-32-545");
		if ($ret != 0) {
		    sleep(2);
		}
		$count++;
	    } while ($ret != 0 && $count < 10);
	    if ($count == 10) {
		print "WINBINDD not reachable after 20 seconds\n";
		teardown_env($self, $envvars);
		return 0;
	    }
	}

	print $self->getlog_env($envvars);

	return 1;
}

1;
