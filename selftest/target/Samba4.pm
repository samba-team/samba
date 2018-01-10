#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

package Samba4;

use strict;
use Cwd qw(abs_path);
use FindBin qw($RealBin);
use POSIX;
use SocketWrapper;
use target::Samba;
use target::Samba3;

sub new($$$$$) {
	my ($classname, $bindir, $ldap, $srcdir, $server_maxtime) = @_;

	my $self = {
		vars => {},
		ldap => $ldap,
		bindir => $bindir,
		srcdir => $srcdir,
		server_maxtime => $server_maxtime,
		target3 => new Samba3($bindir, $srcdir, $server_maxtime)
	};
	bless $self;
	return $self;
}

sub scriptdir_path($$) {
	my ($self, $path) = @_;
	return "$self->{srcdir}/source4/scripting/$path";
}

sub openldap_start($$$) {
}

sub slapd_start($$)
{
	my $count = 0;
	my ($self, $env_vars, $STDIN_READER) = @_;
	my $ldbsearch = Samba::bindir_path($self, "ldbsearch");

	my $uri = $env_vars->{LDAP_URI};

	if (system("$ldbsearch -H $uri -s base -b \"\" supportedLDAPVersion > /dev/null") == 0) {
	    print "A SLAPD is still listening to $uri before we started the LDAP backend.  Aborting!";
	    return 1;
	}
	# running slapd in the background means it stays in the same process group, so it can be
	# killed by timelimit
	my $pid = fork();
	if ($pid == 0) {
		open STDOUT, ">$env_vars->{LDAPDIR}/logs";
		open STDERR, '>&STDOUT';
		close($env_vars->{STDIN_PIPE});
		open STDIN, ">&", $STDIN_READER or die "can't dup STDIN_READER to STDIN: $!";

		if ($self->{ldap} eq "fedora-ds") {
			exec("$ENV{FEDORA_DS_ROOT}/sbin/ns-slapd", "-D", $env_vars->{FEDORA_DS_DIR}, "-d0", "-i", $env_vars->{FEDORA_DS_PIDFILE});
		} elsif ($self->{ldap} eq "openldap") {
			exec($ENV{OPENLDAP_SLAPD}, "-dnone", "-F", $env_vars->{SLAPD_CONF_D}, "-h", $uri);
		}
		die("Unable to start slapd: $!");
	}
	$env_vars->{SLAPD_PID} = $pid;
	sleep(1);
	while (system("$ldbsearch -H $uri -s base -b \"\" supportedLDAPVersion > /dev/null") != 0) {
		$count++;
		if ($count > 40) {
			$self->slapd_stop($env_vars);
			return 0;
		}
		sleep(1);
	}
	return 1;
}

sub slapd_stop($$)
{
	my ($self, $envvars) = @_;
	kill 9, $envvars->{SLAPD_PID};
	return 1;
}

sub check_or_start($$$)
{
        my ($self, $env_vars, $process_model) = @_;
	my $STDIN_READER;

	my $env_ok = $self->check_env($env_vars);
	if ($env_ok) {
		return $env_vars->{SAMBA_PID};
	} elsif (defined($env_vars->{SAMBA_PID})) {
		warn("SAMBA PID $env_vars->{SAMBA_PID} is not running (died)");
		return undef;
	}

	# use a pipe for stdin in the child processes. This allows
	# those processes to monitor the pipe for EOF to ensure they
	# exit when the test script exits
	pipe($STDIN_READER, $env_vars->{STDIN_PIPE});

	# Start slapd before samba, but with the fifo on stdin
	if (defined($self->{ldap})) {
		unless($self->slapd_start($env_vars, $STDIN_READER)) {
			warn("couldn't start slapd (main run)");
			return undef;
		}
	}

	print "STARTING SAMBA...\n";
	my $pid = fork();
	if ($pid == 0) {
		# we want out from samba to go to the log file, but also
		# to the users terminal when running 'make test' on the command
		# line. This puts it on stderr on the terminal
		open STDOUT, "| tee $env_vars->{SAMBA_TEST_LOG} 1>&2";
		open STDERR, '>&STDOUT';

		SocketWrapper::set_default_iface($env_vars->{SOCKET_WRAPPER_DEFAULT_IFACE});

		$ENV{KRB5_CONFIG} = $env_vars->{KRB5_CONFIG};
		$ENV{KRB5CCNAME} = "$env_vars->{KRB5_CCACHE}.samba";
		if (defined($ENV{MITKRB5})) {
			$ENV{KRB5_KDC_PROFILE} = $env_vars->{MITKDC_CONFIG};
		}
		$ENV{SELFTEST_WINBINDD_SOCKET_DIR} = $env_vars->{SELFTEST_WINBINDD_SOCKET_DIR};
		$ENV{NMBD_SOCKET_DIR} = $env_vars->{NMBD_SOCKET_DIR};

		$ENV{NSS_WRAPPER_PASSWD} = $env_vars->{NSS_WRAPPER_PASSWD};
		$ENV{NSS_WRAPPER_GROUP} = $env_vars->{NSS_WRAPPER_GROUP};
		$ENV{NSS_WRAPPER_HOSTS} = $env_vars->{NSS_WRAPPER_HOSTS};
		$ENV{NSS_WRAPPER_HOSTNAME} = $env_vars->{NSS_WRAPPER_HOSTNAME};
		$ENV{NSS_WRAPPER_MODULE_SO_PATH} = $env_vars->{NSS_WRAPPER_MODULE_SO_PATH};
		$ENV{NSS_WRAPPER_MODULE_FN_PREFIX} = $env_vars->{NSS_WRAPPER_MODULE_FN_PREFIX};

		if (defined($env_vars->{RESOLV_WRAPPER_CONF})) {
			$ENV{RESOLV_WRAPPER_CONF} = $env_vars->{RESOLV_WRAPPER_CONF};
		} else {
			$ENV{RESOLV_WRAPPER_HOSTS} = $env_vars->{RESOLV_WRAPPER_HOSTS};
		}

		$ENV{UID_WRAPPER} = "1";
		$ENV{UID_WRAPPER_ROOT} = "1";

		$ENV{MAKE_TEST_BINARY} = Samba::bindir_path($self, "samba");
		my @preargs = ();
		my @optargs = ();
		if (defined($ENV{SAMBA_OPTIONS})) {
			@optargs = split(/ /, $ENV{SAMBA_OPTIONS});
		}
		if(defined($ENV{SAMBA_VALGRIND})) {
			@preargs = split(/ /,$ENV{SAMBA_VALGRIND});
		}

		close($env_vars->{STDIN_PIPE});
		open STDIN, ">&", $STDIN_READER or die "can't dup STDIN_READER to STDIN: $!";

		exec(@preargs, Samba::bindir_path($self, "samba"), "-M", $process_model, "-i", "--no-process-group", "--maximum-runtime=$self->{server_maxtime}", $env_vars->{CONFIGURATION}, @optargs) or die("Unable to start samba: $!");
	}
	$env_vars->{SAMBA_PID} = $pid;
	print "DONE ($pid)\n";

	close($STDIN_READER);

	if ($self->wait_for_start($env_vars) != 0) {
	    warn("Samba $pid failed to start up");
	    return undef;
	}

	return $pid;
}

sub wait_for_start($$)
{
	my ($self, $testenv_vars) = @_;
	my $count = 0;
	my $ret = 0;

	if (not $self->check_env($testenv_vars)) {
	    warn("unable to confirm Samba $testenv_vars->{SAMBA_PID} is running");
	    return -1;
	}

	# This will return quickly when things are up, but be slow if we
	# need to wait for (eg) SSL init
	my $nmblookup =  Samba::bindir_path($self, "nmblookup4");

	do {
		$ret = system("$nmblookup $testenv_vars->{CONFIGURATION} $testenv_vars->{SERVER}");
		if ($ret != 0) {
			sleep(1);
		} else {
			system("$nmblookup $testenv_vars->{CONFIGURATION} -U $testenv_vars->{SERVER_IP} $testenv_vars->{SERVER}");
			system("$nmblookup $testenv_vars->{CONFIGURATION} $testenv_vars->{NETBIOSNAME}");
			system("$nmblookup $testenv_vars->{CONFIGURATION} -U $testenv_vars->{SERVER_IP} $testenv_vars->{NETBIOSNAME}");
			system("$nmblookup $testenv_vars->{CONFIGURATION} $testenv_vars->{NETBIOSNAME}");
			system("$nmblookup $testenv_vars->{CONFIGURATION} -U $testenv_vars->{SERVER_IP} $testenv_vars->{NETBIOSNAME}");
			system("$nmblookup $testenv_vars->{CONFIGURATION} $testenv_vars->{SERVER}");
			system("$nmblookup $testenv_vars->{CONFIGURATION} -U $testenv_vars->{SERVER_IP} $testenv_vars->{SERVER}");
			system("$nmblookup $testenv_vars->{CONFIGURATION} $testenv_vars->{NETBIOSNAME}");
			system("$nmblookup $testenv_vars->{CONFIGURATION} -U $testenv_vars->{SERVER_IP} $testenv_vars->{NETBIOSNAME}");
			system("$nmblookup $testenv_vars->{CONFIGURATION} $testenv_vars->{NETBIOSNAME}");
			system("$nmblookup $testenv_vars->{CONFIGURATION} -U $testenv_vars->{SERVER_IP} $testenv_vars->{NETBIOSNAME}");
		}
		$count++;
	} while ($ret != 0 && $count < 20);
	if ($count == 20) {
		warn("nbt not reachable after 20 retries\n");
		teardown_env($self, $testenv_vars);
		return 0;
	}

	# Ensure we have the first RID Set before we start tests.  This makes the tests more reliable.
	if ($testenv_vars->{SERVER_ROLE} eq "domain controller") {
		print "waiting for working LDAP and a RID Set to be allocated\n";
		my $ldbsearch = Samba::bindir_path($self, "ldbsearch");
		my $count = 0;
		my $base_dn = "DC=".join(",DC=", split(/\./, $testenv_vars->{REALM}));

		my $search_dn = $base_dn;
		if ($testenv_vars->{NETBIOSNAME} ne "RODC") {
			# TODO currently no check for actual rIDAllocationPool
			$search_dn = "cn=RID Set,cn=$testenv_vars->{NETBIOSNAME},ou=domain controllers,$base_dn";
		}
		my $max_wait = 60;

		# Add hosts file for name lookups
		my $cmd = "NSS_WRAPPER_HOSTS='$testenv_vars->{NSS_WRAPPER_HOSTS}' ";
		if (defined($testenv_vars->{RESOLV_WRAPPER_CONF})) {
			$cmd .= "RESOLV_WRAPPER_CONF='$testenv_vars->{RESOLV_WRAPPER_CONF}' ";
		} else {
			$cmd .= "RESOLV_WRAPPER_HOSTS='$testenv_vars->{RESOLV_WRAPPER_HOSTS}' ";
		}

		$cmd .= "$ldbsearch ";
		$cmd .= "$testenv_vars->{CONFIGURATION} ";
		$cmd .= "-H ldap://$testenv_vars->{SERVER} ";
		$cmd .= "-U$testenv_vars->{USERNAME}%$testenv_vars->{PASSWORD} ";
		$cmd .= "-s base ";
		$cmd .= "-b '$search_dn' ";
		while (system("$cmd >/dev/null") != 0) {
			$count++;
			if ($count > $max_wait) {
				warn("Timed out ($max_wait sec) waiting for working LDAP and a RID Set to be allocated by $testenv_vars->{NETBIOSNAME} PID $testenv_vars->{SAMBA_PID}");
				$ret = -1;
				last;
			}
			sleep(1);
		}
	}

	my $wbinfo =  Samba::bindir_path($self, "wbinfo");

	$count = 0;
	do {
		my $cmd = "NSS_WRAPPER_PASSWD=$testenv_vars->{NSS_WRAPPER_PASSWD} ";
		$cmd .= "NSS_WRAPPER_GROUP=$testenv_vars->{NSS_WRAPPER_GROUP} ";
		$cmd .= "SELFTEST_WINBINDD_SOCKET_DIR=$testenv_vars->{SELFTEST_WINBINDD_SOCKET_DIR} ";
		$cmd .= "$wbinfo -p";
		$ret = system($cmd);

		if ($ret != 0) {
			sleep(1);
		}
		$count++;
	} while ($ret != 0 && $count < 20);
	if ($count == 20) {
		warn("winbind not reachable after 20 retries\n");
		teardown_env($self, $testenv_vars);
		return 0;
	}

	print $self->getlog_env($testenv_vars);

	return $ret
}

sub write_ldb_file($$$)
{
	my ($self, $file, $ldif) = @_;

	my $ldbadd =  Samba::bindir_path($self, "ldbadd");
	open(LDIF, "|$ldbadd -H $file >/dev/null");
	print LDIF $ldif;
	return(close(LDIF));
}

sub add_wins_config($$)
{
	my ($self, $privatedir) = @_;

	return $self->write_ldb_file("$privatedir/wins_config.ldb", "
dn: name=TORTURE_11,CN=PARTNERS
objectClass: wreplPartner
name: TORTURE_11
address: 127.0.0.11
pullInterval: 0
pushChangeCount: 0
type: 0x3
");
}

sub mk_fedora_ds($$)
{
	my ($self, $ctx) = @_;

	#Make the subdirectory be as fedora DS would expect
	my $fedora_ds_dir = "$ctx->{ldapdir}/slapd-$ctx->{ldap_instance}";

	my $pidfile = "$fedora_ds_dir/logs/slapd-$ctx->{ldap_instance}.pid";

	return ($fedora_ds_dir, $pidfile);
}

sub mk_openldap($$)
{
	my ($self, $ctx) = @_;

	my $slapd_conf_d = "$ctx->{ldapdir}/slapd.d";
	my $pidfile = "$ctx->{ldapdir}/slapd.pid";

	return ($slapd_conf_d, $pidfile);
}

sub setup_namespaces($$:$$)
{
	my ($self, $localenv, $upn_array, $spn_array) = @_;

	@{$upn_array} = [] unless defined($upn_array);
	my $upn_args = "";
	foreach my $upn (@{$upn_array}) {
		$upn_args .= " --add-upn-suffix=$upn";
	}

	@{$spn_array} = [] unless defined($spn_array);
	my $spn_args = "";
	foreach my $spn (@{$spn_array}) {
		$spn_args .= " --add-spn-suffix=$spn";
	}

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");

	my $cmd_env = "";
	$cmd_env .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$localenv->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($localenv->{RESOLV_WRAPPER_CONF})) {
		$cmd_env .= "RESOLV_WRAPPER_CONF=\"$localenv->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd_env .= "RESOLV_WRAPPER_HOSTS=\"$localenv->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	$cmd_env .= " KRB5_CONFIG=\"$localenv->{KRB5_CONFIG}\" ";
	$cmd_env .= "KRB5CCNAME=\"$localenv->{KRB5_CCACHE}\" ";

	my $cmd_config = " $localenv->{CONFIGURATION}";

	my $namespaces = $cmd_env;
	$namespaces .= " $samba_tool domain trust namespaces $upn_args $spn_args";
	$namespaces .= $cmd_config;
	unless (system($namespaces) == 0) {
		warn("Failed to add namespaces \n$namespaces");
		return;
	}

	return;
}

sub setup_trust($$$$$)
{
	my ($self, $localenv, $remoteenv, $type, $extra_args) = @_;

	$localenv->{TRUST_SERVER} = $remoteenv->{SERVER};
	$localenv->{TRUST_SERVER_IP} = $remoteenv->{SERVER_IP};
	$localenv->{TRUST_SERVER_IPV6} = $remoteenv->{SERVER_IPV6};
	$localenv->{TRUST_NETBIOSNAME} = $remoteenv->{NETBIOSNAME};
	$localenv->{TRUST_USERNAME} = $remoteenv->{USERNAME};
	$localenv->{TRUST_PASSWORD} = $remoteenv->{PASSWORD};
	$localenv->{TRUST_DOMAIN} = $remoteenv->{DOMAIN};
	$localenv->{TRUST_REALM} = $remoteenv->{REALM};

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");
	# setup the trust
	my $cmd_env = "";
	$cmd_env .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$localenv->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($localenv->{RESOLV_WRAPPER_CONF})) {
		$cmd_env .= "RESOLV_WRAPPER_CONF=\"$localenv->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd_env .= "RESOLV_WRAPPER_HOSTS=\"$localenv->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	$cmd_env .= " KRB5_CONFIG=\"$localenv->{KRB5_CONFIG}\" ";
	$cmd_env .= "KRB5CCNAME=\"$localenv->{KRB5_CCACHE}\" ";

	my $cmd_config = " $localenv->{CONFIGURATION}";
	my $cmd_creds = $cmd_config;
	$cmd_creds .= " -U$localenv->{TRUST_DOMAIN}\\\\$localenv->{TRUST_USERNAME}\%$localenv->{TRUST_PASSWORD}";

	my $create = $cmd_env;
	$create .= " $samba_tool domain trust create --type=${type} $localenv->{TRUST_REALM}";
	$create .= " $extra_args";
	$create .= $cmd_creds;
	unless (system($create) == 0) {
		warn("Failed to create trust \n$create");
		return undef;
	}

	return $localenv
}

sub provision_raw_prepare($$$$$$$$$$$)
{
	my ($self, $prefix, $server_role, $hostname,
	    $domain, $realm, $functional_level,
	    $password, $kdc_ipv4, $kdc_ipv6) = @_;
	my $ctx;
	my $netbiosname = uc($hostname);

	unless(-d $prefix or mkdir($prefix, 0777)) {
		warn("Unable to create $prefix");
		return undef;
	}
	my $prefix_abs = abs_path($prefix);

	die ("prefix=''") if $prefix_abs eq "";
	die ("prefix='/'") if $prefix_abs eq "/";

	unless (system("rm -rf $prefix_abs/*") == 0) {
		warn("Unable to clean up");
	}

	
	my $swiface = Samba::get_interface($hostname);

	$ctx->{prefix} = $prefix;
	$ctx->{prefix_abs} = $prefix_abs;

	$ctx->{server_role} = $server_role;
	$ctx->{hostname} = $hostname;
	$ctx->{netbiosname} = $netbiosname;
	$ctx->{swiface} = $swiface;
	$ctx->{password} = $password;
	$ctx->{kdc_ipv4} = $kdc_ipv4;
	$ctx->{kdc_ipv6} = $kdc_ipv6;
	$ctx->{krb5_ccname} = "$prefix_abs/krb5cc_%{uid}";
	if ($functional_level eq "2000") {
		$ctx->{supported_enctypes} = "arcfour-hmac-md5 des-cbc-md5 des-cbc-crc"
	}

#
# Set smbd log level here.
#
	$ctx->{server_loglevel} =$ENV{SERVER_LOG_LEVEL} || 1;
	$ctx->{username} = "Administrator";
	$ctx->{domain} = $domain;
	$ctx->{realm} = uc($realm);
	$ctx->{dnsname} = lc($realm);

	$ctx->{functional_level} = $functional_level;

	my $unix_name = ($ENV{USER} or $ENV{LOGNAME} or `whoami`);
	chomp $unix_name;
	$ctx->{unix_name} = $unix_name;
	$ctx->{unix_uid} = $>;
	my @mygid = split(" ", $();
	$ctx->{unix_gid} = $mygid[0];
	$ctx->{unix_gids_str} = $);
	@{$ctx->{unix_gids}} = split(" ", $ctx->{unix_gids_str});

	$ctx->{etcdir} = "$prefix_abs/etc";
	$ctx->{piddir} = "$prefix_abs/pid";
	$ctx->{smb_conf} = "$ctx->{etcdir}/smb.conf";
	$ctx->{krb5_conf} = "$ctx->{etcdir}/krb5.conf";
	$ctx->{krb5_ccache} = "$prefix_abs/krb5_ccache";
	$ctx->{mitkdc_conf} = "$ctx->{etcdir}/mitkdc.conf";
	$ctx->{privatedir} = "$prefix_abs/private";
	$ctx->{binddnsdir} = "$prefix_abs/bind-dns";
	$ctx->{ncalrpcdir} = "$prefix_abs/ncalrpc";
	$ctx->{lockdir} = "$prefix_abs/lockdir";
	$ctx->{logdir} = "$prefix_abs/logs";
	$ctx->{statedir} = "$prefix_abs/statedir";
	$ctx->{cachedir} = "$prefix_abs/cachedir";
	$ctx->{winbindd_socket_dir} = "$prefix_abs/winbindd_socket";
	$ctx->{ntp_signd_socket_dir} = "$prefix_abs/ntp_signd_socket";
	$ctx->{nsswrap_passwd} = "$ctx->{etcdir}/passwd";
	$ctx->{nsswrap_group} = "$ctx->{etcdir}/group";
	$ctx->{nsswrap_hosts} = "$ENV{SELFTEST_PREFIX}/hosts";
	$ctx->{nsswrap_hostname} = "$ctx->{hostname}.$ctx->{dnsname}";
	if ($ENV{SAMBA_DNS_FAKING}) {
		$ctx->{dns_host_file} = "$ENV{SELFTEST_PREFIX}/dns_host_file";
		$ctx->{samba_dnsupdate} = "$ENV{SRCDIR_ABS}/source4/scripting/bin/samba_dnsupdate -s $ctx->{smb_conf} --all-interfaces --use-file=$ctx->{dns_host_file}";
	} else {
	        $ctx->{samba_dnsupdate} = "$ENV{SRCDIR_ABS}/source4/scripting/bin/samba_dnsupdate -s $ctx->{smb_conf} --all-interfaces";
		$ctx->{use_resolv_wrapper} = 1;
	}
	$ctx->{resolv_conf} = "$ctx->{etcdir}/resolv.conf";

	$ctx->{tlsdir} = "$ctx->{privatedir}/tls";

	$ctx->{ipv4} = "127.0.0.$swiface";
	$ctx->{ipv6} = sprintf("fd00:0000:0000:0000:0000:0000:5357:5f%02x", $swiface);
	$ctx->{interfaces} = "$ctx->{ipv4}/8 $ctx->{ipv6}/64";

	push(@{$ctx->{directories}}, $ctx->{privatedir});
	push(@{$ctx->{directories}}, $ctx->{binddnsdir});
	push(@{$ctx->{directories}}, $ctx->{etcdir});
	push(@{$ctx->{directories}}, $ctx->{piddir});
	push(@{$ctx->{directories}}, $ctx->{lockdir});
	push(@{$ctx->{directories}}, $ctx->{logdir});
	push(@{$ctx->{directories}}, $ctx->{statedir});
	push(@{$ctx->{directories}}, $ctx->{cachedir});

	$ctx->{smb_conf_extra_options} = "";

	my @provision_options = ();
	push (@provision_options, "KRB5_CONFIG=\"$ctx->{krb5_conf}\"");
	push (@provision_options, "KRB5_CCACHE=\"$ctx->{krb5_ccache}\"");
	push (@provision_options, "NSS_WRAPPER_PASSWD=\"$ctx->{nsswrap_passwd}\"");
	push (@provision_options, "NSS_WRAPPER_GROUP=\"$ctx->{nsswrap_group}\"");
	push (@provision_options, "NSS_WRAPPER_HOSTS=\"$ctx->{nsswrap_hosts}\"");
	push (@provision_options, "NSS_WRAPPER_HOSTNAME=\"$ctx->{nsswrap_hostname}\"");
	if (defined($ctx->{use_resolv_wrapper})) {
		push (@provision_options, "RESOLV_WRAPPER_CONF=\"$ctx->{resolv_conf}\"");
	} else {
		push (@provision_options, "RESOLV_WRAPPER_HOSTS=\"$ctx->{dns_host_file}\"");
	}
	if (defined($ENV{GDB_PROVISION})) {
		push (@provision_options, "gdb --args");
		if (!defined($ENV{PYTHON})) {
		    push (@provision_options, "env");
		    push (@provision_options, "python");
		}
	}
	if (defined($ENV{VALGRIND_PROVISION})) {
		push (@provision_options, "valgrind");
		if (!defined($ENV{PYTHON})) {
		    push (@provision_options, "env");
		    push (@provision_options, "python");
		}
	}
	if (defined($ENV{PYTHON})) {
		push (@provision_options, $ENV{PYTHON});
	}
	push (@provision_options, Samba::bindir_path($self, "samba-tool"));
	push (@provision_options, "domain");
	push (@provision_options, "provision");
	push (@provision_options, "--configfile=$ctx->{smb_conf}");
	push (@provision_options, "--host-name=$ctx->{hostname}");
	push (@provision_options, "--host-ip=$ctx->{ipv4}");
	push (@provision_options, "--quiet");
	push (@provision_options, "--domain=$ctx->{domain}");
	push (@provision_options, "--realm=$ctx->{realm}");
	push (@provision_options, "--adminpass=$ctx->{password}");
	push (@provision_options, "--krbtgtpass=krbtgt$ctx->{password}");
	push (@provision_options, "--machinepass=machine$ctx->{password}");
	push (@provision_options, "--root=$ctx->{unix_name}");
	push (@provision_options, "--server-role=\"$ctx->{server_role}\"");
	push (@provision_options, "--function-level=\"$ctx->{functional_level}\"");

	@{$ctx->{provision_options}} = @provision_options;

	return $ctx;
}

#
# Step1 creates the basic configuration
#
sub provision_raw_step1($$)
{
	my ($self, $ctx) = @_;

	mkdir($_, 0777) foreach (@{$ctx->{directories}});

	##
	## lockdir and piddir must be 0755
	##
	chmod 0755, $ctx->{lockdir};
	chmod 0755, $ctx->{piddir};

	unless (open(CONFFILE, ">$ctx->{smb_conf}")) {
		warn("can't open $ctx->{smb_conf}$?");
		return undef;
	}

	Samba::prepare_keyblobs($ctx);
	my $crlfile = "$ctx->{tlsdir}/crl.pem";
	$crlfile = "" unless -e ${crlfile};

	print CONFFILE "
[global]
	netbios name = $ctx->{netbiosname}
	posix:eadb = $ctx->{statedir}/eadb.tdb
	workgroup = $ctx->{domain}
	realm = $ctx->{realm}
	private dir = $ctx->{privatedir}
	binddns dir = $ctx->{binddnsdir}
	pid directory = $ctx->{piddir}
	ncalrpc dir = $ctx->{ncalrpcdir}
	lock dir = $ctx->{lockdir}
	state directory = $ctx->{statedir}
	cache directory = $ctx->{cachedir}
	winbindd socket directory = $ctx->{winbindd_socket_dir}
	ntp signd socket directory = $ctx->{ntp_signd_socket_dir}
	winbind separator = /
	interfaces = $ctx->{interfaces}
	tls dh params file = $ctx->{tlsdir}/dhparms.pem
	tls crlfile = ${crlfile}
	tls verify peer = no_check
	panic action = $RealBin/gdb_backtrace \%d
	wins support = yes
	server role = $ctx->{server_role}
	server services = +echo +smb -s3fs
        dcerpc endpoint servers = +winreg +srvsvc
	notify:inotify = false
	ldb:nosync = true
	ldap server require strong auth = yes
#We don't want to pass our self-tests if the PAC code is wrong
	gensec:require_pac = true
	log file = $ctx->{logdir}/log.\%m
	log level = $ctx->{server_loglevel}
	lanman auth = Yes
	ntlm auth = Yes
	rndc command = true
	dns update command = $ctx->{samba_dnsupdate}
	spn update command = $ENV{SRCDIR_ABS}/source4/scripting/bin/samba_spnupdate -s $ctx->{smb_conf}
	gpo update command = $ENV{SRCDIR_ABS}/source4/scripting/bin/samba_gpoupdate -s $ctx->{smb_conf} -H $ctx->{privatedir}/sam.ldb --machine
	dreplsrv:periodic_startup_interval = 0
	dsdb:schema update allowed = yes

        prefork children = 4

        vfs objects = dfs_samba4 acl_xattr fake_acls xattr_tdb streams_depot

        idmap_ldb:use rfc2307=yes
	winbind enum users = yes
	winbind enum groups = yes

        rpc server port:netlogon = 1026

";

	print CONFFILE "

	# Begin extra options
	$ctx->{smb_conf_extra_options}
	# End extra options
";
	close(CONFFILE);

        #Default the KDC IP to the server's IP
	if (not defined($ctx->{kdc_ipv4})) {
		$ctx->{kdc_ipv4} = $ctx->{ipv4};
	}
	if (not defined($ctx->{kdc_ipv6})) {
		$ctx->{kdc_ipv6} = $ctx->{ipv6};
	}

	Samba::mk_krb5_conf($ctx);
	Samba::mk_mitkdc_conf($ctx, abs_path(Samba::bindir_path($self, "shared")));

	open(PWD, ">$ctx->{nsswrap_passwd}");
	if ($ctx->{unix_uid} != 0) {
		print PWD "root:x:0:0:root gecos:$ctx->{prefix_abs}:/bin/false\n";
	}
	print PWD "$ctx->{unix_name}:x:$ctx->{unix_uid}:65531:$ctx->{unix_name} gecos:$ctx->{prefix_abs}:/bin/false\n";
	print PWD "nobody:x:65534:65533:nobody gecos:$ctx->{prefix_abs}:/bin/false
pdbtest:x:65533:65533:pdbtest gecos:$ctx->{prefix_abs}:/bin/false
pdbtest2:x:65532:65533:pdbtest gecos:$ctx->{prefix_abs}:/bin/false
pdbtest3:x:65531:65533:pdbtest gecos:$ctx->{prefix_abs}:/bin/false
pdbtest4:x:65530:65533:pdbtest gecos:$ctx->{prefix_abs}:/bin/false
";
	close(PWD);
        my $uid_rfc2307test = 65533;

	open(GRP, ">$ctx->{nsswrap_group}");
	if ($ctx->{unix_gid} != 0) {
		print GRP "root:x:0:\n";
	}
	print GRP "$ctx->{unix_name}:x:$ctx->{unix_gid}:\n";
	print GRP "wheel:x:10:
users:x:65531:
nobody:x:65533:
nogroup:x:65534:nobody
";
	close(GRP);
        my $gid_rfc2307test = 65532;

	my $hostname = lc($ctx->{hostname});
	open(HOSTS, ">>$ctx->{nsswrap_hosts}");
	if ($hostname eq "localdc") {
		print HOSTS "$ctx->{ipv4} ${hostname}.$ctx->{dnsname} $ctx->{dnsname} ${hostname}\n";
		print HOSTS "$ctx->{ipv6} ${hostname}.$ctx->{dnsname} $ctx->{dnsname} ${hostname}\n";
	} else {
		print HOSTS "$ctx->{ipv4} ${hostname}.$ctx->{dnsname} ${hostname}\n";
		print HOSTS "$ctx->{ipv6} ${hostname}.$ctx->{dnsname} ${hostname}\n";
	}
	close(HOSTS);

	if (defined($ctx->{resolv_conf})) {
		open(RESOLV_CONF, ">$ctx->{resolv_conf}");
		print RESOLV_CONF "nameserver $ctx->{kdc_ipv4}\n";
		print RESOLV_CONF "nameserver $ctx->{kdc_ipv6}\n";
		close(RESOLV_CONF);
	}

	my $configuration = "--configfile=$ctx->{smb_conf}";

#Ensure the config file is valid before we start
	my $testparm = Samba::bindir_path($self, "samba-tool") . " testparm";
	if (system("$testparm $configuration -v --suppress-prompt >/dev/null 2>&1") != 0) {
		system("$testparm -v --suppress-prompt $configuration >&2");
		warn("Failed to create a valid smb.conf configuration $testparm!");
		return undef;
	}
	unless (system("($testparm $configuration -v --suppress-prompt --parameter-name=\"netbios name\" --section-name=global 2> /dev/null | grep -i \"^$ctx->{netbiosname}\" ) >/dev/null 2>&1") == 0) {
		warn("Failed to create a valid smb.conf configuration! $testparm $configuration -v --suppress-prompt --parameter-name=\"netbios name\" --section-name=global");
		return undef;
	}

	my $ret = {
		KRB5_CONFIG => $ctx->{krb5_conf},
		KRB5_CCACHE => $ctx->{krb5_ccache},
		MITKDC_CONFIG => $ctx->{mitkdc_conf},
		PIDDIR => $ctx->{piddir},
		SERVER => $ctx->{hostname},
		SERVER_IP => $ctx->{ipv4},
		SERVER_IPV6 => $ctx->{ipv6},
		NETBIOSNAME => $ctx->{netbiosname},
		DOMAIN => $ctx->{domain},
		USERNAME => $ctx->{username},
		REALM => $ctx->{realm},
		PASSWORD => $ctx->{password},
		LDAPDIR => $ctx->{ldapdir},
		LDAP_INSTANCE => $ctx->{ldap_instance},
		SELFTEST_WINBINDD_SOCKET_DIR => $ctx->{winbindd_socket_dir},
		NCALRPCDIR => $ctx->{ncalrpcdir},
		LOCKDIR => $ctx->{lockdir},
		STATEDIR => $ctx->{statedir},
		CACHEDIR => $ctx->{cachedir},
		PRIVATEDIR => $ctx->{privatedir},
		BINDDNSDIR => $ctx->{binddnsdir},
		SERVERCONFFILE => $ctx->{smb_conf},
		CONFIGURATION => $configuration,
		SOCKET_WRAPPER_DEFAULT_IFACE => $ctx->{swiface},
		NSS_WRAPPER_PASSWD => $ctx->{nsswrap_passwd},
		NSS_WRAPPER_GROUP => $ctx->{nsswrap_group},
		NSS_WRAPPER_HOSTS => $ctx->{nsswrap_hosts},
		NSS_WRAPPER_HOSTNAME => $ctx->{nsswrap_hostname},
		SAMBA_TEST_FIFO => "$ctx->{prefix}/samba_test.fifo",
		SAMBA_TEST_LOG => "$ctx->{prefix}/samba_test.log",
		SAMBA_TEST_LOG_POS => 0,
		NSS_WRAPPER_MODULE_SO_PATH => Samba::nss_wrapper_winbind_so_path($self),
		NSS_WRAPPER_MODULE_FN_PREFIX => "winbind",
                LOCAL_PATH => $ctx->{share},
                UID_RFC2307TEST => $uid_rfc2307test,
                GID_RFC2307TEST => $gid_rfc2307test,
                SERVER_ROLE => $ctx->{server_role},
	        RESOLV_CONF => $ctx->{resolv_conf}
	};

	if (defined($ctx->{use_resolv_wrapper})) {
	        $ret->{RESOLV_WRAPPER_CONF} = $ctx->{resolv_conf};
	} else {
		$ret->{RESOLV_WRAPPER_HOSTS} = $ctx->{dns_host_file};
	}

	return $ret;
}

#
# Step2 runs the provision script
#
sub provision_raw_step2($$$)
{
	my ($self, $ctx, $ret) = @_;

	my $provision_cmd = join(" ", @{$ctx->{provision_options}});
	unless (system($provision_cmd) == 0) {
		warn("Unable to provision: \n$provision_cmd\n");
		return undef;
	}

	my $testallowed_account = "testallowed";
	my $samba_tool_cmd = "";
	$samba_tool_cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$samba_tool_cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
	    . " user create --configfile=$ctx->{smb_conf} $testallowed_account $ctx->{password}";
	unless (system($samba_tool_cmd) == 0) {
		warn("Unable to add testallowed user: \n$samba_tool_cmd\n");
		return undef;
	}

	my $ldbmodify = "";
	$ldbmodify .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$ldbmodify .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$ldbmodify .= Samba::bindir_path($self, "ldbmodify");
	my $base_dn = "DC=".join(",DC=", split(/\./, $ctx->{realm}));

	if ($ctx->{server_role} ne "domain controller") {
		$base_dn = "DC=$ctx->{netbiosname}";
	}

	my $user_dn = "cn=$testallowed_account,cn=users,$base_dn";
	$testallowed_account = "testallowed account";
	open(LDIF, "|$ldbmodify -H $ctx->{privatedir}/sam.ldb");
	print LDIF "dn: $user_dn
changetype: modify
replace: samAccountName
samAccountName: $testallowed_account
-
";
	close(LDIF);

	open(LDIF, "|$ldbmodify -H $ctx->{privatedir}/sam.ldb");
	print LDIF "dn: $user_dn
changetype: modify
replace: userPrincipalName
userPrincipalName: testallowed upn\@$ctx->{realm}
replace: servicePrincipalName
servicePrincipalName: host/testallowed
-	    
";
	close(LDIF);

	$samba_tool_cmd = "";
	$samba_tool_cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$samba_tool_cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
	    . " user create --configfile=$ctx->{smb_conf} testdenied $ctx->{password}";
	unless (system($samba_tool_cmd) == 0) {
		warn("Unable to add testdenied user: \n$samba_tool_cmd\n");
		return undef;
	}

	my $user_dn = "cn=testdenied,cn=users,$base_dn";
	open(LDIF, "|$ldbmodify -H $ctx->{privatedir}/sam.ldb");
	print LDIF "dn: $user_dn
changetype: modify
replace: userPrincipalName
userPrincipalName: testdenied_upn\@$ctx->{realm}.upn
-	    
";
	close(LDIF);

	$samba_tool_cmd = "";
	$samba_tool_cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$samba_tool_cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
	    . " group addmembers --configfile=$ctx->{smb_conf} 'Allowed RODC Password Replication Group' '$testallowed_account'";
	unless (system($samba_tool_cmd) == 0) {
		warn("Unable to add '$testallowed_account' user to 'Allowed RODC Password Replication Group': \n$samba_tool_cmd\n");
		return undef;
	}

	# Create to users alice and bob!
	my $user_account_array = ["alice", "bob"];

	foreach my $user_account (@{$user_account_array}) {
		my $samba_tool_cmd = "";

		$samba_tool_cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
		$samba_tool_cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
		$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
		    . " user create --configfile=$ctx->{smb_conf} $user_account Secret007";
		unless (system($samba_tool_cmd) == 0) {
			warn("Unable to create user: $user_account\n$samba_tool_cmd\n");
			return undef;
		}
	}

	return $ret;
}

sub provision($$$$$$$$$$)
{
	my ($self, $prefix, $server_role, $hostname,
	    $domain, $realm, $functional_level,
	    $password, $kdc_ipv4, $kdc_ipv6, $extra_smbconf_options, $extra_smbconf_shares,
	    $extra_provision_options) = @_;

	my $ctx = $self->provision_raw_prepare($prefix, $server_role,
					       $hostname,
					       $domain, $realm, $functional_level,
					       $password, $kdc_ipv4, $kdc_ipv6);

	if (defined($extra_provision_options)) {
		push (@{$ctx->{provision_options}}, @{$extra_provision_options});
	} else {
		push (@{$ctx->{provision_options}}, "--use-ntvfs");
	}

	$ctx->{share} = "$ctx->{prefix_abs}/share";
	push(@{$ctx->{directories}}, "$ctx->{share}");
	push(@{$ctx->{directories}}, "$ctx->{share}/test1");
	push(@{$ctx->{directories}}, "$ctx->{share}/test2");

	# precreate directories for printer drivers
	push(@{$ctx->{directories}}, "$ctx->{share}/W32X86");
	push(@{$ctx->{directories}}, "$ctx->{share}/x64");
	push(@{$ctx->{directories}}, "$ctx->{share}/WIN40");

	my $msdfs = "no";
	$msdfs = "yes" if ($server_role eq "domain controller");
	$ctx->{smb_conf_extra_options} = "

	max xmit = 32K
	server max protocol = SMB2
	host msdfs = $msdfs
	lanman auth = yes

	# fruit:copyfile is a global option
	fruit:copyfile = yes

	$extra_smbconf_options

[tmp]
	path = $ctx->{share}
	read only = no
	posix:sharedelay = 100000
	posix:oplocktimeout = 3
	posix:writetimeupdatedelay = 500000

[xcopy_share]
	path = $ctx->{share}
	read only = no
	posix:sharedelay = 100000
	posix:oplocktimeout = 3
	posix:writetimeupdatedelay = 500000
	create mask = 777
	force create mode = 777

[posix_share]
	path = $ctx->{share}
	read only = no
	create mask = 0777
	force create mode = 0
	directory mask = 0777
	force directory mode = 0

[test1]
	path = $ctx->{share}/test1
	read only = no
	posix:sharedelay = 100000
	posix:oplocktimeout = 3
	posix:writetimeupdatedelay = 500000

[test2]
	path = $ctx->{share}/test2
	read only = no
	posix:sharedelay = 100000
	posix:oplocktimeout = 3
	posix:writetimeupdatedelay = 500000

[cifs]
	path = $ctx->{share}/_ignore_cifs_
	read only = no
	ntvfs handler = cifs
	cifs:server = $ctx->{netbiosname}
	cifs:share = tmp
	cifs:use-s4u2proxy = yes
	# There is no username specified here, instead the client is expected
	# to log in with kerberos, and the serverwill use delegated credentials.
	# Or the server tries s4u2self/s4u2proxy to impersonate the client

[simple]
	path = $ctx->{share}
	read only = no
	ntvfs handler = simple

[sysvol]
	path = $ctx->{statedir}/sysvol
	read only = no

[netlogon]
	path = $ctx->{statedir}/sysvol/$ctx->{dnsname}/scripts
	read only = no

[cifsposix]
	copy = simple
	ntvfs handler = cifsposix

[vfs_fruit]
	path = $ctx->{share}
	vfs objects = catia fruit streams_xattr acl_xattr
	ea support = yes
	fruit:resource = file
	fruit:metadata = netatalk
	fruit:locking = netatalk
	fruit:encoding = native

$extra_smbconf_shares
";

	if (defined($self->{ldap})) {
		$ctx->{ldapdir} = "$ctx->{privatedir}/ldap";
		push(@{$ctx->{directories}}, "$ctx->{ldapdir}");

		my $ldap_uri= "$ctx->{ldapdir}/ldapi";
		$ldap_uri =~ s|/|%2F|g;
		$ldap_uri = "ldapi://$ldap_uri";
		$ctx->{ldap_uri} = $ldap_uri;

		$ctx->{ldap_instance} = lc($ctx->{netbiosname});
	}

	my $ret = $self->provision_raw_step1($ctx);
	unless (defined $ret) {
		return undef;
	}

	if (defined($self->{ldap})) {
		$ret->{LDAP_URI} = $ctx->{ldap_uri};
		push (@{$ctx->{provision_options}}, "--ldap-backend-type=" . $self->{ldap});
		push (@{$ctx->{provision_options}}, "--ldap-backend-nosync");
		if ($self->{ldap} eq "openldap") {
			push (@{$ctx->{provision_options}}, "--slapd-path=" . $ENV{OPENLDAP_SLAPD});
			($ret->{SLAPD_CONF_D}, $ret->{OPENLDAP_PIDFILE}) = $self->mk_openldap($ctx) or die("Unable to create openldap directories");

                } elsif ($self->{ldap} eq "fedora-ds") {
 		        push (@{$ctx->{provision_options}}, "--slapd-path=" . "$ENV{FEDORA_DS_ROOT}/sbin/ns-slapd");
 		        push (@{$ctx->{provision_options}}, "--setup-ds-path=" . "$ENV{FEDORA_DS_ROOT}/sbin/setup-ds.pl");
			($ret->{FEDORA_DS_DIR}, $ret->{FEDORA_DS_PIDFILE}) = $self->mk_fedora_ds($ctx) or die("Unable to create fedora ds directories");
		}

	}

	return $self->provision_raw_step2($ctx, $ret);
}

sub provision_s4member($$$$$)
{
	my ($self, $prefix, $dcvars, $hostname, $more_conf) = @_;
	print "PROVISIONING MEMBER...\n";
	my $extra_smb_conf = "
        passdb backend = samba_dsdb
winbindd:use external pipes = true

# the source4 smb server doesn't allow signing by default
server signing = enabled
raw NTLMv2 auth = yes

rpc_server:default = external
rpc_server:svcctl = embedded
rpc_server:srvsvc = embedded
rpc_server:eventlog = embedded
rpc_server:ntsvcs = embedded
rpc_server:winreg = embedded
rpc_server:spoolss = embedded
rpc_daemon:spoolssd = embedded
rpc_server:tcpip = no
";
	if ($more_conf) {
		$extra_smb_conf = $extra_smb_conf . $more_conf . "\n";
	}
	my $ret = $self->provision($prefix,
				   "member server",
				   $hostname,
				   "SAMBADOMAIN",
				   "samba.example.com",
				   "2008",
				   "locMEMpass3",
				   $dcvars->{SERVER_IP},
				   $dcvars->{SERVER_IPV6},
				   $extra_smb_conf, "", undef);
	unless ($ret) {
		return undef;
	}

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");
	my $cmd = "";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($ret->{RESOLV_WRAPPER_CONF})) {
		$cmd .= "RESOLV_WRAPPER_CONF=\"$ret->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd .= "RESOLV_WRAPPER_HOSTS=\"$ret->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$cmd .= "$samba_tool domain join $ret->{CONFIGURATION} $dcvars->{REALM} member";
	$cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD}";
	$cmd .= " --machinepass=machine$ret->{PASSWORD}";

	unless (system($cmd) == 0) {
		warn("Join failed\n$cmd");
		return undef;
	}

	$ret->{MEMBER_SERVER} = $ret->{SERVER};
	$ret->{MEMBER_SERVER_IP} = $ret->{SERVER_IP};
	$ret->{MEMBER_SERVER_IPV6} = $ret->{SERVER_IPV6};
	$ret->{MEMBER_NETBIOSNAME} = $ret->{NETBIOSNAME};
	$ret->{MEMBER_USERNAME} = $ret->{USERNAME};
	$ret->{MEMBER_PASSWORD} = $ret->{PASSWORD};

	$ret->{DC_SERVER} = $dcvars->{DC_SERVER};
	$ret->{DC_SERVER_IP} = $dcvars->{DC_SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $dcvars->{DC_SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $dcvars->{DC_NETBIOSNAME};
	$ret->{DC_USERNAME} = $dcvars->{DC_USERNAME};
	$ret->{DC_PASSWORD} = $dcvars->{DC_PASSWORD};

	return $ret;
}

sub provision_rpc_proxy($$$)
{
	my ($self, $prefix, $dcvars) = @_;
	print "PROVISIONING RPC PROXY...\n";

	my $extra_smbconf_options = "
        passdb backend = samba_dsdb

	# rpc_proxy
	dcerpc_remote:binding = ncacn_ip_tcp:$dcvars->{SERVER}
	dcerpc endpoint servers = epmapper, remote
	dcerpc_remote:interfaces = rpcecho

[cifs_to_dc]
	path = /tmp/_ignore_cifs_to_dc_/_none_
	read only = no
	ntvfs handler = cifs
	cifs:server = $dcvars->{SERVER}
	cifs:share = cifs
	cifs:use-s4u2proxy = yes
	# There is no username specified here, instead the client is expected
	# to log in with kerberos, and the serverwill use delegated credentials.
	# Or the server tries s4u2self/s4u2proxy to impersonate the client

";

	my $ret = $self->provision($prefix,
				   "member server",
				   "localrpcproxy",
				   "SAMBADOMAIN",
				   "samba.example.com",
				   "2008",
				   "locRPCproxypass4",
				   $dcvars->{SERVER_IP},
				   $dcvars->{SERVER_IPV6},
				   $extra_smbconf_options, "", undef);
	unless ($ret) {
		return undef;
	}

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");

	# The joind runs in the context of the rpc_proxy/member for now
	my $cmd = "";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($ret->{RESOLV_WRAPPER_CONF})) {
		$cmd .= "RESOLV_WRAPPER_CONF=\"$ret->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd .= "RESOLV_WRAPPER_HOSTS=\"$ret->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$cmd .= "$samba_tool domain join $ret->{CONFIGURATION} $dcvars->{REALM} member";
	$cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD}";
	$cmd .= " --machinepass=machine$ret->{PASSWORD}";

	unless (system($cmd) == 0) {
		warn("Join failed\n$cmd");
		return undef;
	}

	# Setting up delegation runs in the context of the DC for now
	$cmd = "";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$dcvars->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	$cmd .= "KRB5_CONFIG=\"$dcvars->{KRB5_CONFIG}\" ";
	$cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$cmd .= "$samba_tool delegation for-any-protocol '$ret->{NETBIOSNAME}\$' on";
        $cmd .= " $dcvars->{CONFIGURATION}";
        print $cmd;

	unless (system($cmd) == 0) {
		warn("Delegation failed\n$cmd");
		return undef;
	}

	# Setting up delegation runs in the context of the DC for now
	$cmd = "";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$dcvars->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	$cmd .= "KRB5_CONFIG=\"$dcvars->{KRB5_CONFIG}\" ";
	$cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$cmd .= "$samba_tool delegation add-service '$ret->{NETBIOSNAME}\$' cifs/$dcvars->{SERVER}";
        $cmd .= " $dcvars->{CONFIGURATION}";

	unless (system($cmd) == 0) {
		warn("Delegation failed\n$cmd");
		return undef;
	}

	$ret->{RPC_PROXY_SERVER} = $ret->{SERVER};
	$ret->{RPC_PROXY_SERVER_IP} = $ret->{SERVER_IP};
	$ret->{RPC_PROXY_SERVER_IPV6} = $ret->{SERVER_IPV6};
	$ret->{RPC_PROXY_NETBIOSNAME} = $ret->{NETBIOSNAME};
	$ret->{RPC_PROXY_USERNAME} = $ret->{USERNAME};
	$ret->{RPC_PROXY_PASSWORD} = $ret->{PASSWORD};

	$ret->{DC_SERVER} = $dcvars->{DC_SERVER};
	$ret->{DC_SERVER_IP} = $dcvars->{DC_SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $dcvars->{DC_SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $dcvars->{DC_NETBIOSNAME};
	$ret->{DC_USERNAME} = $dcvars->{DC_USERNAME};
	$ret->{DC_PASSWORD} = $dcvars->{DC_PASSWORD};

	return $ret;
}

sub provision_promoted_dc($$$)
{
	my ($self, $prefix, $dcvars) = @_;
	print "PROVISIONING PROMOTED DC...\n";

	# We do this so that we don't run the provision.  That's the job of 'samba-tool domain dcpromo'.
	my $ctx = $self->provision_raw_prepare($prefix, "domain controller",
					       "promotedvdc",
					       "SAMBADOMAIN",
					       "samba.example.com",
					       "2008",
					       $dcvars->{PASSWORD},
					       $dcvars->{SERVER_IP},
					       $dcvars->{SERVER_IPV6});

	push (@{$ctx->{provision_options}}, "--use-ntvfs");

	$ctx->{smb_conf_extra_options} = "
	max xmit = 32K
	server max protocol = SMB2

        ntlm auth = ntlmv2-only

[sysvol]
	path = $ctx->{statedir}/sysvol
	read only = yes

[netlogon]
	path = $ctx->{statedir}/sysvol/$ctx->{dnsname}/scripts
	read only = no

";

	my $ret = $self->provision_raw_step1($ctx);
	unless ($ret) {
		return undef;
	}

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");
	my $cmd = "";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($ret->{RESOLV_WRAPPER_CONF})) {
		$cmd .= "RESOLV_WRAPPER_CONF=\"$ret->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd .= "RESOLV_WRAPPER_HOSTS=\"$ret->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$cmd .= "$samba_tool domain join $ret->{CONFIGURATION} $dcvars->{REALM} MEMBER --realm=$dcvars->{REALM}";
	$cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD}";
	$cmd .= " --machinepass=machine$ret->{PASSWORD}";

	unless (system($cmd) == 0) {
		warn("Join failed\n$cmd");
		return undef;
	}

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");
	my $cmd = "";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$cmd .= "$samba_tool domain dcpromo $ret->{CONFIGURATION} $dcvars->{REALM} DC --realm=$dcvars->{REALM}";
	$cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD}";
	$cmd .= " --machinepass=machine$ret->{PASSWORD} --use-ntvfs --dns-backend=BIND9_DLZ";

	unless (system($cmd) == 0) {
		warn("Join failed\n$cmd");
		return undef;
	}

	$ret->{PROMOTED_DC_SERVER} = $ret->{SERVER};
	$ret->{PROMOTED_DC_SERVER_IP} = $ret->{SERVER_IP};
	$ret->{PROMOTED_DC_SERVER_IPV6} = $ret->{SERVER_IPV6};
	$ret->{PROMOTED_DC_NETBIOSNAME} = $ret->{NETBIOSNAME};

	$ret->{DC_SERVER} = $dcvars->{DC_SERVER};
	$ret->{DC_SERVER_IP} = $dcvars->{DC_SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $dcvars->{DC_SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $dcvars->{DC_NETBIOSNAME};
	$ret->{DC_USERNAME} = $dcvars->{DC_USERNAME};
	$ret->{DC_PASSWORD} = $dcvars->{DC_PASSWORD};

	return $ret;
}

sub provision_vampire_dc($$$)
{
	my ($self, $prefix, $dcvars, $fl) = @_;
	print "PROVISIONING VAMPIRE DC @ FL $fl...\n";
	my $name = "localvampiredc";
	my $extra_conf = "";

	if ($fl == "2000") {
		$name = "vampire2000dc";
	} else {
		$extra_conf = "drs: immediate link sync = yes
                       drs: max link sync = 250";
	}

	# We do this so that we don't run the provision.  That's the job of 'net vampire'.
	my $ctx = $self->provision_raw_prepare($prefix, "domain controller",
					       $name,
					       $dcvars->{DOMAIN},
					       $dcvars->{REALM},
					       $fl,
					       $dcvars->{PASSWORD},
					       $dcvars->{SERVER_IP},
					       $dcvars->{SERVER_IPV6});

	push (@{$ctx->{provision_options}}, "--use-ntvfs");

	$ctx->{smb_conf_extra_options} = "
	max xmit = 32K
	server max protocol = SMB2

        ntlm auth = mschapv2-and-ntlmv2-only
	$extra_conf

[sysvol]
	path = $ctx->{statedir}/sysvol
	read only = yes

[netlogon]
	path = $ctx->{statedir}/sysvol/$ctx->{dnsname}/scripts
	read only = no

";

	my $ret = $self->provision_raw_step1($ctx);
	unless ($ret) {
		return undef;
	}

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");
	my $cmd = "";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($ret->{RESOLV_WRAPPER_CONF})) {
		$cmd .= "RESOLV_WRAPPER_CONF=\"$ret->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd .= "RESOLV_WRAPPER_HOSTS=\"$ret->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$cmd .= "$samba_tool domain join $ret->{CONFIGURATION} $dcvars->{REALM} DC --realm=$dcvars->{REALM}";
	$cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD} --domain-critical-only";
	$cmd .= " --machinepass=machine$ret->{PASSWORD} --use-ntvfs";

	unless (system($cmd) == 0) {
		warn("Join failed\n$cmd");
		return undef;
	}

        if ($fl == "2000") {
		$ret->{VAMPIRE_2000_DC_SERVER} = $ret->{SERVER};
		$ret->{VAMPIRE_2000_DC_SERVER_IP} = $ret->{SERVER_IP};
		$ret->{VAMPIRE_2000_DC_SERVER_IPV6} = $ret->{SERVER_IPV6};
		$ret->{VAMPIRE_2000_DC_NETBIOSNAME} = $ret->{NETBIOSNAME};
        } else {
		$ret->{VAMPIRE_DC_SERVER} = $ret->{SERVER};
		$ret->{VAMPIRE_DC_SERVER_IP} = $ret->{SERVER_IP};
		$ret->{VAMPIRE_DC_SERVER_IPV6} = $ret->{SERVER_IPV6};
		$ret->{VAMPIRE_DC_NETBIOSNAME} = $ret->{NETBIOSNAME};
        }
	$ret->{DC_SERVER} = $dcvars->{DC_SERVER};
	$ret->{DC_SERVER_IP} = $dcvars->{DC_SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $dcvars->{DC_SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $dcvars->{DC_NETBIOSNAME};
	$ret->{DC_USERNAME} = $dcvars->{DC_USERNAME};
	$ret->{DC_PASSWORD} = $dcvars->{DC_PASSWORD};
	$ret->{DC_REALM} = $dcvars->{DC_REALM};

	return $ret;
}

sub provision_subdom_dc($$$)
{
	my ($self, $prefix, $dcvars) = @_;
	print "PROVISIONING SUBDOMAIN DC...\n";

	# We do this so that we don't run the provision.  That's the job of 'net vampire'.
	my $ctx = $self->provision_raw_prepare($prefix, "domain controller",
					       "localsubdc",
					       "SAMBASUBDOM",
					       "sub.samba.example.com",
					       "2008",
					       $dcvars->{PASSWORD},
					       undef);

	push (@{$ctx->{provision_options}}, "--use-ntvfs");

	$ctx->{smb_conf_extra_options} = "
	max xmit = 32K
	server max protocol = SMB2

[sysvol]
	path = $ctx->{statedir}/sysvol
	read only = yes

[netlogon]
	path = $ctx->{statedir}/sysvol/$ctx->{dnsname}/scripts
	read only = no

";

	my $ret = $self->provision_raw_step1($ctx);
	unless ($ret) {
		return undef;
	}

	Samba::mk_krb5_conf($ctx);
	Samba::mk_mitkdc_conf($ctx, abs_path(Samba::bindir_path($self, "shared")));

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");
	my $cmd = "";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($ret->{RESOLV_WRAPPER_CONF})) {
		$cmd .= "RESOLV_WRAPPER_CONF=\"$ret->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd .= "RESOLV_WRAPPER_HOSTS=\"$ret->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$cmd .= "$samba_tool domain join $ret->{CONFIGURATION} $ctx->{dnsname} subdomain ";
	$cmd .= "--parent-domain=$dcvars->{REALM} -U$dcvars->{DC_USERNAME}\@$dcvars->{REALM}\%$dcvars->{DC_PASSWORD}";
	$cmd .= " --machinepass=machine$ret->{PASSWORD} --use-ntvfs";
	$cmd .= " --adminpass=$ret->{PASSWORD}";

	unless (system($cmd) == 0) {
		warn("Join failed\n$cmd");
		return undef;
	}

	$ret->{SUBDOM_DC_SERVER} = $ret->{SERVER};
	$ret->{SUBDOM_DC_SERVER_IP} = $ret->{SERVER_IP};
	$ret->{SUBDOM_DC_SERVER_IPV6} = $ret->{SERVER_IPV6};
	$ret->{SUBDOM_DC_NETBIOSNAME} = $ret->{NETBIOSNAME};

	$ret->{DC_SERVER} = $dcvars->{DC_SERVER};
	$ret->{DC_SERVER_IP} = $dcvars->{DC_SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $dcvars->{DC_SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $dcvars->{DC_NETBIOSNAME};
	$ret->{DC_USERNAME} = $dcvars->{DC_USERNAME};
	$ret->{DC_PASSWORD} = $dcvars->{DC_PASSWORD};

	return $ret;
}

sub provision_ad_dc_ntvfs($$)
{
	my ($self, $prefix) = @_;

	# We keep the old 'winbind' name here in server services to
	# ensure upgrades which used that name still work with the now
	# alias.

	print "PROVISIONING AD DC (NTVFS)...\n";
        my $extra_conf_options = "netbios aliases = localDC1-a
        server services = +winbind -winbindd
	ldap server require strong auth = allow_sasl_over_tls
	allow nt4 crypto = yes
	raw NTLMv2 auth = yes
	lsa over netlogon = yes
        rpc server port = 1027
        auth event notification = true
	server schannel = auto
	";
	my $ret = $self->provision($prefix,
				   "domain controller",
				   "localdc",
				   "SAMBADOMAIN",
				   "samba.example.com",
				   "2008",
				   "locDCpass1",
				   undef,
				   undef,
				   $extra_conf_options,
				   "",
				   undef);
	unless ($ret) {
		return undef;
	}

	unless($self->add_wins_config("$prefix/private")) {
		warn("Unable to add wins configuration");
		return undef;
	}
	$ret->{NETBIOSALIAS} = "localdc1-a";
	$ret->{DC_SERVER} = $ret->{SERVER};
	$ret->{DC_SERVER_IP} = $ret->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $ret->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $ret->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $ret->{USERNAME};
	$ret->{DC_PASSWORD} = $ret->{PASSWORD};
	$ret->{DC_REALM} = $ret->{REALM};

	return $ret;
}

sub provision_fl2000dc($$)
{
	my ($self, $prefix) = @_;

	print "PROVISIONING DC WITH FOREST LEVEL 2000...\n";
	my $extra_conf_options = "
	spnego:simulate_w2k=yes
	ntlmssp_server:force_old_spnego=yes
";
	my $extra_provision_options = undef;
	# This environment uses plain text secrets
	# i.e. secret attributes are not encrypted on disk.
	# This allows testing of the --plaintext-secrets option for
	# provision
	push (@{$extra_provision_options}, "--plaintext-secrets");
	my $ret = $self->provision($prefix,
				   "domain controller",
				   "dc5",
				   "SAMBA2000",
				   "samba2000.example.com",
				   "2000",
				   "locDCpass5",
				   undef,
				   undef,
				   $extra_conf_options,
				   "",
				   $extra_provision_options);
	unless ($ret) {
		return undef;
	}

	unless($self->add_wins_config("$prefix/private")) {
		warn("Unable to add wins configuration");
		return undef;
	}
	$ret->{DC_SERVER} = $ret->{SERVER};
	$ret->{DC_SERVER_IP} = $ret->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $ret->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $ret->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $ret->{USERNAME};
	$ret->{DC_PASSWORD} = $ret->{PASSWORD};
	$ret->{DC_REALM} = $ret->{REALM};

	return $ret;
}

sub provision_fl2003dc($$$)
{
	my ($self, $prefix, $dcvars) = @_;
	my $swiface1 = Samba::get_interface("fakednsforwarder1");
	my $swiface2 = Samba::get_interface("fakednsforwarder2");

	print "PROVISIONING DC WITH FOREST LEVEL 2003...\n";
	my $extra_conf_options = "allow dns updates = nonsecure and secure
	dcesrv:header signing = no
	dns forwarder = 127.0.0.$swiface1 127.0.0.$swiface2";
	my $ret = $self->provision($prefix,
				   "domain controller",
				   "dc6",
				   "SAMBA2003",
				   "samba2003.example.com",
				   "2003",
				   "locDCpass6",
				   undef,
				   undef,
				   $extra_conf_options,
				   "",
				   undef);
	unless (defined $ret) {
		return undef;
	}

	$ret->{DC_SERVER} = $ret->{SERVER};
	$ret->{DC_SERVER_IP} = $ret->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $ret->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $ret->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $ret->{USERNAME};
	$ret->{DC_PASSWORD} = $ret->{PASSWORD};
	$ret->{DNS_FORWARDER1} = "127.0.0.$swiface1";
	$ret->{DNS_FORWARDER2} = "127.0.0.$swiface2";

	my @samba_tool_options;
	push (@samba_tool_options, Samba::bindir_path($self, "samba-tool"));
	push (@samba_tool_options, "domain");
	push (@samba_tool_options, "passwordsettings");
	push (@samba_tool_options, "set");
	push (@samba_tool_options, "--configfile=$ret->{SERVERCONFFILE}");
	push (@samba_tool_options, "--min-pwd-age=0");
	push (@samba_tool_options, "--history-length=1");

	my $samba_tool_cmd = join(" ", @samba_tool_options);

	unless (system($samba_tool_cmd) == 0) {
		warn("Unable to set min password age to 0: \n$samba_tool_cmd\n");
		return undef;
	}

	unless($self->add_wins_config("$prefix/private")) {
		warn("Unable to add wins configuration");
		return undef;
	}

	return $ret;
}

sub provision_fl2008r2dc($$$)
{
	my ($self, $prefix, $dcvars) = @_;

	print "PROVISIONING DC WITH FOREST LEVEL 2008r2...\n";
        my $extra_conf_options = "ldap server require strong auth = no";
	my $ret = $self->provision($prefix,
				   "domain controller",
				   "dc7",
				   "SAMBA2008R2",
				   "samba2008R2.example.com",
				   "2008_R2",
				   "locDCpass7",
				   undef,
				   undef,
				   $extra_conf_options,
				   "",
				   undef);
	unless (defined $ret) {
		return undef;
	}

	unless ($self->add_wins_config("$prefix/private")) {
		warn("Unable to add wins configuration");
		return undef;
	}
	$ret->{DC_SERVER} = $ret->{SERVER};
	$ret->{DC_SERVER_IP} = $ret->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $ret->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $ret->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $ret->{USERNAME};
	$ret->{DC_PASSWORD} = $ret->{PASSWORD};
	$ret->{DC_REALM} = $ret->{REALM};

	return $ret;
}


sub provision_rodc($$$)
{
	my ($self, $prefix, $dcvars) = @_;
	print "PROVISIONING RODC...\n";

	# We do this so that we don't run the provision.  That's the job of 'net join RODC'.
	my $ctx = $self->provision_raw_prepare($prefix, "domain controller",
					       "rodc",
					       "SAMBADOMAIN",
					       "samba.example.com",
					       "2008",
					       $dcvars->{PASSWORD},
					       $dcvars->{SERVER_IP},
					       $dcvars->{SERVER_IPV6});
	unless ($ctx) {
		return undef;
	}

	push (@{$ctx->{provision_options}}, "--use-ntvfs");

	$ctx->{share} = "$ctx->{prefix_abs}/share";
	push(@{$ctx->{directories}}, "$ctx->{share}");

	$ctx->{smb_conf_extra_options} = "
	max xmit = 32K
	server max protocol = SMB2
	password server = $dcvars->{DC_SERVER}

[sysvol]
	path = $ctx->{statedir}/sysvol
	read only = yes

[netlogon]
	path = $ctx->{statedir}/sysvol/$ctx->{dnsname}/scripts
	read only = yes

[tmp]
	path = $ctx->{share}
	read only = no
	posix:sharedelay = 10000
	posix:oplocktimeout = 3
	posix:writetimeupdatedelay = 50000

";

	my $ret = $self->provision_raw_step1($ctx);
	unless ($ret) {
		return undef;
	}

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");
	my $cmd = "";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($ret->{RESOLV_WRAPPER_CONF})) {
		$cmd .= "RESOLV_WRAPPER_CONF=\"$ret->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd .= "RESOLV_WRAPPER_HOSTS=\"$ret->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$cmd .= "$samba_tool domain join $ret->{CONFIGURATION} $dcvars->{REALM} RODC";
	$cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD}";
	$cmd .= " --server=$dcvars->{DC_SERVER} --use-ntvfs";

	unless (system($cmd) == 0) {
		warn("RODC join failed\n$cmd");
		return undef;
	}

        # This ensures deterministic behaviour for tests that want to have the 'testallowed account'
        # user password verified on the RODC
	my $testallowed_account = "testallowed account";
	$cmd = "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "KRB5CCNAME=\"$ret->{KRB5_CCACHE}\" ";
	$cmd .= "$samba_tool rodc preload '$testallowed_account' $ret->{CONFIGURATION}";
	$cmd .= " --server=$dcvars->{DC_SERVER}";

	unless (system($cmd) == 0) {
		warn("RODC join failed\n$cmd");
		return undef;
	}

	# we overwrite the kdc after the RODC join
	# so that use the RODC as kdc and test
	# the proxy code
	$ctx->{kdc_ipv4} = $ret->{SERVER_IP};
	$ctx->{kdc_ipv6} = $ret->{SERVER_IPV6};
	Samba::mk_krb5_conf($ctx);
	Samba::mk_mitkdc_conf($ctx, abs_path(Samba::bindir_path($self, "shared")));

	$ret->{RODC_DC_SERVER} = $ret->{SERVER};
	$ret->{RODC_DC_SERVER_IP} = $ret->{SERVER_IP};
	$ret->{RODC_DC_SERVER_IPV6} = $ret->{SERVER_IPV6};
	$ret->{RODC_DC_NETBIOSNAME} = $ret->{NETBIOSNAME};

	$ret->{DC_SERVER} = $dcvars->{DC_SERVER};
	$ret->{DC_SERVER_IP} = $dcvars->{DC_SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $dcvars->{DC_SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $dcvars->{DC_NETBIOSNAME};
	$ret->{DC_USERNAME} = $dcvars->{DC_USERNAME};
	$ret->{DC_PASSWORD} = $dcvars->{DC_PASSWORD};

	return $ret;
}

sub read_config_h($)
{
	my ($name) = @_;
	my %ret = {};
	open(LF, "<$name") or die("unable to read $name: $!");
	while (<LF>) {
		chomp;
		next if not (/^#define /);
		if (/^#define (.*?)[ \t]+(.*?)$/) {
			$ret{$1} = $2;
			next;
		}
		if (/^#define (.*?)[ \t]+$/) {
			$ret{$1} = 1;;
			next;
		}
	}
	close(LF);
	return \%ret;
}

sub provision_ad_dc($$$$$$)
{
	my ($self, $prefix, $hostname, $domain, $realm, $smbconf_args) = @_;

	my $prefix_abs = abs_path($prefix);

	my $bindir_abs = abs_path($self->{bindir});
	my $lockdir="$prefix_abs/lockdir";
        my $conffile="$prefix_abs/etc/smb.conf";

	my $require_mutexes = "dbwrap_tdb_require_mutexes:* = yes";
	$require_mutexes = "" if ($ENV{SELFTEST_DONT_REQUIRE_TDB_MUTEX_SUPPORT} eq "1");

	my $config_h = {};

	if (defined($ENV{CONFIG_H})) {
		$config_h = read_config_h($ENV{CONFIG_H});
	}

	my $password_hash_gpg_key_ids = "password hash gpg key ids = 4952E40301FAB41A";
	$password_hash_gpg_key_ids = "" unless defined($config_h->{HAVE_GPGME});

	my $extra_smbconf_options = "
        server services = -smb +s3fs
        xattr_tdb:file = $prefix_abs/statedir/xattr.tdb

	dbwrap_tdb_mutexes:* = yes
	${require_mutexes}

	${password_hash_gpg_key_ids}

	kernel oplocks = no
	kernel change notify = no
	smb2 leases = no

	logging = file
	printing = bsd
	printcap name = /dev/null

	max protocol = SMB3
	read only = no

	smbd:sharedelay = 100000
	smbd:writetimeupdatedelay = 500000
	create mask = 755
	dos filemode = yes
	check parent directory delete on close = yes

        dcerpc endpoint servers = -winreg -srvsvc

	printcap name = /dev/null

	addprinter command = $ENV{SRCDIR_ABS}/source3/script/tests/printing/modprinter.pl -a -s $conffile --
	deleteprinter command = $ENV{SRCDIR_ABS}/source3/script/tests/printing/modprinter.pl -d -s $conffile --

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

	server schannel = auto
        auth event notification = true
        $smbconf_args
";

	my $extra_smbconf_shares = "

[tmpenc]
	copy = tmp
	smb encrypt = required

[tmpcase]
	copy = tmp
	case sensitive = yes

[tmpguest]
	copy = tmp
        guest ok = yes

[hideunread]
	copy = tmp
	hide unreadable = yes

[durable]
	copy = tmp
	kernel share modes = no
	kernel oplocks = no
	posix locking = no

[print\$]
	copy = tmp

[print1]
	copy = tmp
	printable = yes

[print2]
	copy = print1
[print3]
	copy = print1
[lp]
	copy = print1
";

	print "PROVISIONING AD DC...\n";
	my $ret = $self->provision($prefix,
				   "domain controller",
				   $hostname,
				   $domain,
				   $realm,
				   "2008",
				   "locDCpass1",
				   undef,
				   undef,
				   $extra_smbconf_options,
				   $extra_smbconf_shares,
				   undef);
	unless (defined $ret) {
		return undef;
	}

	unless($self->add_wins_config("$prefix/private")) {
		warn("Unable to add wins configuration");
		return undef;
	}

	$ret->{DC_SERVER} = $ret->{SERVER};
	$ret->{DC_SERVER_IP} = $ret->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $ret->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $ret->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $ret->{USERNAME};
	$ret->{DC_PASSWORD} = $ret->{PASSWORD};

	return $ret;
}

sub provision_chgdcpass($$)
{
	my ($self, $prefix) = @_;

	print "PROVISIONING CHGDCPASS...\n";
	my $extra_provision_options = undef;
	# This environment disallows the use of this password
	# (and also removes the default AD complexity checks)
	my $unacceptable_password = "widk3Dsle32jxdBdskldsk55klASKQ";
	push (@{$extra_provision_options}, "--dns-backend=BIND9_DLZ");
	my $ret = $self->provision($prefix,
				   "domain controller",
				   "chgdcpass",
				   "CHDCDOMAIN",
				   "chgdcpassword.samba.example.com",
				   "2008",
				   "chgDCpass1",
				   undef,
				   undef,
				   "check password script = sed -e '/$unacceptable_password/{;q1}; /$unacceptable_password/!{q0}'\n",
				   "",
				   $extra_provision_options);
	unless (defined $ret) {
		return undef;
	}

	unless($self->add_wins_config("$prefix/private")) {
		warn("Unable to add wins configuration");
		return undef;
	}
	
	# Remove secrets.tdb from this environment to test that we
	# still start up on systems without the new matching
	# secrets.tdb records.
	unless (unlink("$ret->{PRIVATEDIR}/secrets.tdb") || unlink("$ret->{PRIVATEDIR}/secrets.ntdb")) {
		warn("Unable to remove $ret->{PRIVATEDIR}/secrets.tdb added during provision");
		return undef;
	}
	    
	$ret->{DC_SERVER} = $ret->{SERVER};
	$ret->{DC_SERVER_IP} = $ret->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $ret->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $ret->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $ret->{USERNAME};
	$ret->{DC_PASSWORD} = $ret->{PASSWORD};
	$ret->{UNACCEPTABLE_PASSWORD} = $unacceptable_password;

	return $ret;
}

sub teardown_env_terminate($$)
{
	my ($self, $envvars) = @_;
	my $pid;

	# This should cause samba to terminate gracefully
	close($envvars->{STDIN_PIPE});

	$pid = $envvars->{SAMBA_PID};
	my $count = 0;
	my $childpid;

	# This should give it time to write out the gcov data
	until ($count > 15) {
	    if (Samba::cleanup_child($pid, "samba") != 0) {
		return;
	    }
	    sleep(1);
	    $count++;
	}

	# After 15 Seconds, work out why this thing is still alive
	warn "server process $pid took more than $count seconds to exit, showing backtrace:\n";
	system("$self->{srcdir}/selftest/gdb_backtrace $pid");

	until ($count > 30) {
	    if (Samba::cleanup_child($pid, "samba") != 0) {
		return;
	    }
	    sleep(1);
	    $count++;
	}

	if (kill(0, $pid)) {
	    warn "server process $pid took more than $count seconds to exit, sending SIGTERM\n";
	    kill "TERM", $pid;
	}

	until ($count > 40) {
	    if (Samba::cleanup_child($pid, "samba") != 0) {
		return;
	    }
	    sleep(1);
	    $count++;
	}
	# If it is still around, kill it
	if (kill(0, $pid)) {
	    warn "server process $pid took more than $count seconds to exit, killing\n with SIGKILL\n";
	    kill 9, $pid;
	}
	return;
}

sub teardown_env($$)
{
	my ($self, $envvars) = @_;
	teardown_env_terminate($self, $envvars);

	$self->slapd_stop($envvars) if ($self->{ldap});

	print $self->getlog_env($envvars);

	return;
}

sub getlog_env($$)
{
	my ($self, $envvars) = @_;
	my $title = "SAMBA LOG of: $envvars->{NETBIOSNAME} pid $envvars->{SAMBA_PID}\n";
	my $out = $title;

	open(LOG, "<$envvars->{SAMBA_TEST_LOG}");

	seek(LOG, $envvars->{SAMBA_TEST_LOG_POS}, SEEK_SET);
	while (<LOG>) {
		$out .= $_;
	}
	$envvars->{SAMBA_TEST_LOG_POS} = tell(LOG);
	close(LOG);

	return "" if $out eq $title;

	return $out;
}

sub check_env($$)
{
	my ($self, $envvars) = @_;
	my $samba_pid = $envvars->{SAMBA_PID};

	if (not defined($samba_pid)) {
	    return 0;
	} elsif ($samba_pid > 0) {
	    my $childpid = Samba::cleanup_child($samba_pid, "samba");

	    if ($childpid == 0) {
		return 1;
	    }
	    return 0;
	} else {
	    return 1;
	}
}

# Declare the environments Samba4 makes available.
# To be set up, they will be called as
#   samba4->setup_$envname($self, $path, $dep_1_vars, $dep_2_vars, ...)
%Samba4::ENV_DEPS = (
	# name               => [dep_1, dep_2, ...],
	ad_dc_ntvfs          => [],
	ad_dc                => [],
	ad_dc_no_nss         => [],
	ad_dc_no_ntlm        => [],
	ad_dc_ntvfs          => [],

	fl2008r2dc           => ["ad_dc"],
	fl2003dc             => ["ad_dc"],
	fl2000dc             => [],

	vampire_2000_dc      => ["fl2000dc"],
	vampire_dc           => ["ad_dc_ntvfs"],
	promoted_dc          => ["ad_dc_ntvfs"],
	subdom_dc            => ["ad_dc_ntvfs"],

	rodc                 => ["ad_dc_ntvfs"],
	rpc_proxy            => ["ad_dc_ntvfs"],
	chgdcpass            => [],

	s4member_dflt_domain => ["ad_dc_ntvfs"],
	s4member             => ["ad_dc_ntvfs"],

	none                 => [],
);

sub setup_s4member
{
	my ($self, $path, $dc_vars) = @_;

	my $env = $self->provision_s4member($path, $dc_vars, "s4member");

	if (defined $env) {
	        if (not defined($self->check_or_start($env, "standard"))) {
		        return undef;
		}
	}

	return $env;
}

sub setup_s4member_dflt_domain
{
	my ($self, $path, $dc_vars) = @_;

	my $env = $self->provision_s4member($path, $dc_vars, "s4member_dflt",
					    "winbind use default domain = yes");

	if (defined $env) {
	        if (not defined($self->check_or_start($env, "standard"))) {
		        return undef;
		}
	}

	return $env;
}

sub setup_rpc_proxy
{
	my ($self, $path, $dc_vars) = @_;

	my $env = $self->provision_rpc_proxy($path, $dc_vars);

	if (defined $env) {
	        if (not defined($self->check_or_start($env, "standard"))) {
		        return undef;
		}
	}
	return $env;
}

sub setup_ad_dc_ntvfs
{
	my ($self, $path) = @_;

	my $env = $self->provision_ad_dc_ntvfs($path);
	if (defined $env) {
	        if (not defined($self->check_or_start($env, "standard"))) {
		    warn("Failed to start ad_dc_ntvfs");
		        return undef;
		}
	}
	return $env;
}

sub setup_chgdcpass
{
	my ($self, $path) = @_;

	my $env = $self->provision_chgdcpass($path);
	if (defined $env) {
	        if (not defined($self->check_or_start($env, "standard"))) {
		        return undef;
		}
	}
	return $env;
}

sub setup_fl2000dc
{
	my ($self, $path) = @_;

	my $env = $self->provision_fl2000dc($path);
	if (defined $env) {
	        if (not defined($self->check_or_start($env, "standard"))) {
		        return undef;
		}
	}

	return $env;
}

sub setup_fl2003dc
{
	my ($self, $path, $dc_vars) = @_;

	my $env = $self->provision_fl2003dc($path);

	if (defined $env) {
	        if (not defined($self->check_or_start($env, "standard"))) {
		        return undef;
		}

		$env = $self->setup_trust($env, $dc_vars, "external", "--no-aes-keys");
	}
	return $env;
}

sub setup_fl2008r2dc
{
	my ($self, $path, $dc_vars) = @_;

	my $env = $self->provision_fl2008r2dc($path);

	if (defined $env) {
	        if (not defined($self->check_or_start($env, "standard"))) {
		        return undef;
		}

		my $upn_array = ["$env->{REALM}.upn"];
		my $spn_array = ["$env->{REALM}.spn"];

		$self->setup_namespaces($env, $upn_array, $spn_array);

		$env = $self->setup_trust($env, $dc_vars, "forest", "");
	}

	return $env;
}

sub setup_vampire_dc
{
	return setup_generic_vampire_dc(@_, "2008");
}

sub setup_vampire_2000_dc
{
	return setup_generic_vampire_dc(@_, "2000");
}

sub setup_generic_vampire_dc
{
	my ($self, $path, $dc_vars, $fl) = @_;

	my $env = $self->provision_vampire_dc($path, $dc_vars, $fl);

	if (defined $env) {
	        if (not defined($self->check_or_start($env, "single"))) {
		        return undef;
		}

		# force replicated DC to update repsTo/repsFrom
		# for vampired partitions
		my $samba_tool =  Samba::bindir_path($self, "samba-tool");

		# as 'vampired' dc may add data in its local replica
		# we need to synchronize data between DCs
		my $base_dn = "DC=".join(",DC=", split(/\./, $dc_vars->{REALM}));
		my $cmd = "";
		$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$env->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
		if (defined($env->{RESOLV_WRAPPER_CONF})) {
			$cmd .= "RESOLV_WRAPPER_CONF=\"$env->{RESOLV_WRAPPER_CONF}\" ";
		} else {
			$cmd .= "RESOLV_WRAPPER_HOSTS=\"$env->{RESOLV_WRAPPER_HOSTS}\" ";
		}
		$cmd .= " KRB5_CONFIG=\"$env->{KRB5_CONFIG}\"";
		$cmd .= "KRB5CCNAME=\"$env->{KRB5_CCACHE}\" ";
		$cmd .= " $samba_tool drs replicate $env->{DC_SERVER} $env->{SERVER}";
		$cmd .= " $dc_vars->{CONFIGURATION}";
		$cmd .= " -U$dc_vars->{DC_USERNAME}\%$dc_vars->{DC_PASSWORD}";
		# replicate Configuration NC
		my $cmd_repl = "$cmd \"CN=Configuration,$base_dn\"";
		unless(system($cmd_repl) == 0) {
			warn("Failed to replicate\n$cmd_repl");
			return undef;
		}
		# replicate Default NC
		$cmd_repl = "$cmd \"$base_dn\"";
		unless(system($cmd_repl) == 0) {
			warn("Failed to replicate\n$cmd_repl");
			return undef;
		}

		# Pull in a full set of changes from the main DC
		my $base_dn = "DC=".join(",DC=", split(/\./, $dc_vars->{REALM}));
		$cmd = "";
		$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$env->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
		if (defined($env->{RESOLV_WRAPPER_CONF})) {
			$cmd .= "RESOLV_WRAPPER_CONF=\"$env->{RESOLV_WRAPPER_CONF}\" ";
		} else {
			$cmd .= "RESOLV_WRAPPER_HOSTS=\"$env->{RESOLV_WRAPPER_HOSTS}\" ";
		}
		$cmd .= " KRB5_CONFIG=\"$env->{KRB5_CONFIG}\"";
		$cmd .= "KRB5CCNAME=\"$env->{KRB5_CCACHE}\" ";
		$cmd .= " $samba_tool drs replicate $env->{SERVER} $env->{DC_SERVER}";
		$cmd .= " $dc_vars->{CONFIGURATION}";
		$cmd .= " -U$dc_vars->{DC_USERNAME}\%$dc_vars->{DC_PASSWORD}";
		# replicate Configuration NC
		my $cmd_repl = "$cmd \"CN=Configuration,$base_dn\"";
		unless(system($cmd_repl) == 0) {
			warn("Failed to replicate\n$cmd_repl");
			return undef;
		}
		# replicate Default NC
		$cmd_repl = "$cmd \"$base_dn\"";
		unless(system($cmd_repl) == 0) {
			warn("Failed to replicate\n$cmd_repl");
			return undef;
		}
	}

	return $env;
}

sub setup_promoted_dc
{
	my ($self, $path, $dc_vars) = @_;

	my $env = $self->provision_promoted_dc($path, $dc_vars);

	if (defined $env) {
	        if (not defined($self->check_or_start($env, "single"))) {
		        return undef;
		}

		# force source and replicated DC to update repsTo/repsFrom
		# for vampired partitions
		my $samba_tool =  Samba::bindir_path($self, "samba-tool");
		my $cmd = "";
		# as 'vampired' dc may add data in its local replica
		# we need to synchronize data between DCs
		my $base_dn = "DC=".join(",DC=", split(/\./, $dc_vars->{REALM}));
		$cmd = "SOCKET_WRAPPER_DEFAULT_IFACE=\"$env->{SOCKET_WRAPPER_DEFAULT_IFACE}\"";
		$cmd .= " KRB5_CONFIG=\"$env->{KRB5_CONFIG}\"";
		$cmd .= "KRB5CCNAME=\"$env->{KRB5_CCACHE}\" ";
		$cmd .= " $samba_tool drs replicate $env->{DC_SERVER} $env->{SERVER}";
		$cmd .= " $dc_vars->{CONFIGURATION}";
		$cmd .= " -U$dc_vars->{DC_USERNAME}\%$dc_vars->{DC_PASSWORD}";
		# replicate Configuration NC
		my $cmd_repl = "$cmd \"CN=Configuration,$base_dn\"";
		unless(system($cmd_repl) == 0) {
			warn("Failed to replicate\n$cmd_repl");
			return undef;
		}
		# replicate Default NC
		$cmd_repl = "$cmd \"$base_dn\"";
		unless(system($cmd_repl) == 0) {
			warn("Failed to replicate\n$cmd_repl");
			return undef;
		}
	}

	return $env;
}

sub setup_subdom_dc
{
	my ($self, $path, $dc_vars) = @_;

	my $env = $self->provision_subdom_dc($path, $dc_vars);

	if (defined $env) {
	        if (not defined($self->check_or_start($env, "single"))) {
		        return undef;
		}

		# force replicated DC to update repsTo/repsFrom
		# for primary domain partitions
		my $samba_tool =  Samba::bindir_path($self, "samba-tool");
		my $cmd = "";
		# as 'subdomain' dc may add data in its local replica
		# we need to synchronize data between DCs
		my $base_dn = "DC=".join(",DC=", split(/\./, $env->{REALM}));
		my $config_dn = "CN=Configuration,DC=".join(",DC=", split(/\./, $dc_vars->{REALM}));
		$cmd = "SOCKET_WRAPPER_DEFAULT_IFACE=\"$env->{SOCKET_WRAPPER_DEFAULT_IFACE}\"";
		$cmd .= " KRB5_CONFIG=\"$env->{KRB5_CONFIG}\"";
		$cmd .= "KRB5CCNAME=\"$env->{KRB5_CCACHE}\" ";
		$cmd .= " $samba_tool drs replicate $env->{DC_SERVER} $env->{SUBDOM_DC_SERVER}";
		$cmd .= " $dc_vars->{CONFIGURATION}";
		$cmd .= " -U$dc_vars->{DC_USERNAME}\%$dc_vars->{DC_PASSWORD} --realm=$dc_vars->{DC_REALM}";
		# replicate Configuration NC
		my $cmd_repl = "$cmd \"$config_dn\"";
		unless(system($cmd_repl) == 0) {
			warn("Failed to replicate\n$cmd_repl");
			return undef;
		}
		# replicate Default NC
		$cmd_repl = "$cmd \"$base_dn\"";
		unless(system($cmd_repl) == 0) {
			warn("Failed to replicate\n$cmd_repl");
			return undef;
		}
	}

	return $env;
}

sub setup_rodc
{
	my ($self, $path, $dc_vars) = @_;

	my $env = $self->provision_rodc($path, $dc_vars);

	unless ($env) {
		return undef;
	}

	if (not defined($self->check_or_start($env, "standard"))) {
	    return undef;
	}

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");
	my $cmd = "";

	my $base_dn = "DC=".join(",DC=", split(/\./, $dc_vars->{REALM}));
	$cmd = "SOCKET_WRAPPER_DEFAULT_IFACE=\"$env->{SOCKET_WRAPPER_DEFAULT_IFACE}\"";
	$cmd .= " KRB5_CONFIG=\"$env->{KRB5_CONFIG}\"";
	$cmd .= "KRB5CCNAME=\"$env->{KRB5_CCACHE}\" ";
	$cmd .= " $samba_tool drs replicate $env->{SERVER} $env->{DC_SERVER}";
	$cmd .= " $dc_vars->{CONFIGURATION}";
	$cmd .= " -U$dc_vars->{DC_USERNAME}\%$dc_vars->{DC_PASSWORD}";
	# replicate Configuration NC
	my $cmd_repl = "$cmd \"CN=Configuration,$base_dn\"";
	unless(system($cmd_repl) == 0) {
	    warn("Failed to replicate\n$cmd_repl");
	    return undef;
	}
	# replicate Default NC
	$cmd_repl = "$cmd \"$base_dn\"";
	unless(system($cmd_repl) == 0) {
	    warn("Failed to replicate\n$cmd_repl");
	    return undef;
	}

	return $env;
}

sub setup_ad_dc
{
	my ($self, $path) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->{target3}->have_ads()) {
	       return "UNKNOWN";
	}

	my $env = $self->provision_ad_dc($path, "addc", "ADDOMAIN",
					 "addom.samba.example.com", "");
	unless ($env) {
		return undef;
	}

	if (not defined($self->check_or_start($env, "single"))) {
	    return undef;
	}

	my $upn_array = ["$env->{REALM}.upn"];
	my $spn_array = ["$env->{REALM}.spn"];

	$self->setup_namespaces($env, $upn_array, $spn_array);

	return $env;
}

sub setup_ad_dc_no_nss
{
	my ($self, $path) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->{target3}->have_ads()) {
	       return "UNKNOWN";
	}

	my $env = $self->provision_ad_dc($path, "addc_no_nss", "ADNONSSDOMAIN",
					 "adnonssdom.samba.example.com", "");
	unless ($env) {
		return undef;
	}

	$env->{NSS_WRAPPER_MODULE_SO_PATH} = undef;
	$env->{NSS_WRAPPER_MODULE_FN_PREFIX} = undef;

	if (not defined($self->check_or_start($env, "single"))) {
	    return undef;
	}

	my $upn_array = ["$env->{REALM}.upn"];
	my $spn_array = ["$env->{REALM}.spn"];

	$self->setup_namespaces($env, $upn_array, $spn_array);

	return $env;
}

sub setup_ad_dc_no_ntlm
{
	my ($self, $path) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->{target3}->have_ads()) {
	       return "UNKNOWN";
	}

	my $env = $self->provision_ad_dc($path, "addc_no_ntlm", "ADNONTLMDOMAIN",
					 "adnontlmdom.samba.example.com",
					 "ntlm auth = disabled");
	unless ($env) {
		return undef;
	}

	if (not defined($self->check_or_start($env, "prefork"))) {
	    return undef;
	}

	my $upn_array = ["$env->{REALM}.upn"];
	my $spn_array = ["$env->{REALM}.spn"];

	$self->setup_namespaces($env, $upn_array, $spn_array);

	return $env;
}

sub setup_none
{
	my ($self, $path) = @_;

	my $ret = {
		KRB5_CONFIG => abs_path($path) . "/no_krb5.conf",
		SAMBA_PID => -1,
	}
}

1;
