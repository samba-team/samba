#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

# NOTE: Refer to the README for more details about the various testenvs,
# and tips about adding new testenvs.

package Samba4;

use strict;
use warnings;
use Cwd qw(abs_path);
use FindBin qw($RealBin);
use POSIX;
use SocketWrapper;
use target::Samba;
use target::Samba3;
use Archive::Tar;

sub new($$$$$) {
	my ($classname, $SambaCtx, $bindir, $srcdir, $server_maxtime) = @_;

	my $self = {
		vars => {},
		SambaCtx => $SambaCtx,
		bindir => $bindir,
		srcdir => $srcdir,
		server_maxtime => $server_maxtime,
		target3 => new Samba3($SambaCtx, $bindir, $srcdir, $server_maxtime)
	};
	bless $self;
	return $self;
}

sub scriptdir_path($$) {
	my ($self, $path) = @_;
	return "$self->{srcdir}/source4/scripting/$path";
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

	# build up the command to run samba
	my @preargs = ();
	my @optargs = ();
	if (defined($ENV{SAMBA_OPTIONS})) {
		@optargs = split(/ /, $ENV{SAMBA_OPTIONS});
	}
	if(defined($ENV{SAMBA_VALGRIND})) {
		@preargs = split(/ /,$ENV{SAMBA_VALGRIND});
	}

	if (defined($process_model)) {
		push @optargs, ("-M", $process_model);
	}
	my $binary = Samba::bindir_path($self, "samba");
	my @full_cmd = (@preargs, $binary, "-i",
			"--no-process-group", "--maximum-runtime=$self->{server_maxtime}",
			$env_vars->{CONFIGURATION}, @optargs);

	# the samba process takes some additional env variables (compared to s3)
	my $samba_envs = Samba::get_env_for_process("samba", $env_vars);
	if (defined($ENV{MITKRB5})) {
		$samba_envs->{KRB5_KDC_PROFILE} = $env_vars->{MITKDC_CONFIG};
	}

	# fork a child process and exec() samba
	my $daemon_ctx = {
		NAME => "samba",
		BINARY_PATH => $binary,
		FULL_CMD => [ @full_cmd ],
		LOG_FILE => $env_vars->{SAMBA_TEST_LOG},
		TEE_STDOUT => 1,
		PCAP_FILE => "env-$ENV{ENVNAME}-samba",
		ENV_VARS => $samba_envs,
	};
	my $pid = Samba::fork_and_exec($self, $env_vars, $daemon_ctx, $STDIN_READER);

	$env_vars->{SAMBA_PID} = $pid;

	# close the parent's read-end of the pipe
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
		teardown_env($self, $testenv_vars);
		warn("nbt not reachable after 20 retries\n");
		return -1;
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
		my $cmd = $self->get_cmd_env_vars($testenv_vars);

		$cmd .= "$ldbsearch ";
		$cmd .= "$testenv_vars->{CONFIGURATION} ";
		$cmd .= "-H ldap://$testenv_vars->{SERVER} ";
		$cmd .= "-U$testenv_vars->{USERNAME}%$testenv_vars->{PASSWORD} ";
		$cmd .= "-s base ";
		$cmd .= "-b '$search_dn' ";
		while (system("$cmd >/dev/null") != 0) {
			$count++;
			if ($count > $max_wait) {
				teardown_env($self, $testenv_vars);
				warn("Timed out ($max_wait sec) waiting for working LDAP and a RID Set to be allocated by $testenv_vars->{NETBIOSNAME} PID $testenv_vars->{SAMBA_PID}");
				return -1;
			}
			print "Waiting for working LDAP...\n";
			sleep(1);
		}
	}

	my $wbinfo =  Samba::bindir_path($self, "wbinfo");

	$count = 0;
	do {
		my $cmd = "NSS_WRAPPER_PASSWD=$testenv_vars->{NSS_WRAPPER_PASSWD} ";
		$cmd .= "NSS_WRAPPER_GROUP=$testenv_vars->{NSS_WRAPPER_GROUP} ";
		$cmd .= "SELFTEST_WINBINDD_SOCKET_DIR=$testenv_vars->{SELFTEST_WINBINDD_SOCKET_DIR} ";
		$cmd .= "$wbinfo -P";
		$ret = system($cmd);

		if ($ret != 0) {
			sleep(1);
		}
		$count++;
	} while ($ret != 0 && $count < 20);
	if ($count == 20) {
		teardown_env($self, $testenv_vars);
		warn("winbind not reachable after 20 retries\n");
		return -1;
	}

	# Ensure we registered all our names
	if ($testenv_vars->{SERVER_ROLE} eq "domain controller") {
		my $max_wait = 120;
		print "Waiting for dns_update_cache to be created.\n";
		$count = 0;
		while (not -e "$testenv_vars->{PRIVATEDIR}/dns_update_cache") {
			$count++;
			if ($count > $max_wait) {
				teardown_env($self, $testenv_vars);
				warn("Timed out ($max_wait sec) waiting for dns_update_cache PID $testenv_vars->{SAMBA_PID}");
				return -1;
			}
			print "Waiting for dns_update_cache to be created...\n";
			sleep(1);
		}
		print "Waiting for dns_update_cache to be filled.\n";
		$count = 0;
		while ((-s "$testenv_vars->{PRIVATEDIR}/dns_update_cache") == 0) {
			$count++;
			if ($count > $max_wait) {
				teardown_env($self, $testenv_vars);
				warn("Timed out ($max_wait sec) waiting for dns_update_cache PID $testenv_vars->{SAMBA_PID}");
				return -1;
			}
			print "Waiting for dns_update_cache to be filled...\n";
			sleep(1);
		}
	}

	print $self->getlog_env($testenv_vars);

	print "READY ($testenv_vars->{SAMBA_PID})\n";

	return 0
}

sub write_ldb_file($$$)
{
	my ($self, $file, $ldif_in) = @_;

	my $ldbadd =  Samba::bindir_path($self, "ldbadd");
	open(my $ldif, "|$ldbadd -H $file > /dev/null")
	    or die "Failed to run $ldbadd: $!";
	print $ldif $ldif_in;
	close($ldif);

	unless ($? == 0) {
	    warn("$ldbadd failed: $?");
	    return undef;
	}
	return 1;
}

sub add_wins_config($$)
{
	my ($self, $privatedir) = @_;
	my $client_ip = Samba::get_ipv4_addr("client");

	return $self->write_ldb_file("$privatedir/wins_config.ldb", "
dn: name=TORTURE_11,CN=PARTNERS
objectClass: wreplPartner
name: TORTURE_11
address: $client_ip
pullInterval: 0
pushChangeCount: 0
type: 0x3
");
}

sub setup_dns_hub_internal($$$)
{
	my ($self, $hostname, $prefix) = @_;
	my $STDIN_READER;

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

	my $env = undef;
	$env->{NETBIOSNAME} = $hostname;

	$env->{SERVER_IP} = Samba::get_ipv4_addr($hostname);
	$env->{SERVER_IPV6} = Samba::get_ipv6_addr($hostname);
	$env->{SOCKET_WRAPPER_DEFAULT_IFACE} = Samba::get_interface($hostname);
	$env->{DNS_HUB_LOG} = "$prefix_abs/dns_hub.log";
	$env->{RESOLV_CONF} = "$prefix_abs/resolv.conf";
	$env->{TESTENV_DIR} = $prefix_abs;

	my $ctx = undef;
	$ctx->{resolv_conf} = $env->{RESOLV_CONF};
	$ctx->{dns_ipv4} = $env->{SERVER_IP};
	$ctx->{dns_ipv6} = $env->{SERVER_IPV6};
	Samba::mk_resolv_conf($ctx);

	my @preargs = ();
	my @args = ();
	if (!defined($ENV{PYTHON})) {
	    push (@preargs, "env");
	    push (@preargs, "python");
	} else {
	    push (@preargs, $ENV{PYTHON});
	}
	my $binary = "$self->{srcdir}/selftest/target/dns_hub.py";
	push (@args, "$self->{server_maxtime}");
	push (@args, "$env->{SERVER_IP},$env->{SERVER_IPV6}");
	push (@args, Samba::realm_to_ip_mappings());
	my @full_cmd = (@preargs, $binary, @args);

	my $daemon_ctx = {
		NAME => "dnshub",
		BINARY_PATH => $binary,
		FULL_CMD => [ @full_cmd ],
		LOG_FILE => $env->{DNS_HUB_LOG},
		TEE_STDOUT => 1,
		PCAP_FILE => "env-$ENV{ENVNAME}-dns_hub",
		ENV_VARS => {},
	};

	# use a pipe for stdin in the child processes. This allows
	# those processes to monitor the pipe for EOF to ensure they
	# exit when the test script exits
	pipe($STDIN_READER, $env->{STDIN_PIPE});

	my $pid = Samba::fork_and_exec($self, $env, $daemon_ctx, $STDIN_READER);

	$env->{SAMBA_PID} = $pid;
	$env->{KRB5_CONFIG} = "$prefix_abs/no_krb5.conf";

	# close the parent's read-end of the pipe
	close($STDIN_READER);

	return $env;
}

sub setup_dns_hub
{
	my ($self, $prefix) = @_;

	my $hostname = "rootdnsforwarder";

	unless(-d $prefix or mkdir($prefix, 0777)) {
		warn("Unable to create $prefix");
		return undef;
	}
	my $env = $self->setup_dns_hub_internal("$hostname", "$prefix/$hostname");

	$self->{dns_hub_env} = $env;

	return $env;
}

sub get_dns_hub_env($)
{
	my ($self, $prefix) = @_;

	if (defined($self->{dns_hub_env})) {
	        return $self->{dns_hub_env};
	}

	die("get_dns_hub_env() not setup 'dns_hub_env'");
	return undef;
}

sub return_env_value
{
	my ($env, $overwrite, $key) = @_;

	if (defined($overwrite) and defined($overwrite->{$key})) {
		return $overwrite->{$key};
	}

	if (defined($env->{$key})) {
		return $env->{$key};
	}

	return undef;
}

# Returns the environmental variables that we pass to samba-tool commands
sub get_cmd_env_vars
{
	my ($self, $givenenv, $overwrite) = @_;

	my @keys = (
		"NSS_WRAPPER_HOSTS",
		"SOCKET_WRAPPER_DEFAULT_IFACE",
		"RESOLV_CONF",
		"RESOLV_WRAPPER_CONF",
		"RESOLV_WRAPPER_HOSTS",
		"GNUTLS_FORCE_FIPS_MODE",
		"OPENSSL_FORCE_FIPS_MODE",
		"KRB5_CONFIG",
		"KRB5_CCACHE",
		"GNUPGHOME",
	);

	my $localenv = undef;
	foreach my $key (@keys) {
		my $v = return_env_value($givenenv, $overwrite, $key);
		$localenv->{$key} = $v if defined($v);
	}

	my $cmd_env = "NSS_WRAPPER_HOSTS='$localenv->{NSS_WRAPPER_HOSTS}' ";
	$cmd_env .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$localenv->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($localenv->{RESOLV_WRAPPER_CONF})) {
		$cmd_env .= "RESOLV_WRAPPER_CONF=\"$localenv->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd_env .= "RESOLV_WRAPPER_HOSTS=\"$localenv->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	if (defined($localenv->{GNUTLS_FORCE_FIPS_MODE})) {
		$cmd_env .= "GNUTLS_FORCE_FIPS_MODE=$localenv->{GNUTLS_FORCE_FIPS_MODE} ";
	}
	if (defined($localenv->{OPENSSL_FORCE_FIPS_MODE})) {
		$cmd_env .= "OPENSSL_FORCE_FIPS_MODE=$localenv->{OPENSSL_FORCE_FIPS_MODE} ";
	}
	$cmd_env .= "KRB5_CONFIG=\"$localenv->{KRB5_CONFIG}\" ";
	$cmd_env .= "KRB5CCNAME=\"$localenv->{KRB5_CCACHE}\" ";
	$cmd_env .= "RESOLV_CONF=\"$localenv->{RESOLV_CONF}\" ";
	$cmd_env .= "GNUPGHOME=\"$localenv->{GNUPGHOME}\" ";

	return $cmd_env;
}

# Sets up a forest trust namespace.
# (Note this is different to kernel namespaces, setup by the
# USE_NAMESPACES=1 option)
sub setup_namespaces
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

	my $cmd_env = $self->get_cmd_env_vars($localenv);

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

	$localenv->{TRUST_USERNAME} = $remoteenv->{USERNAME};
	$localenv->{TRUST_PASSWORD} = $remoteenv->{PASSWORD};
	$localenv->{TRUST_DOMAIN} = $remoteenv->{DOMAIN};
	$localenv->{TRUST_REALM} = $remoteenv->{REALM};
	$localenv->{TRUST_DOMSID} = $remoteenv->{DOMSID};

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");

	# setup the trust
	my $cmd_env = $self->get_cmd_env_vars($localenv);

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

	my $groupname = "g_$localenv->{TRUST_DOMAIN}";
	my $groupadd = $cmd_env;
	$groupadd .= " $samba_tool group add '$groupname' --group-scope=Domain $cmd_config";
	unless (system($groupadd) == 0) {
		warn("Failed to create group \n$groupadd");
		return undef;
	}
	my $groupmem = $cmd_env;
	$groupmem .= " $samba_tool group addmembers '$groupname' '$localenv->{TRUST_DOMSID}-513' $cmd_config";
	unless (system($groupmem) == 0) {
		warn("Failed to add group member \n$groupmem");
		return undef;
	}

	return $localenv
}

sub provision_raw_prepare($$$$$$$$$$$$$$)
{
	my ($self,
	    $prefix,
	    $server_role,
	    $hostname,
	    $domain,
	    $realm,
	    $samsid,
	    $functional_level,
	    $password,
	    $kdc_ipv4,
	    $kdc_ipv6,
	    $force_fips_mode,
	    $extra_provision_options) = @_;
	my $ctx;
	my $python_cmd = "";
	if (defined $ENV{PYTHON}) {
		$python_cmd = $ENV{PYTHON} . " ";
	}
	$ctx->{python} = $python_cmd;
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
	$ctx->{force_fips_mode} = $force_fips_mode;
	$ctx->{krb5_ccname} = "$prefix_abs/krb5cc_%{uid}";
	if ($functional_level eq "2000") {
		$ctx->{supported_enctypes} = "arcfour-hmac-md5 des-cbc-md5 des-cbc-crc";
	}

#
# Set smbd log level here.
#
	$ctx->{server_loglevel} =$ENV{SERVER_LOG_LEVEL} || 1;
	$ctx->{username} = "Administrator";
	$ctx->{domain} = $domain;
	$ctx->{realm} = uc($realm);
	$ctx->{dnsname} = lc($realm);
	$ctx->{samsid} = $samsid;

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
	$ctx->{gnupghome} = "$prefix_abs/gnupg";
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
		$ctx->{samba_dnsupdate} = $python_cmd .  $ctx->{samba_dnsupdate};
	} else {
	        $ctx->{samba_dnsupdate} = "$ENV{SRCDIR_ABS}/source4/scripting/bin/samba_dnsupdate -s $ctx->{smb_conf} --all-interfaces";
		$ctx->{samba_dnsupdate} = $python_cmd .  $ctx->{samba_dnsupdate};
		$ctx->{use_resolv_wrapper} = 1;
	}

	my $dns_hub = $self->get_dns_hub_env();
	$ctx->{resolv_conf} = $dns_hub->{RESOLV_CONF};

	$ctx->{tlsdir} = "$ctx->{privatedir}/tls";

	$ctx->{ipv4} = Samba::get_ipv4_addr($hostname);
	$ctx->{ipv6} = Samba::get_ipv6_addr($hostname);

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
	push (@provision_options, "GNUPGHOME=\"$ctx->{gnupghome}\"");
	push (@provision_options, "KRB5_CONFIG=\"$ctx->{krb5_conf}\"");
	push (@provision_options, "KRB5CCNAME=\"$ctx->{krb5_ccache}\"");
	push (@provision_options, "NSS_WRAPPER_PASSWD=\"$ctx->{nsswrap_passwd}\"");
	push (@provision_options, "NSS_WRAPPER_GROUP=\"$ctx->{nsswrap_group}\"");
	push (@provision_options, "NSS_WRAPPER_HOSTS=\"$ctx->{nsswrap_hosts}\"");
	push (@provision_options, "NSS_WRAPPER_HOSTNAME=\"$ctx->{nsswrap_hostname}\"");
	if (defined($ctx->{use_resolv_wrapper})) {
		push (@provision_options, "RESOLV_WRAPPER_CONF=\"$ctx->{resolv_conf}\"");
		push (@provision_options, "RESOLV_CONF=\"$ctx->{resolv_conf}\"");
	} else {
		push (@provision_options, "RESOLV_WRAPPER_HOSTS=\"$ctx->{dns_host_file}\"");
	}
	if (defined($ctx->{force_fips_mode})) {
		push (@provision_options, "GNUTLS_FORCE_FIPS_MODE=1");
		push (@provision_options, "OPENSSL_FORCE_FIPS_MODE=1");
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

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");

	push (@provision_options, $samba_tool);
	push (@provision_options, "domain");
	push (@provision_options, "provision");
	push (@provision_options, "--configfile=$ctx->{smb_conf}");
	push (@provision_options, "--host-name=$ctx->{hostname}");
	push (@provision_options, "--host-ip=$ctx->{ipv4}");
	push (@provision_options, "--quiet");
	push (@provision_options, "--domain=$ctx->{domain}");
	push (@provision_options, "--realm=$ctx->{realm}");
	if (defined($ctx->{samsid})) {
		push (@provision_options, "--domain-sid=$ctx->{samsid}");
	}
	push (@provision_options, "--adminpass=$ctx->{password}");
	push (@provision_options, "--krbtgtpass=krbtgt$ctx->{password}");
	push (@provision_options, "--machinepass=machine$ctx->{password}");
	push (@provision_options, "--root=$ctx->{unix_name}");
	push (@provision_options, "--server-role=\"$ctx->{server_role}\"");
	push (@provision_options, "--function-level=\"$ctx->{functional_level}\"");

	@{$ctx->{provision_options}} = @provision_options;

	if (defined($extra_provision_options)) {
		push (@{$ctx->{provision_options}}, @{$extra_provision_options});
	}

	return $ctx;
}

sub has_option
{
	my ($self, $keyword, @options_list) = @_;

	# convert the options-list to a hash-map for easy keyword lookup
	my %options_dict = map { $_ => 1 } @options_list;

	return exists $options_dict{$keyword};
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

	Samba::copy_gnupg_home($ctx);
	Samba::prepare_keyblobs($ctx);
	my $crlfile = "$ctx->{tlsdir}/crl.pem";
	$crlfile = "" unless -e ${crlfile};

	# work out which file server to use. Default to source3 smbd (s3fs),
	# unless the source4 NTVFS (smb) file server has been specified
	my $services = "-smb +s3fs";
	if ($self->has_option("--use-ntvfs", @{$ctx->{provision_options}})) {
		$services = "+smb -s3fs";
	}

	my $interfaces = Samba::get_interfaces_config($ctx->{netbiosname});

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
	interfaces = $interfaces
	tls dh params file = $ctx->{tlsdir}/dhparms.pem
	tls crlfile = ${crlfile}
	tls verify peer = no_check
	panic action = $RealBin/gdb_backtrace \%d
	wins support = yes
	server role = $ctx->{server_role}
	server services = +echo $services
        dcerpc endpoint servers = +winreg +srvsvc
	notify:inotify = false
	ldb:nosync = true
	ldap server require strong auth = yes
	log file = $ctx->{logdir}/log.\%m
	log level = $ctx->{server_loglevel}
	lanman auth = Yes
	ntlm auth = Yes
	client min protocol = SMB2_02
	server min protocol = SMB2_02
	mangled names = yes
	dns update command = $ctx->{samba_dnsupdate}
	spn update command = $ctx->{python} $ENV{SRCDIR_ABS}/source4/scripting/bin/samba_spnupdate -s $ctx->{smb_conf}
	gpo update command = $ctx->{python} $ENV{SRCDIR_ABS}/source4/scripting/bin/samba-gpupdate -s $ctx->{smb_conf} --target=Computer
	samba kcc command = $ctx->{python} $ENV{SRCDIR_ABS}/source4/scripting/bin/samba_kcc
	dreplsrv:periodic_startup_interval = 0
	dsdb:schema update allowed = yes

        vfs objects = dfs_samba4 acl_xattr fake_acls xattr_tdb streams_depot

        idmap_ldb:use rfc2307=yes
	winbind enum users = yes
	winbind enum groups = yes

        rpc server port:netlogon = 1026
	include system krb5 conf = no

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

	# Return the environment variables for the new testenv DC.
	# Note that we have SERVER_X and DC_SERVER_X variables (which have the same
	# value initially). In a 2 DC setup, $DC_SERVER_X will always be the PDC.
	my $ret = {
		GNUPGHOME => $ctx->{gnupghome},
		KRB5_CONFIG => $ctx->{krb5_conf},
		KRB5_CCACHE => $ctx->{krb5_ccache},
		MITKDC_CONFIG => $ctx->{mitkdc_conf},
		PIDDIR => $ctx->{piddir},
		SERVER => $ctx->{hostname},
		DC_SERVER => $ctx->{hostname},
		SERVER_IP => $ctx->{ipv4},
		DC_SERVER_IP => $ctx->{ipv4},
		SERVER_IPV6 => $ctx->{ipv6},
		DC_SERVER_IPV6 => $ctx->{ipv6},
		NETBIOSNAME => $ctx->{netbiosname},
		DC_NETBIOSNAME => $ctx->{netbiosname},
		DOMAIN => $ctx->{domain},
		USERNAME => $ctx->{username},
		DC_USERNAME => $ctx->{username},
		REALM => $ctx->{realm},
		DNSNAME => $ctx->{dnsname},
		SAMSID => $ctx->{samsid},
		PASSWORD => $ctx->{password},
		DC_PASSWORD => $ctx->{password},
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
		TESTENV_DIR => $ctx->{prefix_abs},
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
	        RESOLV_CONF => $ctx->{resolv_conf},
	};

	if (defined($ctx->{use_resolv_wrapper})) {
	        $ret->{RESOLV_WRAPPER_CONF} = $ctx->{resolv_conf};
	} else {
		$ret->{RESOLV_WRAPPER_HOSTS} = $ctx->{dns_host_file};
	}
	if (defined($ctx->{force_fips_mode})) {
		$ret->{GNUTLS_FORCE_FIPS_MODE} = "1",
		$ret->{OPENSSL_FORCE_FIPS_MODE} = "1",
	}

	if ($ctx->{server_role} eq "domain controller") {
		$ret->{DOMSID} = $ret->{SAMSID};
	}

	return $ret;
}

#
# Step2 runs the provision script
#
sub provision_raw_step2($$$)
{
	my ($self, $ctx, $ret) = @_;

	my $ldif;

	my $provision_cmd = join(" ", @{$ctx->{provision_options}});
	unless (system($provision_cmd) == 0) {
		warn("Unable to provision: \n$provision_cmd\n");
		return undef;
	}

	my $cmd_env = $self->get_cmd_env_vars($ret);

	my $testallowed_account = "testallowed";
	my $samba_tool_cmd = ${cmd_env};
	$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
	    . " user create --configfile=$ctx->{smb_conf} $testallowed_account $ctx->{password}";
	unless (system($samba_tool_cmd) == 0) {
		warn("Unable to add testallowed user: \n$samba_tool_cmd\n");
		return undef;
	}

	my $srv_account = "srv_account";
	$samba_tool_cmd = ${cmd_env};
	$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
	    . " user create --configfile=$ctx->{smb_conf} $srv_account $ctx->{password}";
	unless (system($samba_tool_cmd) == 0) {
		warn("Unable to add $srv_account user: \n$samba_tool_cmd\n");
		return undef;
	}

	$samba_tool_cmd = ${cmd_env};
	$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
	    . " spn add HOST/$srv_account --configfile=$ctx->{smb_conf} $srv_account";
	unless (system($samba_tool_cmd) == 0) {
		warn("Unable to add spn for $srv_account: \n$samba_tool_cmd\n");
		return undef;
	}

	my $ldbmodify = ${cmd_env};
	$ldbmodify .= Samba::bindir_path($self, "ldbmodify");
	$ldbmodify .=  " --configfile=$ctx->{smb_conf}";
	my $base_dn = "DC=".join(",DC=", split(/\./, $ctx->{realm}));

	if ($ctx->{server_role} ne "domain controller") {
		$base_dn = "DC=$ctx->{netbiosname}";
	}

	my $user_dn = "cn=$testallowed_account,cn=users,$base_dn";
	$testallowed_account = "testallowed account";
	open($ldif, "|$ldbmodify -H $ctx->{privatedir}/sam.ldb")
	    or die "Failed to run $ldbmodify: $!";
	print $ldif "dn: $user_dn
changetype: modify
replace: samAccountName
samAccountName: $testallowed_account
-
";
	close($ldif);
	unless ($? == 0) {
	    warn("$ldbmodify failed: $?");
	    return undef;
	}

	open($ldif, "|$ldbmodify -H $ctx->{privatedir}/sam.ldb")
            or die "Failed to run $ldbmodify: $!";
	print $ldif "dn: $user_dn
changetype: modify
replace: userPrincipalName
userPrincipalName: testallowed upn\@$ctx->{realm}
replace: servicePrincipalName
servicePrincipalName: host/testallowed
-	    
";
	close($ldif);
	unless ($? == 0) {
	    warn("$ldbmodify failed: $?");
	    return undef;
	}

	$samba_tool_cmd = ${cmd_env};
	$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
	    . " user create --configfile=$ctx->{smb_conf} testdenied $ctx->{password}";
	unless (system($samba_tool_cmd) == 0) {
		warn("Unable to add testdenied user: \n$samba_tool_cmd\n");
		return undef;
	}

	$user_dn = "cn=testdenied,cn=users,$base_dn";
        open($ldif, "|$ldbmodify -H $ctx->{privatedir}/sam.ldb")
            or die "Failed to run $ldbmodify: $!";
        print $ldif "dn: $user_dn
changetype: modify
replace: userPrincipalName
userPrincipalName: testdenied_upn\@$ctx->{realm}.upn
-	    
";
	close($ldif);
	unless ($? == 0) {
	    warn("$ldbmodify failed: $?");
	    return undef;
	}

	$samba_tool_cmd = ${cmd_env};
	$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
	    . " user create --configfile=$ctx->{smb_conf} testupnspn $ctx->{password}";
	unless (system($samba_tool_cmd) == 0) {
		warn("Unable to add testupnspn user: \n$samba_tool_cmd\n");
		return undef;
	}

	$user_dn = "cn=testupnspn,cn=users,$base_dn";
        open($ldif, "|$ldbmodify -H $ctx->{privatedir}/sam.ldb")
            or die "Failed to run $ldbmodify: $!";
        print $ldif "dn: $user_dn
changetype: modify
replace: userPrincipalName
userPrincipalName: http/testupnspn.$ctx->{dnsname}\@$ctx->{realm}
replace: servicePrincipalName
servicePrincipalName: http/testupnspn.$ctx->{dnsname}
-
";
	close($ldif);
	unless ($? == 0) {
	    warn("$ldbmodify failed: $?");
	    return undef;
	}

	$samba_tool_cmd = ${cmd_env};
	$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
	    . " group addmembers --configfile=$ctx->{smb_conf} 'Allowed RODC Password Replication Group' '$testallowed_account'";
	unless (system($samba_tool_cmd) == 0) {
		warn("Unable to add '$testallowed_account' user to 'Allowed RODC Password Replication Group': \n$samba_tool_cmd\n");
		return undef;
	}

	# Create to users alice and bob!
	my $user_account_array = ["alice", "bob", "jane", "joe"];

	foreach my $user_account (@{$user_account_array}) {
		my $samba_tool_cmd = ${cmd_env};

		$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
		    . " user create --configfile=$ctx->{smb_conf} $user_account Secret007";
		unless (system($samba_tool_cmd) == 0) {
			warn("Unable to create user: $user_account\n$samba_tool_cmd\n");
			return undef;
		}
	}

	my $group_array = ["Samba Users"];

	foreach my $group (@{$group_array}) {
		my $samba_tool_cmd = ${cmd_env};

		$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
		    . " group add --configfile=$ctx->{smb_conf} \"$group\"";
		unless (system($samba_tool_cmd) == 0) {
			warn("Unable to create group: $group\n$samba_tool_cmd\n");
			return undef;
		}
	}

	# Add user joe to group "Samba Users"
	my $group = "Samba Users";
	my $user_account = "joe";

	$samba_tool_cmd = ${cmd_env};
	$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
	    . " group addmembers --configfile=$ctx->{smb_conf} \"$group\" $user_account";
	unless (system($samba_tool_cmd) == 0) {
		warn("Unable to add " . $user_account . "to group group : $group\n$samba_tool_cmd\n");
		return undef;
	}

	$group = "Samba Users";
	$user_account = "joe";

	$samba_tool_cmd = ${cmd_env};
	$samba_tool_cmd .= Samba::bindir_path($self, "samba-tool")
	    . " user setprimarygroup --configfile=$ctx->{smb_conf} $user_account \"$group\"";
	unless (system($samba_tool_cmd) == 0) {
		warn("Unable to set primary group of user: $user_account\n$samba_tool_cmd\n");
		return undef;
	}

	# Change the userPrincipalName for jane
	$user_dn = "cn=jane,cn=users,$base_dn";

	open($ldif, "|$ldbmodify -H $ctx->{privatedir}/sam.ldb")
            or die "Failed to run $ldbmodify: $!";
        print $ldif "dn: $user_dn
changetype: modify
replace: userPrincipalName
userPrincipalName: jane.doe\@$ctx->{realm}
-
";
	close($ldif);
	unless ($? == 0) {
	    warn("$ldbmodify failed: $?");
	    return undef;
	}

	return $ret;
}

sub provision($$$$$$$$$$$)
{
	my ($self,
	    $prefix,
	    $server_role,
	    $hostname,
	    $domain,
	    $realm,
	    $functional_level,
	    $password,
	    $kdc_ipv4,
	    $kdc_ipv6,
	    $force_fips_mode,
	    $extra_smbconf_options,
	    $extra_smbconf_shares,
	    $extra_provision_options) = @_;

	my $samsid = Samba::random_domain_sid();

	my $ctx = $self->provision_raw_prepare($prefix, $server_role,
					       $hostname,
					       $domain, $realm,
					       $samsid,
					       $functional_level,
					       $password,
					       $kdc_ipv4,
					       $kdc_ipv6,
					       $force_fips_mode,
					       $extra_provision_options);

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

[xattr]
	path = $ctx->{share}
        # This can be used for testing real fs xattr stuff
	vfs objects = streams_xattr acl_xattr

$extra_smbconf_shares
";

	my $ret = $self->provision_raw_step1($ctx);
	unless (defined $ret) {
		return undef;
	}

	return $self->provision_raw_step2($ctx, $ret);
}

# For multi-DC testenvs, we want $DC_SERVER to always be the PDC (i.e. the
# original DC) in the testenv. $SERVER is always the joined DC that we are
# actually running the test against
sub set_pdc_env_vars
{
	my ($self, $env, $dcvars) = @_;

	$env->{DC_SERVER} = $dcvars->{DC_SERVER};
	$env->{DC_SERVER_IP} = $dcvars->{DC_SERVER_IP};
	$env->{DC_SERVER_IPV6} = $dcvars->{DC_SERVER_IPV6};
	$env->{DC_SERVERCONFFILE} = $dcvars->{SERVERCONFFILE};
	$env->{DC_NETBIOSNAME} = $dcvars->{DC_NETBIOSNAME};
	$env->{DC_USERNAME} = $dcvars->{DC_USERNAME};
	$env->{DC_PASSWORD} = $dcvars->{DC_PASSWORD};
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
# override the new SMB2 only default
client min protocol = CORE
server min protocol = LANMAN1
";
	if ($more_conf) {
		$extra_smb_conf = $extra_smb_conf . $more_conf . "\n";
	}
	my $extra_provision_options = ["--use-ntvfs"];
	my $ret = $self->provision($prefix,
				   "member server",
				   $hostname,
				   $dcvars->{DOMAIN},
				   $dcvars->{REALM},
				   "2008",
				   "locMEMpass3",
				   $dcvars->{SERVER_IP},
				   $dcvars->{SERVER_IPV6},
				   undef,
				   $extra_smb_conf, "",
				   $extra_provision_options);
	unless ($ret) {
		return undef;
	}

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");
	my $cmd = $self->get_cmd_env_vars($ret);
	$cmd .= "$samba_tool domain join $ret->{CONFIGURATION} $dcvars->{REALM} member";
	$cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD}";
	$cmd .= " --machinepass=machine$ret->{PASSWORD}";

	unless (system($cmd) == 0) {
		warn("Join failed\n$cmd");
		return undef;
	}

	$ret->{DOMSID} = $dcvars->{DOMSID};
	$self->set_pdc_env_vars($ret, $dcvars);

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
	dcerpc_remote:allow_anonymous_fallback = yes
	# override the new SMB2 only default
	client min protocol = CORE
	server min protocol = LANMAN1
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

	my $extra_provision_options = ["--use-ntvfs"];
	my $ret = $self->provision($prefix,
				   "member server",
				   "localrpcproxy",
				   $dcvars->{DOMAIN},
				   $dcvars->{REALM},
				   "2008",
				   "locRPCproxypass4",
				   $dcvars->{SERVER_IP},
				   $dcvars->{SERVER_IPV6},
				   undef,
				   $extra_smbconf_options, "",
				   $extra_provision_options);
	unless ($ret) {
		return undef;
	}

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");

	# The joind runs in the context of the rpc_proxy/member for now
	my $cmd = $self->get_cmd_env_vars($ret);
	$cmd .= "$samba_tool domain join $ret->{CONFIGURATION} $dcvars->{REALM} member";
	$cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD}";
	$cmd .= " --machinepass=machine$ret->{PASSWORD}";

	unless (system($cmd) == 0) {
		warn("Join failed\n$cmd");
		return undef;
	}

	# Prepare a context of the DC, but using the local CCACHE.
	my $overwrite = undef;
	$overwrite->{KRB5_CCACHE} = $ret->{KRB5_CCACHE};
	my $dc_cmd_env = $self->get_cmd_env_vars($dcvars, $overwrite);

	# Setting up delegation runs in the context of the DC for now
	$cmd = $dc_cmd_env;
	$cmd .= "$samba_tool delegation for-any-protocol '$ret->{NETBIOSNAME}\$' on";
        $cmd .= " $dcvars->{CONFIGURATION}";
        print $cmd;

	unless (system($cmd) == 0) {
		warn("Delegation failed\n$cmd");
		return undef;
	}

	# Setting up delegation runs in the context of the DC for now
	$cmd = $dc_cmd_env;
	$cmd .= "$samba_tool delegation add-service '$ret->{NETBIOSNAME}\$' cifs/$dcvars->{SERVER}";
        $cmd .= " $dcvars->{CONFIGURATION}";

	unless (system($cmd) == 0) {
		warn("Delegation failed\n$cmd");
		return undef;
	}

	$ret->{DOMSID} = $dcvars->{DOMSID};
	$self->set_pdc_env_vars($ret, $dcvars);

	return $ret;
}

sub provision_promoted_dc($$$)
{
	my ($self, $prefix, $dcvars) = @_;
	print "PROVISIONING PROMOTED DC...\n";

	# We do this so that we don't run the provision.  That's the job of 'samba-tool domain dcpromo'.
	my $ctx = $self->provision_raw_prepare($prefix, "domain controller",
					       "promotedvdc",
					       $dcvars->{DOMAIN},
					       $dcvars->{REALM},
					       $dcvars->{SAMSID},
					       "2008",
					       $dcvars->{PASSWORD},
					       $dcvars->{SERVER_IP},
					       $dcvars->{SERVER_IPV6});

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
	my $cmd = $self->get_cmd_env_vars($ret);
	$cmd .= "$samba_tool domain join $ret->{CONFIGURATION} $dcvars->{REALM} MEMBER --realm=$dcvars->{REALM}";
	$cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD}";
	$cmd .= " --machinepass=machine$ret->{PASSWORD}";

	unless (system($cmd) == 0) {
		warn("Join failed\n$cmd");
		return undef;
	}

	$samba_tool =  Samba::bindir_path($self, "samba-tool");
	$cmd = $self->get_cmd_env_vars($ret);
	$cmd .= "$samba_tool domain dcpromo $ret->{CONFIGURATION} $dcvars->{REALM} DC --realm=$dcvars->{REALM}";
	$cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD}";
	$cmd .= " --machinepass=machine$ret->{PASSWORD} --dns-backend=BIND9_DLZ";

	unless (system($cmd) == 0) {
		warn("Join failed\n$cmd");
		return undef;
	}

	$self->set_pdc_env_vars($ret, $dcvars);

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
					       $dcvars->{DOMSID},
					       $fl,
					       $dcvars->{PASSWORD},
					       $dcvars->{SERVER_IP},
					       $dcvars->{SERVER_IPV6});

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
	my $cmd = $self->get_cmd_env_vars($ret);
	$cmd .= "$samba_tool domain join $ret->{CONFIGURATION} $dcvars->{REALM} DC --realm=$dcvars->{REALM}";
	$cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD} --domain-critical-only";
	$cmd .= " --machinepass=machine$ret->{PASSWORD}";
	$cmd .= " --backend-store=mdb";

	unless (system($cmd) == 0) {
		warn("Join failed\n$cmd");
		return undef;
	}

	$self->set_pdc_env_vars($ret, $dcvars);
	$ret->{DC_REALM} = $dcvars->{DC_REALM};

	return $ret;
}

sub provision_ad_dc_ntvfs($$$)
{
	my ($self, $prefix, $extra_provision_options) = @_;

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
	dsdb event notification = true
	dsdb password event notification = true
	dsdb group change notification = true
	server schannel = auto
	# override the new SMB2 only default
	client min protocol = CORE
	server min protocol = LANMAN1
	";
	push (@{$extra_provision_options}, "--use-ntvfs");
	my $ret = $self->provision($prefix,
				   "domain controller",
				   "localdc",
				   "SAMBADOMAIN",
				   "samba.example.com",
				   "2008",
				   "locDCpass1",
				   undef,
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
	$ret->{NETBIOSALIAS} = "localdc1-a";
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
	my $extra_provision_options = ["--base-schema=2008_R2"];
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
	$ret->{DC_REALM} = $ret->{REALM};

	return $ret;
}

sub provision_fl2003dc($$$)
{
	my ($self, $prefix, $dcvars) = @_;
	my $ip_addr1 = Samba::get_ipv4_addr("fakednsforwarder1");
	my $ip_addr2 = Samba::get_ipv4_addr("fakednsforwarder2");

	print "PROVISIONING DC WITH FOREST LEVEL 2003...\n";
	my $extra_conf_options = "allow dns updates = nonsecure and secure
	dcesrv:header signing = no
	dcesrv:max auth states = 0
	dns forwarder = $ip_addr1 $ip_addr2";
	my $extra_provision_options = ["--base-schema=2008_R2"];
	my $ret = $self->provision($prefix,
				   "domain controller",
				   "dc6",
				   "SAMBA2003",
				   "samba2003.example.com",
				   "2003",
				   "locDCpass6",
				   undef,
				   undef,
				   undef,
				   $extra_conf_options,
				   "",
				   $extra_provision_options);
	unless (defined $ret) {
		return undef;
	}

	$ret->{DNS_FORWARDER1} = $ip_addr1;
	$ret->{DNS_FORWARDER2} = $ip_addr2;

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
        my $extra_conf_options = "
	ldap server require strong auth = no
        # delay by 10 seconds, 10^7 usecs
	ldap_server:delay_expire_disconnect = 10000
";
	my $extra_provision_options = ["--base-schema=2008_R2"];
	my $ret = $self->provision($prefix,
				   "domain controller",
				   "dc7",
				   "SAMBA2008R2",
				   "samba2008R2.example.com",
				   "2008_R2",
				   "locDCpass7",
				   undef,
				   undef,
				   undef,
				   $extra_conf_options,
				   "",
				   $extra_provision_options);
	unless (defined $ret) {
		return undef;
	}

	unless ($self->add_wins_config("$prefix/private")) {
		warn("Unable to add wins configuration");
		return undef;
	}
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
					       $dcvars->{DOMAIN},
					       $dcvars->{REALM},
					       $dcvars->{DOMSID},
					       "2008",
					       $dcvars->{PASSWORD},
					       $dcvars->{SERVER_IP},
					       $dcvars->{SERVER_IPV6});
	unless ($ctx) {
		return undef;
	}

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
	my $cmd = $self->get_cmd_env_vars($ret);
	$cmd .= "$samba_tool domain join $ret->{CONFIGURATION} $dcvars->{REALM} RODC";
	$cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD}";
	$cmd .= " --server=$dcvars->{DC_SERVER}";

	unless (system($cmd) == 0) {
		warn("RODC join failed\n$cmd");
		return undef;
	}

        # This ensures deterministic behaviour for tests that want to have the 'testallowed account'
        # user password verified on the RODC
	my $testallowed_account = "testallowed account";
	$cmd = $self->get_cmd_env_vars($ret);
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

	$self->set_pdc_env_vars($ret, $dcvars);

	return $ret;
}

sub read_config_h($)
{
	my ($name) = @_;
	my %ret;
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

sub provision_ad_dc($$$$$$$)
{
	my ($self,
	    $prefix,
	    $hostname,
	    $domain,
	    $realm,
	    $force_fips_mode,
	    $smbconf_args,
	    $extra_provision_options) = @_;

	my $prefix_abs = abs_path($prefix);

	my $bindir_abs = abs_path($self->{bindir});
	my $lockdir="$prefix_abs/lockdir";
        my $conffile="$prefix_abs/etc/smb.conf";

	my $require_mutexes = "dbwrap_tdb_require_mutexes:* = yes";
	if ($ENV{SELFTEST_DONT_REQUIRE_TDB_MUTEX_SUPPORT} // '' eq "1") {
		$require_mutexes = "";
	}

	my $config_h = {};

	if (defined($ENV{CONFIG_H})) {
		$config_h = read_config_h($ENV{CONFIG_H});
	}

	my $password_hash_gpg_key_ids = "password hash gpg key ids = 4952E40301FAB41A";
	$password_hash_gpg_key_ids = "" unless defined($config_h->{HAVE_GPGME});

	my $extra_smbconf_options = "
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
	dsdb event notification = true
	dsdb password event notification = true
	dsdb group change notification = true
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
[print4]
	copy = print1
	guest ok = yes
[lp]
	copy = print1
";

	push (@{$extra_provision_options}, "--backend-store=mdb");
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
				   $force_fips_mode,
				   $extra_smbconf_options,
				   $extra_smbconf_shares,
				   $extra_provision_options);
	unless (defined $ret) {
		return undef;
	}

	unless($self->add_wins_config("$prefix/private")) {
		warn("Unable to add wins configuration");
		return undef;
	}

	return $ret;
}

sub provision_chgdcpass($$)
{
	my ($self, $prefix) = @_;

	print "PROVISIONING CHGDCPASS...\n";
	# This environment disallows the use of this password
	# (and also removes the default AD complexity checks)
	my $unacceptable_password = "Paßßword-widk3Dsle32jxdBdskldsk55klASKQ";
	my $extra_smb_conf = "
	check password script = $self->{srcdir}/selftest/checkpassword_arg1.sh ${unacceptable_password}
	allow dcerpc auth level connect:lsarpc = yes
	dcesrv:max auth states = 8
";
	my $extra_provision_options = ["--dns-backend=BIND9_DLZ"];
	my $ret = $self->provision($prefix,
				   "domain controller",
				   "chgdcpass",
				   "CHDCDOMAIN",
				   "chgdcpassword.samba.example.com",
				   "2008",
				   "chgDCpass1",
				   undef,
				   undef,
				   undef,
				   $extra_smb_conf,
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

	$ret->{UNACCEPTABLE_PASSWORD} = $unacceptable_password;

	return $ret;
}

sub teardown_env_terminate($$)
{
	my ($self, $envvars) = @_;
	my $pid;

	# This should cause samba to terminate gracefully
	my $smbcontrol = Samba::bindir_path($self, "smbcontrol");
	my $cmd = "";
	$cmd .= "$smbcontrol samba shutdown $envvars->{CONFIGURATION}";
	my $ret = system($cmd);
	if ($ret != 0) {
		warn "'$cmd' failed with '$ret'\n";
	}

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
# The interdependencies between the testenvs are declared below. Some testenvs
# are dependent on another testenv running first, e.g. vampire_dc is dependent
# on ad_dc_ntvfs because vampire_dc joins ad_dc_ntvfs's domain. All DCs are
# dependent on dns_hub, which handles resolving DNS queries for the realm.
%Samba4::ENV_DEPS = (
	# name               => [dep_1, dep_2, ...],
	dns_hub              => [],
	ad_dc_ntvfs          => ["dns_hub"],
	ad_dc_fips           => ["dns_hub"],
	ad_dc                => ["dns_hub"],
	ad_dc_smb1           => ["dns_hub"],
	ad_dc_smb1_done      => ["ad_dc_smb1"],
	ad_dc_no_nss         => ["dns_hub"],
	ad_dc_no_ntlm        => ["dns_hub"],

	fl2008r2dc           => ["ad_dc"],
	fl2003dc             => ["ad_dc"],
	fl2000dc             => ["dns_hub"],

	vampire_2000_dc      => ["fl2000dc"],
	vampire_dc           => ["ad_dc_ntvfs"],
	promoted_dc          => ["ad_dc_ntvfs"],

	rodc                 => ["ad_dc_ntvfs"],
	rpc_proxy            => ["ad_dc_ntvfs"],
	chgdcpass            => ["dns_hub"],

	s4member_dflt_domain => ["ad_dc_ntvfs"],
	s4member             => ["ad_dc_ntvfs"],

	# envs that test the server process model
	proclimitdc          => ["dns_hub"],
	preforkrestartdc     => ["dns_hub"],

	# backup/restore testenvs
	backupfromdc         => ["dns_hub"],
	customdc             => ["dns_hub"],
	restoredc            => ["backupfromdc"],
	renamedc             => ["backupfromdc"],
	offlinebackupdc      => ["backupfromdc"],
	labdc                => ["backupfromdc"],

	# aliases in order to split autbuild tasks
	fl2008dc             => ["ad_dc"],
	ad_dc_default        => ["ad_dc"],
	ad_dc_default_smb1   => ["ad_dc_smb1"],
	ad_dc_default_smb1_done   => ["ad_dc_default_smb1"],
	ad_dc_slowtests      => ["ad_dc"],
	ad_dc_backup         => ["ad_dc"],

	schema_dc      => ["dns_hub"],
	schema_pair_dc => ["schema_dc"],

	none                 => [],
);

%Samba4::ENV_DEPS_POST = (
	schema_dc => ["schema_pair_dc"],
);

sub return_alias_env
{
	my ($self, $path, $env) = @_;

	# just an alias
	return $env;
}

sub setup_fl2008dc
{
	my ($self, $path) = @_;

	my $extra_args = ["--base-schema=2008_R2"];
	my $env = $self->provision_ad_dc_ntvfs($path, $extra_args);
	if (defined $env) {
	        if (not defined($self->check_or_start($env, "standard"))) {
		    warn("Failed to start fl2008dc");
		        return undef;
		}
	}
	return $env;
}

sub setup_ad_dc_default
{
	my ($self, $path, $dep_env) = @_;
	return $self->return_alias_env($path, $dep_env)
}

sub setup_ad_dc_default_smb1
{
	my ($self, $path, $dep_env) = @_;
	return $self->return_alias_env($path, $dep_env)
}

sub setup_ad_dc_default_smb1_done
{
	my ($self, $path, $dep_env) = @_;
	return $self->return_alias_env($path, $dep_env)
}

sub setup_ad_dc_slowtests
{
	my ($self, $path, $dep_env) = @_;
	return $self->return_alias_env($path, $dep_env)
}

sub setup_ad_dc_backup
{
	my ($self, $path, $dep_env) = @_;
	return $self->return_alias_env($path, $dep_env)
}

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

	my $env = $self->provision_ad_dc_ntvfs($path, undef);
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
		my $cmd = $self->get_cmd_env_vars($env);
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
		$base_dn = "DC=".join(",DC=", split(/\./, $dc_vars->{REALM}));
		$cmd = $self->get_cmd_env_vars($env);
		$cmd .= " $samba_tool drs replicate $env->{SERVER} $env->{DC_SERVER}";
		$cmd .= " $dc_vars->{CONFIGURATION}";
		$cmd .= " -U$dc_vars->{DC_USERNAME}\%$dc_vars->{DC_PASSWORD}";
		# replicate Configuration NC
		$cmd_repl = "$cmd \"CN=Configuration,$base_dn\"";
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
		my $cmd = $self->get_cmd_env_vars($env);
		# as 'vampired' dc may add data in its local replica
		# we need to synchronize data between DCs
		my $base_dn = "DC=".join(",DC=", split(/\./, $dc_vars->{REALM}));
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
	my $cmd = $self->get_cmd_env_vars($env);

	my $base_dn = "DC=".join(",DC=", split(/\./, $dc_vars->{REALM}));
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

sub _setup_ad_dc
{
	my ($self, $path, $conf_opts, $server, $dom) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->{target3}->have_ads()) {
	       return "UNKNOWN";
	}

	if (!defined($conf_opts)) {
		$conf_opts = "";
	}
	if (!defined($server)) {
		$server = "addc";
	}
	if (!defined($dom)) {
		$dom = "addom.samba.example.com";
	}
	my $env = $self->provision_ad_dc($path, $server, "ADDOMAIN",
					 $dom,
					 undef,
					 $conf_opts,
					 undef);
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

sub setup_ad_dc
{
	my ($self, $path) = @_;
	return _setup_ad_dc($self, $path, undef, undef, undef);
}

sub setup_ad_dc_smb1
{
	my ($self, $path) = @_;
	my $conf_opts = "
[global]
	client min protocol = CORE
	server min protocol = LANMAN1
";
	return _setup_ad_dc($self, $path, $conf_opts, "addcsmb1", "addom2.samba.example.com");
}

sub setup_ad_dc_smb1_done
{
	my ($self, $path, $dep_env) = @_;
	return $self->return_alias_env($path, $dep_env);
}

sub setup_ad_dc_no_nss
{
	my ($self, $path) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->{target3}->have_ads()) {
	       return "UNKNOWN";
	}

	my $env = $self->provision_ad_dc($path,
					 "addc_no_nss",
					 "ADNONSSDOMAIN",
					 "adnonssdom.samba.example.com",
					 undef,
					 "",
					 undef);
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

	my $env = $self->provision_ad_dc($path,
					 "addc_no_ntlm",
					 "ADNONTLMDOMAIN",
					 "adnontlmdom.samba.example.com",
					 undef,
					 "ntlm auth = disabled",
					 undef);
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

sub setup_ad_dc_fips
{
	my ($self, $path) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->{target3}->have_ads()) {
	       return "UNKNOWN";
	}

	my $env = $self->provision_ad_dc($path,
					 "fipsdc",
					 "FIPSDOMAIN",
					 "fips.samba.example.com",
					 1,
					 "",
					 undef);
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

#
# AD DC test environment used solely to test pre-fork process restarts.
# As processes get killed off and restarted it should not be used for other
sub setup_preforkrestartdc
{
	my ($self, $path) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->{target3}->have_ads()) {
	       return "UNKNOWN";
	}

	# note DC name must be <= 15 chars so we use 'prockill' instead of
	# 'preforkrestart'
	my $env = $self->provision_ad_dc($path,
					 "prockilldc",
					 "PROCKILLDOMAIN",
					 "prockilldom.samba.example.com",
					 undef,
					 "prefork backoff increment = 5\nprefork maximum backoff=10",
					 undef);
	unless ($env) {
		return undef;
	}

	$env->{NSS_WRAPPER_MODULE_SO_PATH} = undef;
	$env->{NSS_WRAPPER_MODULE_FN_PREFIX} = undef;

	if (not defined($self->check_or_start($env, "prefork"))) {
	    return undef;
	}

	my $upn_array = ["$env->{REALM}.upn"];
	my $spn_array = ["$env->{REALM}.spn"];

	$self->setup_namespaces($env, $upn_array, $spn_array);

	return $env;
}

#
# ad_dc test environment used solely to test standard process model connection
# process limits. As the limit is set artificially low it should not be used
# for other tests.
sub setup_proclimitdc
{
	my ($self, $path) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->{target3}->have_ads()) {
	       return "UNKNOWN";
	}

	my $env = $self->provision_ad_dc($path,
					 "proclimitdc",
					 "PROCLIMITDOM",
					 "proclimit.samba.example.com",
					 undef,
					 "max smbd processes = 20",
					 undef);
	unless ($env) {
		return undef;
	}

	$env->{NSS_WRAPPER_MODULE_SO_PATH} = undef;
	$env->{NSS_WRAPPER_MODULE_FN_PREFIX} = undef;

	if (not defined($self->check_or_start($env, "standard"))) {
	    return undef;
	}

	my $upn_array = ["$env->{REALM}.upn"];
	my $spn_array = ["$env->{REALM}.spn"];

	$self->setup_namespaces($env, $upn_array, $spn_array);

	return $env;
}

# Used to test a live upgrade of the schema on a 2 DC network.
sub setup_schema_dc
{
	my ($self, $path) = @_;

	# provision the PDC using an older base schema
	my $provision_args = ["--base-schema=2008_R2", "--backend-store=mdb"];

	my $env = $self->provision_ad_dc($path,
					 "liveupgrade1dc",
					 "SCHEMADOMAIN",
					 "schema.samba.example.com",
					 undef,
					 "drs: max link sync = 2",
					 $provision_args);
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

# the second DC in the live schema upgrade pair
sub setup_schema_pair_dc
{
	# note: dcvars contains the env info for the dependent testenv ('schema_dc')
	my ($self, $prefix, $dcvars) = @_;
	print "Preparing SCHEMA UPGRADE PAIR DC...\n";

	my ($env, $ctx) = $self->prepare_dc_testenv($prefix, "liveupgrade2dc",
						    $dcvars->{DOMAIN},
						    $dcvars->{REALM},
						    $dcvars->{PASSWORD},
						    "");

	my $samba_tool =  Samba::bindir_path($self, "samba-tool");
	my $cmd_vars = $self->get_cmd_env_vars($env);

	my $join_cmd = $cmd_vars;
	$join_cmd .= "$samba_tool domain join $env->{CONFIGURATION} $dcvars->{REALM} DC --realm=$dcvars->{REALM}";
	$join_cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD} ";
	$join_cmd .= " --backend-store=mdb";

	my $upgrade_cmd = $cmd_vars;
	$upgrade_cmd .= "$samba_tool domain schemaupgrade $dcvars->{CONFIGURATION}";
	$upgrade_cmd .= " -U$dcvars->{USERNAME}\%$dcvars->{PASSWORD}";

	my $repl_cmd = $cmd_vars;
	$repl_cmd .= "$samba_tool drs replicate $env->{SERVER} $dcvars->{SERVER}";
        $repl_cmd .= " CN=Schema,CN=Configuration,DC=schema,DC=samba,DC=example,DC=com";
	$repl_cmd .= " -U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD}";

	unless (system($join_cmd) == 0) {
		warn("Join failed\n$join_cmd");
		return undef;
	}

	$env->{DC_SERVER} = $dcvars->{SERVER};
	$env->{DC_SERVER_IP} = $dcvars->{SERVER_IP};
	$env->{DC_SERVER_IPV6} = $dcvars->{SERVER_IPV6};
	$env->{DC_NETBIOSNAME} = $dcvars->{NETBIOSNAME};

	# start samba for the new DC
	if (not defined($self->check_or_start($env, "standard"))) {
	    return undef;
	}

	unless (system($upgrade_cmd) == 0) {
		warn("Schema upgrade failed\n$upgrade_cmd");
		return undef;
	}

	unless (system($repl_cmd) == 0) {
		warn("Post-update schema replication failed\n$repl_cmd");
		return undef;
	}

	return $env;
}

# Sets up a DC that's solely used to do a domain backup from. We then use the
# backupfrom-DC to create the restore-DC - this proves that the backup/restore
# process will create a Samba DC that will actually start up.
# We don't use the backup-DC for anything else because its domain will conflict
# with the restore DC.
sub setup_backupfromdc
{
	my ($self, $path) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->{target3}->have_ads()) {
	       return "UNKNOWN";
	}

	my $provision_args = ["--site=Backup-Site"];

	my $env = $self->provision_ad_dc($path,
					 "backupfromdc",
					 "BACKUPDOMAIN",
					 "backupdom.samba.example.com",
					 undef,
					 "samba kcc command = /bin/true",
					 $provision_args);
	unless ($env) {
		return undef;
	}

	if (not defined($self->check_or_start($env))) {
	    return undef;
	}

	my $upn_array = ["$env->{REALM}.upn"];
	my $spn_array = ["$env->{REALM}.spn"];

	$self->setup_namespaces($env, $upn_array, $spn_array);

	# Set up a dangling forward link to an expunged object
	#
	# We need this to ensure that the "samba-tool domain backup rename"
	# that is part of the creation of the labdc environment can
	# cope with this situation on the source DC.

	if (not $self->write_ldb_file("$env->{PRIVATEDIR}/sam.ldb", "
dn: ou=linktest,dc=backupdom,dc=samba,dc=example,dc=com
objectclass: organizationalUnit
-

dn: cn=linkto,ou=linktest,dc=backupdom,dc=samba,dc=example,dc=com
objectclass: msExchConfigurationContainer
-

dn: cn=linkfrom,ou=linktest,dc=backupdom,dc=samba,dc=example,dc=com
objectclass: msExchConfigurationContainer
addressBookRoots: cn=linkto,ou=linktest,dc=backupdom,dc=samba,dc=example,dc=com
-

")) {
	    return undef;
	}
	my $ldbdel = Samba::bindir_path($self, "ldbdel");
	my $cmd = "$ldbdel -H $env->{PRIVATEDIR}/sam.ldb cn=linkto,ou=linktest,dc=backupdom,dc=samba,dc=example,dc=com";

	unless(system($cmd) == 0) {
		warn("Failed to delete link target: \n$cmd");
		return undef;
	}

	# Expunge will ensure that linkto is totally wiped from the DB
	my $samba_tool = Samba::bindir_path($self, "samba-tool");
	$cmd = "$samba_tool  domain tombstones expunge --tombstone-lifetime=0 $env->{CONFIGURATION}";

	unless(system($cmd) == 0) {
		warn("Failed to expunge link target: \n$cmd");
		return undef;
	}
	return $env;
}

# returns the server/user-auth params needed to run an online backup cmd
sub get_backup_server_args
{
	# dcvars contains the env info for the backup DC testenv
	my ($self, $dcvars) = @_;
	my $server = $dcvars->{DC_SERVER_IP};
	my $server_args = "--server=$server ";
	$server_args .= "-U$dcvars->{DC_USERNAME}\%$dcvars->{DC_PASSWORD}";
	$server_args .= " $dcvars->{CONFIGURATION}";

	return $server_args;
}

# Creates a backup of a running testenv DC
sub create_backup
{
	# note: dcvars contains the env info for the backup DC testenv
	my ($self, $env, $dcvars, $backupdir, $backup_cmd) = @_;

	# get all the env variables we pass in with the samba-tool command
	# Note: use the backupfrom-DC's krb5.conf to do the backup
	my $overwrite = undef;
	$overwrite->{KRB5_CONFIG} = $dcvars->{KRB5_CONFIG};
	my $cmd_env = $self->get_cmd_env_vars($env, $overwrite);

	# use samba-tool to create a backup from the 'backupfromdc' DC
	my $cmd = "";
	my $samba_tool = Samba::bindir_path($self, "samba-tool");

	$cmd .= "$cmd_env $samba_tool domain backup $backup_cmd";
	$cmd .= " --targetdir=$backupdir";

	print "Executing: $cmd\n";
	unless(system($cmd) == 0) {
		warn("Failed to create backup using: \n$cmd");
		return undef;
	}

	# get the name of the backup file created
	opendir(DIR, $backupdir);
	my @files = grep(/\.tar/, readdir(DIR));
	closedir(DIR);

	if(scalar @files != 1) {
		warn("Backup file not found in directory $backupdir\n");
		return undef;
	}
	my $backup_file = "$backupdir/$files[0]";
	print "Using backup file $backup_file...\n";

	return $backup_file;
}

# Restores a backup-file to populate a testenv for a new DC
sub restore_backup_file
{
	my ($self, $backup_file, $restore_opts, $restoredir, $smbconf) = @_;

	# pass the restore command the testenv's smb.conf that we've already
	# generated. But move it to a temp-dir first, so that the restore doesn't
	# overwrite it
	my $tmpdir = File::Temp->newdir();
	my $tmpconf = "$tmpdir/smb.conf";
	my $cmd = "cp $smbconf $tmpconf";
	unless(system($cmd) == 0) {
		warn("Failed to backup smb.conf using: \n$cmd");
		return -1;
	}

	my $samba_tool = Samba::bindir_path($self, "samba-tool");
	$cmd = "$samba_tool domain backup restore --backup-file=$backup_file";
	$cmd .= " --targetdir=$restoredir $restore_opts --configfile=$tmpconf";

	print "Executing: $cmd\n";
	unless(system($cmd) == 0) {
		warn("Failed to restore backup using: \n$cmd");
		return -1;
	}

	print "Restore complete\n";
	return 0
}

# sets up the initial directory and returns the new testenv's env info
# (without actually doing a 'domain join')
sub prepare_dc_testenv
{
	my ($self, $prefix, $dcname, $domain, $realm,
		$password, $conf_options, $dnsupdate_options) = @_;

	my $ctx = $self->provision_raw_prepare($prefix, "domain controller",
					       $dcname,
					       $domain,
					       $realm,
					       undef,
					       "2008",
					       $password,
					       undef,
					       undef);

	# the restore uses a slightly different state-dir location to other testenvs
	$ctx->{statedir} = "$ctx->{prefix_abs}/state";
	push(@{$ctx->{directories}}, "$ctx->{statedir}");

	# add support for sysvol/netlogon/tmp shares
	$ctx->{share} = "$ctx->{prefix_abs}/share";
	push(@{$ctx->{directories}}, "$ctx->{share}");
	push(@{$ctx->{directories}}, "$ctx->{share}/test1");

	if (defined($dnsupdate_options)) {
		$ctx->{samba_dnsupdate} .= $dnsupdate_options;
	}

	$ctx->{smb_conf_extra_options} = "
	$conf_options
	max xmit = 32K
	server max protocol = SMB2
	samba kcc command = /bin/true
	xattr_tdb:file = $ctx->{statedir}/xattr.tdb

[sysvol]
	path = $ctx->{statedir}/sysvol
	read only = no

[netlogon]
	path = $ctx->{statedir}/sysvol/$ctx->{dnsname}/scripts
	read only = no

[tmp]
	path = $ctx->{share}
	read only = no
	posix:sharedelay = 10000
	posix:oplocktimeout = 3
	posix:writetimeupdatedelay = 50000

[test1]
	path = $ctx->{share}/test1
	read only = no
	posix:sharedelay = 100000
	posix:oplocktimeout = 3
	posix:writetimeupdatedelay = 500000
";

	my $env = $self->provision_raw_step1($ctx);

    return ($env, $ctx);
}


# Set up a DC testenv solely by using the samba-tool domain backup/restore
# commands. This proves that we can backup an online DC ('backupfromdc') and
# use the backup file to create a valid, working samba DC.
sub setup_restoredc
{
	# note: dcvars contains the env info for the dependent testenv ('backupfromdc')
	my ($self, $prefix, $dcvars) = @_;
	print "Preparing RESTORE DC...\n";

	# we arbitrarily designate the restored DC as having SMBv1 disabled
	my $extra_conf = "
	server min protocol = SMB2
	client min protocol = SMB2
	prefork children = 1";
	my $dnsupdate_options = " --use-samba-tool --no-credentials";

	my ($env, $ctx) = $self->prepare_dc_testenv($prefix, "restoredc",
						    $dcvars->{DOMAIN},
						    $dcvars->{REALM},
						    $dcvars->{PASSWORD},
						    $extra_conf,
						    $dnsupdate_options);

	# create a backup of the 'backupfromdc'
	my $backupdir = File::Temp->newdir();
	my $server_args = $self->get_backup_server_args($dcvars);
	my $backup_args = "online $server_args";
	my $backup_file = $self->create_backup($env, $dcvars, $backupdir,
					       $backup_args);
	unless($backup_file) {
		return undef;
	}

	# restore the backup file to populate the restore-DC testenv
	my $restore_dir = abs_path($prefix);
	my $ret = $self->restore_backup_file($backup_file,
					     "--newservername=$env->{SERVER}",
					     $restore_dir, $env->{SERVERCONFFILE});
	unless ($ret == 0) {
		return undef;
	}

	#
	# As we create a the same domain as a clone
	# we need a separate resolv.conf!
	#
	$ctx->{resolv_conf} = "$ctx->{etcdir}/resolv.conf";
	$ctx->{dns_ipv4} = $ctx->{ipv4};
	$ctx->{dns_ipv6} = $ctx->{ipv6};
	Samba::mk_resolv_conf($ctx);
	$env->{RESOLV_CONF} = $ctx->{resolv_conf};

	# start samba for the restored DC
	if (not defined($self->check_or_start($env))) {
	    return undef;
	}

	return $env;
}

# Set up a DC testenv solely by using the 'samba-tool domain backup rename' and
# restore commands. This proves that we can backup and rename an online DC
# ('backupfromdc') and use the backup file to create a valid, working samba DC.
sub setup_renamedc
{
	# note: dcvars contains the env info for the dependent testenv ('backupfromdc')
	my ($self, $prefix, $dcvars) = @_;
	print "Preparing RENAME DC...\n";
	my $extra_conf = "prefork children = 1";

	my $realm = "renamedom.samba.example.com";
	my ($env, $ctx) = $self->prepare_dc_testenv($prefix, "renamedc",
						    "RENAMEDOMAIN", $realm,
						    $dcvars->{PASSWORD}, $extra_conf);

	# create a backup of the 'backupfromdc' which renames the domain
	my $backupdir = File::Temp->newdir();
	my $server_args = $self->get_backup_server_args($dcvars);
	my $backup_args = "rename $env->{DOMAIN} $env->{REALM} $server_args";
	$backup_args .= " --backend-store=tdb";
	my $backup_file = $self->create_backup($env, $dcvars, $backupdir,
					       $backup_args);
	unless($backup_file) {
		return undef;
	}

	# restore the backup file to populate the rename-DC testenv
	my $restore_dir = abs_path($prefix);
	my $restore_opts =  "--newservername=$env->{SERVER} --host-ip=$env->{SERVER_IP}";
	my $ret = $self->restore_backup_file($backup_file, $restore_opts,
					     $restore_dir, $env->{SERVERCONFFILE});
	unless ($ret == 0) {
		return undef;
	}

	# start samba for the restored DC
	if (not defined($self->check_or_start($env))) {
	    return undef;
	}

	my $upn_array = ["$env->{REALM}.upn"];
	my $spn_array = ["$env->{REALM}.spn"];

	$self->setup_namespaces($env, $upn_array, $spn_array);

	return $env;
}

# Set up a DC testenv solely by using the 'samba-tool domain backup offline' and
# restore commands. This proves that we do an offline backup of a local DC
# ('backupfromdc') and use the backup file to create a valid, working samba DC.
sub setup_offlinebackupdc
{
	# note: dcvars contains the env info for the dependent testenv ('backupfromdc')
	my ($self, $prefix, $dcvars) = @_;
	print "Preparing OFFLINE BACKUP DC...\n";
	my $extra_conf = "prefork children = 1";
	my $dnsupdate_options = " --use-samba-tool --no-credentials";

	my ($env, $ctx) = $self->prepare_dc_testenv($prefix, "offlinebackupdc",
						    $dcvars->{DOMAIN},
						    $dcvars->{REALM},
						    $dcvars->{PASSWORD},
						    $extra_conf,
						    $dnsupdate_options);

	# create an offline backup of the 'backupfromdc' target
	my $backupdir = File::Temp->newdir();
	my $cmd = "offline -s $dcvars->{SERVERCONFFILE}";
	my $backup_file = $self->create_backup($env, $dcvars,
					       $backupdir, $cmd);

	unless($backup_file) {
		return undef;
	}

	# restore the backup file to populate the rename-DC testenv
	my $restore_dir = abs_path($prefix);
	my $restore_opts =  "--newservername=$env->{SERVER} --host-ip=$env->{SERVER_IP}";
	my $ret = $self->restore_backup_file($backup_file, $restore_opts,
					     $restore_dir, $env->{SERVERCONFFILE});
	unless ($ret == 0) {
		return undef;
	}

	#
	# As we create a the same domain as a clone
	# we need a separate resolv.conf!
	#
	$ctx->{resolv_conf} = "$ctx->{etcdir}/resolv.conf";
	$ctx->{dns_ipv4} = $ctx->{ipv4};
	$ctx->{dns_ipv6} = $ctx->{ipv6};
	Samba::mk_resolv_conf($ctx);
	$env->{RESOLV_CONF} = $ctx->{resolv_conf};

	# re-create the testenv's krb5.conf (the restore may have overwritten it)
	Samba::mk_krb5_conf($ctx);

	# start samba for the restored DC
	if (not defined($self->check_or_start($env))) {
	    return undef;
	}

	return $env;
}

# Set up a DC testenv solely by using the samba-tool 'domain backup rename' and
# restore commands, using the --no-secrets option. This proves that we can
# create a realistic lab environment from an online DC ('backupfromdc').
sub setup_labdc
{
	# note: dcvars contains the env info for the dependent testenv ('backupfromdc')
	my ($self, $prefix, $dcvars) = @_;
	print "Preparing LAB-DOMAIN DC...\n";
	my $extra_conf = "prefork children = 1";

	my ($env, $ctx) = $self->prepare_dc_testenv($prefix, "labdc",
						    "LABDOMAIN",
						    "labdom.samba.example.com",
						    $dcvars->{PASSWORD}, $extra_conf);

	# create a backup of the 'backupfromdc' which renames the domain and uses
	# the --no-secrets option to scrub any sensitive info
	my $backupdir = File::Temp->newdir();
	my $server_args = $self->get_backup_server_args($dcvars);
	my $backup_args = "rename $env->{DOMAIN} $env->{REALM} $server_args";
	$backup_args .= " --no-secrets --backend-store=mdb";
	my $backup_file = $self->create_backup($env, $dcvars, $backupdir,
					       $backup_args);
	unless($backup_file) {
		return undef;
	}

	# restore the backup file to populate the lab-DC testenv
	my $restore_dir = abs_path($prefix);
	my $restore_opts =  "--newservername=$env->{SERVER} --host-ip=$env->{SERVER_IP}";
	my $ret = $self->restore_backup_file($backup_file, $restore_opts,
					     $restore_dir, $env->{SERVERCONFFILE});
	unless ($ret == 0) {
		return undef;
	}

	# because we don't include any secrets in the backup, we need to reset the
	# admin user's password back to what the testenv expects
	my $samba_tool = Samba::bindir_path($self, "samba-tool");
	my $cmd = "$samba_tool user setpassword $env->{USERNAME} ";
	$cmd .= "--newpassword=$env->{PASSWORD} -H $restore_dir/private/sam.ldb";
	$cmd .= " $env->{CONFIGURATION}";

	unless(system($cmd) == 0) {
		warn("Failed to reset admin's password: \n$cmd");
		return undef;
	}

	# start samba for the restored DC
	if (not defined($self->check_or_start($env))) {
	    return undef;
	}

	my $upn_array = ["$env->{REALM}.upn"];
	my $spn_array = ["$env->{REALM}.spn"];

	$self->setup_namespaces($env, $upn_array, $spn_array);

	return $env;
}

# Inspects a backup *.tar.bz2 file and determines the realm/domain it contains
sub get_backup_domain_realm
{
	my ($self, $backup_file) = @_;

	print "Determining REALM/DOMAIN values in backup...\n";

	# The backup will have the correct domain/realm values in the smb.conf.
	# So we can work out the env variables the testenv should use based on
	# that. Let's start by extracting the smb.conf
	my $tar = Archive::Tar->new($backup_file);
	my $tmpdir = File::Temp->newdir();
	my $smbconf = "$tmpdir/smb.conf";

	# note that the filepaths within the tar-file differ slightly for online
	# and offline backups
	if ($tar->contains_file("etc/smb.conf")) {
		$tar->extract_file("etc/smb.conf", $smbconf);
	} elsif ($tar->contains_file("./etc/smb.conf")) {
		$tar->extract_file("./etc/smb.conf", $smbconf);
	} else {
		warn("Could not find smb.conf in $backup_file");
		return undef, undef;
	}

	# make sure we don't try to create locks/sockets in the default install
	# location (i.e. /usr/local/samba/)
	my $options = "--option=\"private dir = $tmpdir\"";
	$options .=  " --option=\"lock dir = $tmpdir\"";

	# now use testparm to read the values we're interested in
	my $testparm = Samba::bindir_path($self, "testparm");
	my $domain = `$testparm $smbconf -sl --parameter-name=WORKGROUP $options`;
	my $realm = `$testparm $smbconf -sl --parameter-name=REALM $options`;
	chomp $realm;
	chomp $domain;
	print "Backup-file REALM is $realm, DOMAIN is $domain\n";

	return ($domain, $realm);
}

# This spins up a custom testenv that can be based on any backup-file you want.
# This is just intended for manual testing (rather than automated test-cases)
sub setup_customdc
{
	my ($self, $prefix) = @_;
	print "Preparing CUSTOM RESTORE DC...\n";
	my $dc_name = "customdc";
	my $password = "locDCpass1";
	my $backup_file = $ENV{'BACKUP_FILE'};
	my $dnsupdate_options = " --use-samba-tool --no-credentials";

	# user must specify a backup file to restore via an ENV variable, i.e.
	# BACKUP_FILE=backup-blah.tar.bz2 SELFTEST_TESTENV=customdc make testenv
	if (not defined($backup_file)) {
		warn("Please specify BACKUP_FILE");
		return undef;
	}

	# work out the correct domain/realm env values from the backup-file
	my ($domain, $realm) = $self->get_backup_domain_realm($backup_file);
	if ($domain eq '' or $realm eq '') {
		warn("Could not determine domain or realm");
		return undef;
	}

	# create a placeholder directory and smb.conf, as well as the env vars.
	my ($env, $ctx) = $self->prepare_dc_testenv($prefix, $dc_name,
						    $domain, $realm, $password, "",
						    $dnsupdate_options);

	# restore the specified backup file to populate the testenv
	my $restore_dir = abs_path($prefix);
	my $ret = $self->restore_backup_file($backup_file,
					     "--newservername=$env->{SERVER}",
					     $restore_dir, $env->{SERVERCONFFILE});
	unless ($ret == 0) {
		return undef;
	}

	#
	# As we create a the same domain as a clone
	# we need a separate resolv.conf!
	#
	$ctx->{resolv_conf} = "$ctx->{etcdir}/resolv.conf";
	$ctx->{dns_ipv4} = $ctx->{ipv4};
	$ctx->{dns_ipv6} = $ctx->{ipv6};
	Samba::mk_resolv_conf($ctx);
	$env->{RESOLV_CONF} = $ctx->{resolv_conf};

	# Change the admin password to the testenv default, just in case it's
	# different, or in case this was a --no-secrets backup
	my $samba_tool = Samba::bindir_path($self, "samba-tool");
	my $cmd = "$samba_tool user setpassword $env->{USERNAME} ";
	$cmd .= "--newpassword=$password -H $restore_dir/private/sam.ldb";
	$cmd .= " $env->{CONFIGURATION}";

	unless(system($cmd) == 0) {
		warn("Failed to reset admin's password: \n$cmd");
		return undef;
	}

	# re-create the testenv's krb5.conf (the restore may have overwritten it,
	# if the backup-file was an offline backup)
	Samba::mk_krb5_conf($ctx);

	# start samba for the restored DC
	if (not defined($self->check_or_start($env))) {
	    return undef;
	}

	# if this was a backup-rename, then we may need to setup namespaces
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
