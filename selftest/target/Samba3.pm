#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

# NOTE: Refer to the README for more details about the various testenvs,
# and tips about adding new testenvs.

package Samba3;

use strict;
use warnings;
use Cwd qw(abs_path);
use FindBin qw($RealBin);
use POSIX;
use target::Samba;
use File::Path 'remove_tree';

sub return_alias_env
{
	my ($self, $path, $env) = @_;

	# just an alias
	return $env;
}

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
		$mods .= "streams_xattr btrfs";
	}

	if ($mods) {
		return "vfs objects = $mods";
	}

	return '';
}

sub new($$) {
	my ($classname, $SambaCtx, $bindir, $srcdir, $server_maxtime) = @_;
	my $self = { vars => {},
		     SambaCtx => $SambaCtx,
		     bindir => $bindir,
		     srcdir => $srcdir,
		     server_maxtime => $server_maxtime
	};
	bless $self;
	return $self;
}

sub teardown_env($$)
{
	my ($self, $envvars) = @_;

	if (defined($envvars->{CTDB_PREFIX})) {
		$self->teardown_env_ctdb($envvars);
	} else {
		$self->teardown_env_samba($envvars);
	}

	return;
}

sub teardown_env_samba($$)
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

sub teardown_env_ctdb($$)
{
	my ($self, $data) = @_;

	if (defined($data->{SAMBA_NODES})) {
		my $num_nodes = $data->{NUM_NODES};
		my $nodes = $data->{SAMBA_NODES};

		for (my $i = 0; $i < $num_nodes; $i++) {
			if (defined($nodes->[$i])) {
				$self->teardown_env_samba($nodes->[$i]);
			}
		}
	}

	close($data->{CTDB_STDIN_PIPE});

	if (not defined($data->{SAMBA_NODES})) {
		# Give waiting children time to exit
		sleep(5);
	}

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

# Declare the environments Samba3 makes available.
# To be set up, they will be called as
#   samba3->setup_$envname($self, $path, $dep_1_vars, $dep_2_vars, ...)
%Samba3::ENV_DEPS = (
	# name              => [dep_1, dep_2, ...],
	nt4_dc              => [],
	nt4_dc_smb1         => [],
	nt4_dc_smb1_done    => ["nt4_dc_smb1"],
	nt4_dc_schannel     => [],

	simpleserver        => [],
	fileserver          => [],
	fileserver_smb1     => [],
	fileserver_smb1_done => ["fileserver_smb1"],
	maptoguest          => [],
	ktest               => [],

	nt4_member          => ["nt4_dc"],

	ad_member           => ["ad_dc", "fl2008r2dc", "fl2003dc"],
	ad_member_rfc2307   => ["ad_dc_ntvfs"],
	ad_member_idmap_rid => ["ad_dc"],
	ad_member_idmap_ad  => ["fl2008r2dc"],
	ad_member_fips      => ["ad_dc_fips"],

	clusteredmember_smb1 => ["nt4_dc"],
);

%Samba3::ENV_DEPS_POST = ();

sub setup_nt4_dc
{
	my ($self, $path, $more_conf, $server) = @_;

	print "PROVISIONING NT4 DC...";

	my $nt4_dc_options = "
	domain master = yes
	domain logons = yes
	lanman auth = yes
	ntlm auth = yes
	raw NTLMv2 auth = yes
	server schannel = auto

	rpc_server:epmapper = external
	rpc_server:spoolss = external
	rpc_server:lsarpc = external
	rpc_server:samr = external
	rpc_server:netlogon = external
	rpc_server:register_embedded_np = yes
	rpc_server:FssagentRpc = external

	rpc_daemon:epmd = fork
	rpc_daemon:spoolssd = fork
	rpc_daemon:lsasd = fork
	rpc_daemon:fssd = fork
	fss: sequence timeout = 1
	check parent directory delete on close = yes
";

	if (defined($more_conf)) {
		$nt4_dc_options = $nt4_dc_options . $more_conf;
	}
	if (!defined($server)) {
		$server = "LOCALNT4DC2";
	}
	my $vars = $self->provision(
	    prefix => $path,
	    domain => "SAMBA-TEST",
	    server => $server,
	    password => "localntdc2pass",
	    extra_options => $nt4_dc_options);

	$vars or return undef;

	if (not $self->check_or_start(
		env_vars => $vars,
		nmbd => "yes",
		winbindd => "yes",
		smbd => "yes")) {
	       return undef;
	}

	$vars->{DOMSID} = $vars->{SAMSID};
	$vars->{DC_SERVER} = $vars->{SERVER};
	$vars->{DC_SERVER_IP} = $vars->{SERVER_IP};
	$vars->{DC_SERVER_IPV6} = $vars->{SERVER_IPV6};
	$vars->{DC_NETBIOSNAME} = $vars->{NETBIOSNAME};
	$vars->{DC_USERNAME} = $vars->{USERNAME};
	$vars->{DC_PASSWORD} = $vars->{PASSWORD};

	return $vars;
}

sub setup_nt4_dc_smb1
{
	my ($self, $path) = @_;
	my $conf = "
[global]
	client min protocol = CORE
	server min protocol = LANMAN1
";
	return $self->setup_nt4_dc($path, $conf, "LCLNT4DC2SMB1");
}

sub setup_nt4_dc_smb1_done
{
	my ($self, $path, $dep_env) = @_;
	return $self->return_alias_env($path, $dep_env);
}

sub setup_nt4_dc_schannel
{
	my ($self, $path) = @_;

	print "PROVISIONING NT4 DC WITH SERVER SCHANNEL ...";

	my $pdc_options = "
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

	server schannel = yes
	# used to reproduce bug #12772
	server max protocol = SMB2_02
";

	my $vars = $self->provision(
	    prefix => $path,
	    domain => "NT4SCHANNEL",
	    server => "LOCALNT4DC9",
	    password => "localntdc9pass",
	    extra_options => $pdc_options);

	$vars or return undef;

	if (not $self->check_or_start(
		env_vars => $vars,
		nmbd => "yes",
		winbindd => "yes",
		smbd => "yes")) {
	       return undef;
	}

	$vars->{DOMSID} = $vars->{SAMSID};
	$vars->{DC_SERVER} = $vars->{SERVER};
	$vars->{DC_SERVER_IP} = $vars->{SERVER_IP};
	$vars->{DC_SERVER_IPV6} = $vars->{SERVER_IPV6};
	$vars->{DC_NETBIOSNAME} = $vars->{NETBIOSNAME};
	$vars->{DC_USERNAME} = $vars->{USERNAME};
	$vars->{DC_PASSWORD} = $vars->{PASSWORD};

	return $vars;
}

sub setup_nt4_member
{
	my ($self, $prefix, $nt4_dc_vars) = @_;
	my $count = 0;
	my $rc;

	print "PROVISIONING MEMBER...";

	my $require_mutexes = "dbwrap_tdb_require_mutexes:* = yes";
	if ($ENV{SELFTEST_DONT_REQUIRE_TDB_MUTEX_SUPPORT} // '' eq "1") {
		$require_mutexes = "";
	}

	my $member_options = "
	security = domain
	dbwrap_tdb_mutexes:* = yes
	${require_mutexes}
";
	my $ret = $self->provision(
	    prefix => $prefix,
	    domain => $nt4_dc_vars->{DOMAIN},
	    server => "LOCALNT4MEMBER3",
	    password => "localnt4member3pass",
	    extra_options => $member_options);

	$ret or return undef;

	my $nmblookup = Samba::bindir_path($self, "nmblookup");
	do {
		print "Waiting for the LOGON SERVER registration ...\n";
		$rc = system("$nmblookup $ret->{CONFIGURATION} $ret->{DOMAIN}\#1c");
		if ($rc != 0) {
			sleep(1);
		}
		$count++;
	} while ($rc != 0 && $count < 10);
	if ($count == 10) {
		print "NMBD not reachable after 10 retries\n";
		teardown_env($self, $ret);
		return 0;
	}

	my $net = Samba::bindir_path($self, "net");
	# Add hosts file for name lookups
	my $cmd = "NSS_WRAPPER_HOSTS='$ret->{NSS_WRAPPER_HOSTS}' ";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	$cmd .= "SELFTEST_WINBINDD_SOCKET_DIR=\"$ret->{SELFTEST_WINBINDD_SOCKET_DIR}\" ";
	$cmd .= "$net rpc join $ret->{CONFIGURATION} $nt4_dc_vars->{DOMAIN} member";
	$cmd .= " -U$nt4_dc_vars->{USERNAME}\%$nt4_dc_vars->{PASSWORD}";

	if (system($cmd) != 0) {
	    warn("Join failed\n$cmd");
	    return undef;
	}

	# Add hosts file for name lookups
	$cmd = "NSS_WRAPPER_HOSTS='$ret->{NSS_WRAPPER_HOSTS}' ";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	$cmd .= "SELFTEST_WINBINDD_SOCKET_DIR=\"$ret->{SELFTEST_WINBINDD_SOCKET_DIR}\" ";
	$cmd .= "$net $ret->{CONFIGURATION} primarytrust dumpinfo | grep -q 'REDACTED SECRET VALUES'";

	if (system($cmd) != 0) {
	    warn("check failed\n$cmd");
	    return undef;
	}

	if (not $self->check_or_start(
		env_vars => $ret,
		nmbd => "yes",
		winbindd => "yes",
		smbd => "yes")) {
	       return undef;
	}

	$ret->{DOMSID} = $nt4_dc_vars->{DOMSID};
	$ret->{DC_SERVER} = $nt4_dc_vars->{SERVER};
	$ret->{DC_SERVER_IP} = $nt4_dc_vars->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $nt4_dc_vars->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $nt4_dc_vars->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $nt4_dc_vars->{USERNAME};
	$ret->{DC_PASSWORD} = $nt4_dc_vars->{PASSWORD};

	return $ret;
}

sub setup_clusteredmember_smb1
{
	my ($self, $prefix, $nt4_dc_vars) = @_;
	my $count = 0;
	my $rc;
	my @retvals = ();
	my $ret;

	print "PROVISIONING CLUSTEREDMEMBER...\n";

	my $prefix_abs = abs_path($prefix);
	mkdir($prefix_abs, 0777);

	my $server_name = "CLUSTEREDMEMBER";

	my $ctdb_data = $self->setup_ctdb($prefix);

	if (not $ctdb_data) {
		print "No ctdb data\n";
		return undef;
	}

	print "PROVISIONING CLUSTERED SAMBA...\n";

	my $num_nodes = $ctdb_data->{NUM_NODES};
	my $nodes = $ctdb_data->{CTDB_NODES};

	# Enable cleanup of earlier nodes if a later node fails
	$ctdb_data->{SAMBA_NODES} = \@retvals;

	for (my $i = 0; $i < $num_nodes; $i++) {
		my $node = $nodes->[$i];
		my $socket = $node->{SOCKET_FILE};
		my $server_name = $node->{SERVER_NAME};
		my $pub_iface = $node->{SOCKET_WRAPPER_DEFAULT_IFACE};
		my $node_prefix = $node->{NODE_PREFIX};

		print "NODE_PREFIX=${node_prefix}\n";
		print "SOCKET=${socket}\n";

		my $require_mutexes = "dbwrap_tdb_require_mutexes:* = yes";
		if ($ENV{SELFTEST_DONT_REQUIRE_TDB_MUTEX_SUPPORT} // '' eq "1") {
			$require_mutexes = "" ;
		}

		my $member_options = "
       security = domain
       server signing = on
       clustering = yes
       ctdbd socket = ${socket}
       client min protocol = CORE
       server min protocol = LANMAN1
       dbwrap_tdb_mutexes:* = yes
       ${require_mutexes}
";

		my $node_ret = $self->provision(
		    prefix => "$node_prefix",
		    domain => $nt4_dc_vars->{DOMAIN},
		    server => "$server_name",
		    password => "clustermember8pass",
		    netbios_name => "CLUSTEREDMEMBER",
		    share_dir => "${prefix_abs}/shared",
		    extra_options => $member_options,
		    no_delete_prefix => 1);
		if (not $node_ret) {
			print "Provision node $i failed\n";
			teardown_env($self, $ctdb_data);
			return undef;
		}

		my $nmblookup = Samba::bindir_path($self, "nmblookup");
		do {
			print "Waiting for the LOGON SERVER registration ...\n";
			$rc = system("$nmblookup $node_ret->{CONFIGURATION} " .
				     "$node_ret->{DOMAIN}\#1c");
			if ($rc != 0) {
				sleep(1);
			}
			$count++;
		} while ($rc != 0 && $count < 10);

		if ($count == 10) {
			print "NMBD not reachable after 10 retries\n";
			teardown_env($self, $node_ret);
			teardown_env($self, $ctdb_data);
			return undef;
		}

		push(@retvals, $node_ret);
	}

	$ret = {%$ctdb_data, %{$retvals[0]}};

	my $net = Samba::bindir_path($self, "net");
	my $cmd = "";
	$cmd .= "UID_WRAPPER_ROOT=1 ";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	$cmd .= "SELFTEST_WINBINDD_SOCKET_DIR=\"$ret->{SELFTEST_WINBINDD_SOCKET_DIR}\" ";
	$cmd .= "$net join $ret->{CONFIGURATION} $nt4_dc_vars->{DOMAIN} member";
	$cmd .= " -U$nt4_dc_vars->{USERNAME}\%$nt4_dc_vars->{PASSWORD}";

	if (system($cmd) != 0) {
		warn("Join failed\n$cmd");
		teardown_env($self, $ret);
		return undef;
	}

	for (my $i=0; $i<@retvals; $i++) {
		my $node_provision = $retvals[$i];
		my $ok;
		$ok = $self->check_or_start(
		    env_vars => $node_provision,
		    winbindd => "yes",
		    smbd => "yes",
		    child_cleanup => sub {
			map {
			    my $fh = $_->{STDIN_PIPE};
			    close($fh) if defined($fh);
			} @retvals });
		if (not $ok) {
			teardown_env($self, $ret);
			return undef;
		}
	}

	#
	# Build a unclist for every share
	#
	unless (open(NODES, "<$ret->{CTDB_NODES_FILE}")) {
		warn("Unable to open CTDB nodes file");
		teardown_env($self, $ret);
		return undef;
	}
	my @nodes = <NODES>;
	close(NODES);
	chomp @nodes;

	my $conffile = $ret->{SERVERCONFFILE};
	$cmd = "";
	$cmd .= 'sed -n -e \'s|^\[\(.*\)\]$|\1|p\'';
	$cmd .= " \"$conffile\"";
	$cmd .= " | grep -vx 'global'";

	my @shares = `$cmd`;
	$rc = $?;
	if ($rc != 0) {
		warn("Listing shares failed\n$cmd");
		teardown_env($self, $ret);
		return undef;
	}
	chomp @shares;

	my $unclistdir = "${prefix_abs}/unclists";
	mkdir($unclistdir, 0777);
	foreach my $share (@shares) {
		my $l = "${unclistdir}/${share}.txt";
		unless (open(UNCLIST, ">${l}")) {
			warn("Unable to open UNC list ${l}");
			teardown_env($self, $ret);
			return undef;
		}
		foreach my $node (@nodes) {
			print UNCLIST "//${node}/${share}\n";
		}
		close(UNCLIST);
	}

	$ret->{DOMSID} = $nt4_dc_vars->{DOMSID};
	$ret->{DC_SERVER} = $nt4_dc_vars->{SERVER};
	$ret->{DC_SERVER_IP} = $nt4_dc_vars->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $nt4_dc_vars->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $nt4_dc_vars->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $nt4_dc_vars->{USERNAME};
	$ret->{DC_PASSWORD} = $nt4_dc_vars->{PASSWORD};

	return $ret;
}

sub provision_ad_member
{
	my ($self,
	    $prefix,
	    $machine_account,
	    $dcvars,
	    $trustvars_f,
	    $trustvars_e,
	    $force_fips_mode) = @_;

	my $prefix_abs = abs_path($prefix);
	my @dirs = ();

	mkdir($prefix_abs, 0777);

	my $share_dir="$prefix_abs/share";
	push(@dirs, $share_dir);

	my $substitution_path = "$share_dir/D_$dcvars->{DOMAIN}";
	push(@dirs, $substitution_path);

	$substitution_path = "$share_dir/D_$dcvars->{DOMAIN}/U_alice";
	push(@dirs, $substitution_path);

	$substitution_path = "$share_dir/D_$dcvars->{DOMAIN}/U_alice/G_domain users";
	push(@dirs, $substitution_path);

	# Using '/' as the winbind separator is a bad idea ...
	$substitution_path = "$share_dir/D_$dcvars->{DOMAIN}/u_$dcvars->{DOMAIN}";
	push(@dirs, $substitution_path);

	$substitution_path = "$share_dir/D_$dcvars->{DOMAIN}/u_$dcvars->{DOMAIN}/alice";
	push(@dirs, $substitution_path);

	$substitution_path = "$share_dir/D_$dcvars->{DOMAIN}/u_$dcvars->{DOMAIN}/alice/g_$dcvars->{DOMAIN}";
	push(@dirs, $substitution_path);

	$substitution_path = "$share_dir/D_$dcvars->{DOMAIN}/u_$dcvars->{DOMAIN}/alice/g_$dcvars->{DOMAIN}/domain users";
	push(@dirs, $substitution_path);

	my $member_options = "
	security = ads
        workgroup = $dcvars->{DOMAIN}
        realm = $dcvars->{REALM}
        netbios aliases = foo bar
	template homedir = /home/%D/%G/%U
	auth event notification = true
	password server = $dcvars->{SERVER}
	winbind scan trusted domains = no
	winbind use krb5 enterprise principals = yes

	allow dcerpc auth level connect:lsarpc = yes
	dcesrv:max auth states = 8

	rpc_server:epmapper = external
	rpc_server:lsarpc = external
	rpc_server:samr = external
	rpc_server:netlogon = disabled
	rpc_server:register_embedded_np = yes

	rpc_daemon:epmd = fork
	rpc_daemon:lsasd = fork

[sub_dug]
	path = $share_dir/D_%D/U_%U/G_%G
	writeable = yes

[sub_dug2]
	path = $share_dir/D_%D/u_%u/g_%g
	writeable = yes

[sub_valid_users]
	path = $share_dir
	valid users = ADDOMAIN/%U

";

	my $ret = $self->provision(
	    prefix => $prefix,
	    domain => $dcvars->{DOMAIN},
	    realm => $dcvars->{REALM},
	    server => $machine_account,
	    password => "loCalMemberPass",
	    extra_options => $member_options,
	    resolv_conf => $dcvars->{RESOLV_CONF});

	$ret or return undef;

	mkdir($_, 0777) foreach(@dirs);

	$ret->{DOMAIN} = $dcvars->{DOMAIN};
	$ret->{REALM} = $dcvars->{REALM};
	$ret->{DOMSID} = $dcvars->{DOMSID};

	my $ctx;
	$ctx = {};
	$ctx->{krb5_conf} = "$prefix_abs/lib/krb5.conf";
	$ctx->{domain} = $dcvars->{DOMAIN};
	$ctx->{realm} = $dcvars->{REALM};
	$ctx->{dnsname} = lc($dcvars->{REALM});
	$ctx->{kdc_ipv4} = $dcvars->{SERVER_IP};
	$ctx->{kdc_ipv6} = $dcvars->{SERVER_IPV6};
	$ctx->{krb5_ccname} = "$prefix_abs/krb5cc_%{uid}";
	Samba::mk_krb5_conf($ctx, "");

	$ret->{KRB5_CONFIG} = $ctx->{krb5_conf};

	if (defined($force_fips_mode)) {
		$ret->{GNUTLS_FORCE_FIPS_MODE} = "1";
		$ret->{OPENSSL_FORCE_FIPS_MODE} = "1";
	}

	my $net = Samba::bindir_path($self, "net");
	# Add hosts file for name lookups
	my $cmd = "NSS_WRAPPER_HOSTS='$ret->{NSS_WRAPPER_HOSTS}' ";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($ret->{RESOLV_WRAPPER_CONF})) {
		$cmd .= "RESOLV_WRAPPER_CONF=\"$ret->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd .= "RESOLV_WRAPPER_HOSTS=\"$ret->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	if (defined($force_fips_mode)) {
		$cmd .= "GNUTLS_FORCE_FIPS_MODE=1 ";
		$cmd .= "OPENSSL_FORCE_FIPS_MODE=1 ";
	}
	$cmd .= "RESOLV_CONF=\"$ret->{RESOLV_CONF}\" ";
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "SELFTEST_WINBINDD_SOCKET_DIR=\"$ret->{SELFTEST_WINBINDD_SOCKET_DIR}\" ";
	$cmd .= "$net join $ret->{CONFIGURATION}";
	$cmd .= " -U$dcvars->{USERNAME}\%$dcvars->{PASSWORD} -k";

	if (system($cmd) != 0) {
	    warn("Join failed\n$cmd");
	    return undef;
	}

	# We need world access to this share, as otherwise the domain
	# administrator from the AD domain provided by Samba4 can't
	# access the share for tests.
	chmod 0777, "$prefix/share";

	if (not $self->check_or_start(
		env_vars => $ret,
		nmbd => "yes",
		winbindd => "yes",
		smbd => "yes")) {
	    return undef;
	}

	$ret->{DC_SERVER} = $dcvars->{SERVER};
	$ret->{DC_SERVER_IP} = $dcvars->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $dcvars->{SERVER_IPV6};
	$ret->{DC_SERVERCONFFILE} = $dcvars->{SERVERCONFFILE};
	$ret->{DC_NETBIOSNAME} = $dcvars->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $dcvars->{USERNAME};
	$ret->{DC_PASSWORD} = $dcvars->{PASSWORD};

	# forest trust
	$ret->{TRUST_F_BOTH_SERVER} = $trustvars_f->{SERVER};
	$ret->{TRUST_F_BOTH_SERVER_IP} = $trustvars_f->{SERVER_IP};
	$ret->{TRUST_F_BOTH_SERVER_IPV6} = $trustvars_f->{SERVER_IPV6};
	$ret->{TRUST_F_BOTH_NETBIOSNAME} = $trustvars_f->{NETBIOSNAME};
	$ret->{TRUST_F_BOTH_USERNAME} = $trustvars_f->{USERNAME};
	$ret->{TRUST_F_BOTH_PASSWORD} = $trustvars_f->{PASSWORD};
	$ret->{TRUST_F_BOTH_DOMAIN} = $trustvars_f->{DOMAIN};
	$ret->{TRUST_F_BOTH_REALM} = $trustvars_f->{REALM};

	# external trust
	$ret->{TRUST_E_BOTH_SERVER} = $trustvars_e->{SERVER};
	$ret->{TRUST_E_BOTH_SERVER_IP} = $trustvars_e->{SERVER_IP};
	$ret->{TRUST_E_BOTH_SERVER_IPV6} = $trustvars_e->{SERVER_IPV6};
	$ret->{TRUST_E_BOTH_NETBIOSNAME} = $trustvars_e->{NETBIOSNAME};
	$ret->{TRUST_E_BOTH_USERNAME} = $trustvars_e->{USERNAME};
	$ret->{TRUST_E_BOTH_PASSWORD} = $trustvars_e->{PASSWORD};
	$ret->{TRUST_E_BOTH_DOMAIN} = $trustvars_e->{DOMAIN};
	$ret->{TRUST_E_BOTH_REALM} = $trustvars_e->{REALM};

	return $ret;
}

sub setup_ad_member
{
	my ($self,
	    $prefix,
	    $dcvars,
	    $trustvars_f,
	    $trustvars_e) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->have_ads()) {
	        return "UNKNOWN";
	}

	print "PROVISIONING AD MEMBER...";

	return $self->provision_ad_member($prefix,
					  "LOCALADMEMBER",
					  $dcvars,
					  $trustvars_f,
					  $trustvars_e);
}

sub setup_ad_member_rfc2307
{
	my ($self, $prefix, $dcvars) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->have_ads()) {
	        return "UNKNOWN";
	}

	print "PROVISIONING S3 AD MEMBER WITH idmap_rfc2307 config...";

	my $member_options = "
	security = ads
        workgroup = $dcvars->{DOMAIN}
        realm = $dcvars->{REALM}
        idmap cache time = 0
        idmap negative cache time = 0
        idmap config * : backend = autorid
        idmap config * : range = 1000000-1999999
        idmap config * : rangesize = 100000
        idmap config $dcvars->{DOMAIN} : backend = rfc2307
        idmap config $dcvars->{DOMAIN} : range = 2000000-2999999
        idmap config $dcvars->{DOMAIN} : ldap_server = ad
        idmap config $dcvars->{DOMAIN} : bind_path_user = ou=idmap,dc=samba,dc=example,dc=com
        idmap config $dcvars->{DOMAIN} : bind_path_group = ou=idmap,dc=samba,dc=example,dc=com

        password server = $dcvars->{SERVER}
";

	my $ret = $self->provision(
	    prefix => $prefix,
	    domain => $dcvars->{DOMAIN},
	    realm => $dcvars->{REALM},
	    server => "RFC2307MEMBER",
	    password => "loCalMemberPass",
	    extra_options => $member_options,
	    resolv_conf => $dcvars->{RESOLV_CONF});

	$ret or return undef;

	$ret->{DOMAIN} = $dcvars->{DOMAIN};
	$ret->{REALM} = $dcvars->{REALM};
	$ret->{DOMSID} = $dcvars->{DOMSID};

	my $ctx;
	my $prefix_abs = abs_path($prefix);
	$ctx = {};
	$ctx->{krb5_conf} = "$prefix_abs/lib/krb5.conf";
	$ctx->{domain} = $dcvars->{DOMAIN};
	$ctx->{realm} = $dcvars->{REALM};
	$ctx->{dnsname} = lc($dcvars->{REALM});
	$ctx->{kdc_ipv4} = $dcvars->{SERVER_IP};
	$ctx->{kdc_ipv6} = $dcvars->{SERVER_IPV6};
	$ctx->{krb5_ccname} = "$prefix_abs/krb5cc_%{uid}";
	Samba::mk_krb5_conf($ctx, "");

	$ret->{KRB5_CONFIG} = $ctx->{krb5_conf};

	my $net = Samba::bindir_path($self, "net");
	# Add hosts file for name lookups
	my $cmd = "NSS_WRAPPER_HOSTS='$ret->{NSS_WRAPPER_HOSTS}' ";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($ret->{RESOLV_WRAPPER_CONF})) {
		$cmd .= "RESOLV_WRAPPER_CONF=\"$ret->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd .= "RESOLV_WRAPPER_HOSTS=\"$ret->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	$cmd .= "RESOLV_CONF=\"$ret->{RESOLV_CONF}\" ";
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "SELFTEST_WINBINDD_SOCKET_DIR=\"$ret->{SELFTEST_WINBINDD_SOCKET_DIR}\" ";
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

	if (not $self->check_or_start(
		env_vars => $ret,
		nmbd => "yes",
		winbindd => "yes",
		smbd => "yes")) {
		return undef;
	}

	$ret->{DC_SERVER} = $dcvars->{SERVER};
	$ret->{DC_SERVER_IP} = $dcvars->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $dcvars->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $dcvars->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $dcvars->{USERNAME};
	$ret->{DC_PASSWORD} = $dcvars->{PASSWORD};

	return $ret;
}

sub setup_ad_member_idmap_rid
{
	my ($self, $prefix, $dcvars) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->have_ads()) {
	        return "UNKNOWN";
	}

	print "PROVISIONING S3 AD MEMBER WITH idmap_rid config...";

	my $member_options = "
	security = ads
	workgroup = $dcvars->{DOMAIN}
	realm = $dcvars->{REALM}
	idmap config * : backend = tdb
	idmap config * : range = 1000000-1999999
	idmap config $dcvars->{DOMAIN} : backend = rid
	idmap config $dcvars->{DOMAIN} : range = 2000000-2999999
	# Prevent overridding the provisioned lib/krb5.conf which sets certain
	# values required for tests to succeed
	create krb5 conf = no
        map to guest = bad user
";

	my $ret = $self->provision(
	    prefix => $prefix,
	    domain => $dcvars->{DOMAIN},
	    realm => $dcvars->{REALM},
	    server => "IDMAPRIDMEMBER",
	    password => "loCalMemberPass",
	    extra_options => $member_options,
	    resolv_conf => $dcvars->{RESOLV_CONF});

	$ret or return undef;

	$ret->{DOMAIN} = $dcvars->{DOMAIN};
	$ret->{REALM} = $dcvars->{REALM};
	$ret->{DOMSID} = $dcvars->{DOMSID};

	my $ctx;
	my $prefix_abs = abs_path($prefix);
	$ctx = {};
	$ctx->{krb5_conf} = "$prefix_abs/lib/krb5.conf";
	$ctx->{domain} = $dcvars->{DOMAIN};
	$ctx->{realm} = $dcvars->{REALM};
	$ctx->{dnsname} = lc($dcvars->{REALM});
	$ctx->{kdc_ipv4} = $dcvars->{SERVER_IP};
	$ctx->{kdc_ipv6} = $dcvars->{SERVER_IPV6};
	$ctx->{krb5_ccname} = "$prefix_abs/krb5cc_%{uid}";
	Samba::mk_krb5_conf($ctx, "");

	$ret->{KRB5_CONFIG} = $ctx->{krb5_conf};

	my $net = Samba::bindir_path($self, "net");
	# Add hosts file for name lookups
	my $cmd = "NSS_WRAPPER_HOSTS='$ret->{NSS_WRAPPER_HOSTS}' ";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($ret->{RESOLV_WRAPPER_CONF})) {
		$cmd .= "RESOLV_WRAPPER_CONF=\"$ret->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd .= "RESOLV_WRAPPER_HOSTS=\"$ret->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	$cmd .= "RESOLV_CONF=\"$ret->{RESOLV_CONF}\" ";
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "SELFTEST_WINBINDD_SOCKET_DIR=\"$ret->{SELFTEST_WINBINDD_SOCKET_DIR}\" ";
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

	if (not $self->check_or_start(
		env_vars => $ret,
		nmbd => "yes",
		winbindd => "yes",
		smbd => "yes")) {
		return undef;
	}

	$ret->{DC_SERVER} = $dcvars->{SERVER};
	$ret->{DC_SERVER_IP} = $dcvars->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $dcvars->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $dcvars->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $dcvars->{USERNAME};
	$ret->{DC_PASSWORD} = $dcvars->{PASSWORD};

	return $ret;
}

sub setup_ad_member_idmap_ad
{
	my ($self, $prefix, $dcvars) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->have_ads()) {
	        return "UNKNOWN";
	}

	print "PROVISIONING S3 AD MEMBER WITH idmap_ad config...";

	my $member_options = "
	security = ads
	workgroup = $dcvars->{DOMAIN}
	realm = $dcvars->{REALM}
	password server = $dcvars->{SERVER}
	idmap config * : backend = tdb
	idmap config * : range = 1000000-1999999
	idmap config $dcvars->{DOMAIN} : backend = ad
	idmap config $dcvars->{DOMAIN} : range = 2000000-2999999
	idmap config $dcvars->{TRUST_DOMAIN} : backend = ad
	idmap config $dcvars->{TRUST_DOMAIN} : range = 2000000-2999999
	gensec_gssapi:requested_life_time = 5
";

	my $ret = $self->provision(
	    prefix => $prefix,
	    domain => $dcvars->{DOMAIN},
	    realm => $dcvars->{REALM},
	    server => "IDMAPADMEMBER",
	    password => "loCalMemberPass",
	    extra_options => $member_options,
	    resolv_conf => $dcvars->{RESOLV_CONF});

	$ret or return undef;

	$ret->{DOMAIN} = $dcvars->{DOMAIN};
	$ret->{REALM} = $dcvars->{REALM};
	$ret->{DOMSID} = $dcvars->{DOMSID};

	my $ctx;
	my $prefix_abs = abs_path($prefix);
	$ctx = {};
	$ctx->{krb5_conf} = "$prefix_abs/lib/krb5.conf";
	$ctx->{domain} = $dcvars->{DOMAIN};
	$ctx->{realm} = $dcvars->{REALM};
	$ctx->{dnsname} = lc($dcvars->{REALM});
	$ctx->{kdc_ipv4} = $dcvars->{SERVER_IP};
	$ctx->{kdc_ipv6} = $dcvars->{SERVER_IPV6};
	$ctx->{krb5_ccname} = "$prefix_abs/krb5cc_%{uid}";
	Samba::mk_krb5_conf($ctx, "");

	$ret->{KRB5_CONFIG} = $ctx->{krb5_conf};

	my $net = Samba::bindir_path($self, "net");
	# Add hosts file for name lookups
	my $cmd = "NSS_WRAPPER_HOSTS='$ret->{NSS_WRAPPER_HOSTS}' ";
	$cmd .= "SOCKET_WRAPPER_DEFAULT_IFACE=\"$ret->{SOCKET_WRAPPER_DEFAULT_IFACE}\" ";
	if (defined($ret->{RESOLV_WRAPPER_CONF})) {
		$cmd .= "RESOLV_WRAPPER_CONF=\"$ret->{RESOLV_WRAPPER_CONF}\" ";
	} else {
		$cmd .= "RESOLV_WRAPPER_HOSTS=\"$ret->{RESOLV_WRAPPER_HOSTS}\" ";
	}
	$cmd .= "RESOLV_CONF=\"$ret->{RESOLV_CONF}\" ";
	$cmd .= "KRB5_CONFIG=\"$ret->{KRB5_CONFIG}\" ";
	$cmd .= "SELFTEST_WINBINDD_SOCKET_DIR=\"$ret->{SELFTEST_WINBINDD_SOCKET_DIR}\" ";
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

	if (not $self->check_or_start(
		env_vars => $ret,
		nmbd => "yes",
		winbindd => "yes",
		smbd => "yes")) {
		return undef;
	}

	$ret->{DC_SERVER} = $dcvars->{SERVER};
	$ret->{DC_SERVER_IP} = $dcvars->{SERVER_IP};
	$ret->{DC_SERVER_IPV6} = $dcvars->{SERVER_IPV6};
	$ret->{DC_NETBIOSNAME} = $dcvars->{NETBIOSNAME};
	$ret->{DC_USERNAME} = $dcvars->{USERNAME};
	$ret->{DC_PASSWORD} = $dcvars->{PASSWORD};

	$ret->{TRUST_SERVER} = $dcvars->{TRUST_SERVER};
	$ret->{TRUST_USERNAME} = $dcvars->{TRUST_USERNAME};
	$ret->{TRUST_PASSWORD} = $dcvars->{TRUST_PASSWORD};
	$ret->{TRUST_DOMAIN} = $dcvars->{TRUST_DOMAIN};
	$ret->{TRUST_REALM} = $dcvars->{TRUST_REALM};
	$ret->{TRUST_DOMSID} = $dcvars->{TRUST_DOMSID};

	return $ret;
}

sub setup_ad_member_fips
{
	my ($self,
	    $prefix,
	    $dcvars,
	    $trustvars_f,
	    $trustvars_e) = @_;

	# If we didn't build with ADS, pretend this env was never available
	if (not $self->have_ads()) {
	        return "UNKNOWN";
	}

	print "PROVISIONING AD FIPS MEMBER...";

	return $self->provision_ad_member($prefix,
					  "FIPSADMEMBER",
					  $dcvars,
					  $trustvars_f,
					  $trustvars_e,
					  1);
}

sub setup_simpleserver
{
	my ($self, $path) = @_;

	print "PROVISIONING simple server...";

	my $prefix_abs = abs_path($path);

	my $simpleserver_options = "
	lanman auth = yes
	ntlm auth = yes
	vfs objects = xattr_tdb streams_depot
	change notify = no
	smb encrypt = off

[vfs_aio_pthread]
	path = $prefix_abs/share
	read only = no
	vfs objects = aio_pthread
	aio_pthread:aio open = yes
	smbd:async dosmode = no

[vfs_aio_pthread_async_dosmode_default1]
	path = $prefix_abs/share
	read only = no
	vfs objects = aio_pthread
	store dos attributes = yes
	aio_pthread:aio open = yes
	smbd:async dosmode = yes

[vfs_aio_pthread_async_dosmode_default2]
	path = $prefix_abs/share
	read only = no
	vfs objects = aio_pthread xattr_tdb
	store dos attributes = yes
	aio_pthread:aio open = yes
	smbd:async dosmode = yes

[vfs_aio_pthread_async_dosmode_force_sync1]
	path = $prefix_abs/share
	read only = no
	vfs objects = aio_pthread
	store dos attributes = yes
	aio_pthread:aio open = yes
	smbd:async dosmode = yes
	# This simulates non linux systems
	smbd:force sync user path safe threadpool = yes
	smbd:force sync user chdir safe threadpool = yes
	smbd:force sync root path safe threadpool = yes
	smbd:force sync root chdir safe threadpool = yes

[vfs_aio_pthread_async_dosmode_force_sync2]
	path = $prefix_abs/share
	read only = no
	vfs objects = aio_pthread xattr_tdb
	store dos attributes = yes
	aio_pthread:aio open = yes
	smbd:async dosmode = yes
	# This simulates non linux systems
	smbd:force sync user path safe threadpool = yes
	smbd:force sync user chdir safe threadpool = yes
	smbd:force sync root path safe threadpool = yes
	smbd:force sync root chdir safe threadpool = yes

[vfs_aio_fork]
	path = $prefix_abs/share
        vfs objects = aio_fork
        read only = no
        vfs_aio_fork:erratic_testing_mode=yes

[dosmode]
	path = $prefix_abs/share
	vfs objects =
	store dos attributes = yes
	hide files = /hidefile/
	hide dot files = yes

[enc_desired]
	path = $prefix_abs/share
	vfs objects =
	smb encrypt = desired

[hidenewfiles]
	path = $prefix_abs/share
	hide new files timeout = 5
";

	my $vars = $self->provision(
	    prefix => $path,
	    domain => "WORKGROUP",
	    server => "LOCALSHARE4",
	    password => "local4pass",
	    extra_options => $simpleserver_options);

	$vars or return undef;

	if (not $self->check_or_start(
		env_vars => $vars,
		nmbd => "yes",
		smbd => "yes")) {
	       return undef;
	}

	return $vars;
}

sub create_file_chmod($$)
{
    my ($name, $mode) = @_;
    my $fh;

    unless (open($fh, '>', $name)) {
	warn("Unable to open $name");
	return undef;
    }
    chmod($mode, $fh);
}

sub setup_fileserver
{
	my ($self, $path, $more_conf, $server) = @_;
	my $prefix_abs = abs_path($path);
	my $srcdir_abs = abs_path($self->{srcdir});

	print "PROVISIONING file server ...\n";

	my @dirs = ();

	mkdir($prefix_abs, 0777);

	my $usershare_dir="$prefix_abs/lib/usershare";

	mkdir("$prefix_abs/lib", 0755);
	remove_tree($usershare_dir);
	mkdir($usershare_dir, 01770);

	my $share_dir="$prefix_abs/share";

	# Create share directory structure
	my $lower_case_share_dir="$share_dir/lower-case";
	push(@dirs, $lower_case_share_dir);

	my $lower_case_share_dir_30000="$share_dir/lower-case-30000";
	push(@dirs, $lower_case_share_dir_30000);

	my $dfree_share_dir="$share_dir/dfree";
	push(@dirs, $dfree_share_dir);
	push(@dirs, "$dfree_share_dir/subdir1");
	push(@dirs, "$dfree_share_dir/subdir2");
	push(@dirs, "$dfree_share_dir/subdir3");

	my $quotadir_dir="$share_dir/quota";
	push(@dirs, $quotadir_dir);

	my $valid_users_sharedir="$share_dir/valid_users";
	push(@dirs,$valid_users_sharedir);

	my $offline_sharedir="$share_dir/offline";
	push(@dirs,$offline_sharedir);

	my $force_user_valid_users_dir = "$share_dir/force_user_valid_users";
	push(@dirs, $force_user_valid_users_dir);

	my $smbget_sharedir="$share_dir/smbget";
	push(@dirs,$smbget_sharedir);

	my $tarmode_sharedir="$share_dir/tarmode";
	push(@dirs,$tarmode_sharedir);

	my $tarmode2_sharedir="$share_dir/tarmode2";
	push(@dirs,$tarmode2_sharedir);

	my $smbcacls_sharedir="$share_dir/smbcacls";
	push(@dirs,$smbcacls_sharedir);

	my $usershare_sharedir="$share_dir/usershares";
	push(@dirs,$usershare_sharedir);

	my $dropbox_sharedir="$share_dir/dropbox";
	push(@dirs,$dropbox_sharedir);

	my $bad_iconv_sharedir="$share_dir/bad_iconv";
	push(@dirs, $bad_iconv_sharedir);

	my $ip4 = Samba::get_ipv4_addr("FILESERVER");
	my $fileserver_options = "
	kernel change notify = yes
	rpc_server:mdssvc = embedded
	spotlight backend = elasticsearch
	elasticsearch:address = $ip4
	elasticsearch:port = 8080
	elasticsearch:mappings = $srcdir_abs/source3/rpc_server/mdssvc/elasticsearch_mappings.json

	usershare path = $usershare_dir
	usershare max shares = 10
	usershare allow guests = yes
	usershare prefix allow list = $usershare_sharedir

	get quota command = $prefix_abs/getset_quota.py
	set quota command = $prefix_abs/getset_quota.py
[tarmode]
	path = $tarmode_sharedir
	comment = tar test share
	xattr_tdb:file = $prefix_abs/tarmode-xattr.tdb
[tarmode2]
	path = $tarmode2_sharedir
	comment = tar test share
	xattr_tdb:file = $prefix_abs/tarmode2-xattr.tdb
[spotlight]
	path = $share_dir
	spotlight = yes
	read only = no
[no_spotlight]
	path = $share_dir
	spotlight = no
	read only = no
[lowercase]
	path = $lower_case_share_dir
	comment = smb username is [%U]
	case sensitive = True
	default case = lower
	preserve case = no
	short preserve case = no
[lowercase-30000]
	path = $lower_case_share_dir_30000
	comment = smb username is [%U]
	case sensitive = True
	default case = lower
	preserve case = no
	short preserve case = no
[dfree]
	path = $dfree_share_dir
	comment = smb username is [%U]
	dfree command = $srcdir_abs/testprogs/blackbox/dfree.sh
[valid-users-access]
	path = $valid_users_sharedir
	valid users = +userdup
[offline]
	path = $offline_sharedir
	vfs objects = offline

# BUG: https://bugzilla.samba.org/show_bug.cgi?id=9878
# RH BUG: https://bugzilla.redhat.com/show_bug.cgi?id=1077651
[force_user_valid_users]
	path = $force_user_valid_users_dir
	comment = force user with valid users combination test share
	valid users = +force_user
	force user = force_user
	force group = everyone
	write list = force_user

[smbget]
	path = $smbget_sharedir
	comment = smb username is [%U]
	guest ok = yes
[ign_sysacls]
	path = $share_dir
	comment = ignore system acls
	acl_xattr:ignore system acls = yes
[inherit_owner]
	path = $share_dir
	comment = inherit owner
	inherit owner = yes
[inherit_owner_u]
	path = $share_dir
	comment = inherit only unix owner
	inherit owner = unix only
	acl_xattr:ignore system acls = yes
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=13690
[force_group_test]
	path = $share_dir
	comment = force group test
#	force group = everyone

[create_mode_664]
	path = $share_dir
	comment = smb username is [%U]
	create mask = 0644
	force create mode = 0664
	vfs objects = dirsort

[dropbox]
	path = $dropbox_sharedir
	comment = smb username is [%U]
	writeable = yes
	vfs objects =

[bad_iconv]
	path = $bad_iconv_sharedir
	comment = smb username is [%U]
	vfs objects =

[homes]
	comment = Home directories
	browseable = No
	read only = No
";

	if (defined($more_conf)) {
		$fileserver_options = $fileserver_options . $more_conf;
	}
	if (!defined($server)) {
		$server = "FILESERVER";
	}

	my $vars = $self->provision(
	    prefix => $path,
	    domain => "WORKGROUP",
	    server => $server,
	    password => "fileserver",
	    extra_options => $fileserver_options,
	    no_delete_prefix => 1);

	$vars or return undef;

	if (not $self->check_or_start(
		env_vars => $vars,
		nmbd => "yes",
		smbd => "yes")) {
	       return undef;
	}


	mkdir($_, 0777) foreach(@dirs);

	## Create case sensitive lower case share dir
	foreach my $file ('a'..'z') {
		my $full_path = $lower_case_share_dir . '/' . $file;
		open my $fh, '>', $full_path;
		# Add some content to file
		print $fh $full_path;
		close $fh;
	}

	for (my $file = 1; $file < 51; ++$file) {
		my $full_path = $lower_case_share_dir . '/' . $file;
		open my $fh, '>', $full_path;
		# Add some content to file
		print $fh $full_path;
		close $fh;
	}

	# Create content for 30000 share
	foreach my $file ('a'..'z') {
		my $full_path = $lower_case_share_dir_30000 . '/' . $file;
		open my $fh, '>', $full_path;
		# Add some content to file
		print $fh $full_path;
		close $fh;
	}

	for (my $file = 1; $file < 30001; ++$file) {
		my $full_path = $lower_case_share_dir_30000 . '/' . $file;
		open my $fh, '>', $full_path;
		# Add some content to file
		print $fh $full_path;
		close $fh;
	}

	##
	## create a listable file in valid_users_share
	##
	create_file_chmod("$valid_users_sharedir/foo", 0644) or return undef;

	##
	## create a valid utf8 filename which is invalid as a CP850 conversion
	##
	create_file_chmod("$bad_iconv_sharedir/\xED\x9F\xBF", 0644) or return undef;

	return $vars;
}

sub setup_fileserver_smb1
{
	my ($self, $path) = @_;
	my $prefix_abs = abs_path($path);
	my $conf = "
[global]
	client min protocol = CORE
	server min protocol = LANMAN1

[hidenewfiles]
	path = $prefix_abs/share
	hide new files timeout = 5
[vfs_aio_pthread]
	path = $prefix_abs/share
	read only = no
	vfs objects = aio_pthread
	aio_pthread:aio open = yes
	smbd:async dosmode = no

[vfs_aio_pthread_async_dosmode_default1]
	path = $prefix_abs/share
	read only = no
	vfs objects = aio_pthread
	store dos attributes = yes
	aio_pthread:aio open = yes
	smbd:async dosmode = yes

[vfs_aio_pthread_async_dosmode_default2]
	path = $prefix_abs/share
	read only = no
	vfs objects = aio_pthread xattr_tdb
	store dos attributes = yes
	aio_pthread:aio open = yes
	smbd:async dosmode = yes

[vfs_aio_pthread_async_dosmode_force_sync1]
	path = $prefix_abs/share
	read only = no
	vfs objects = aio_pthread
	store dos attributes = yes
	aio_pthread:aio open = yes
	smbd:async dosmode = yes
	# This simulates non linux systems
	smbd:force sync user path safe threadpool = yes
	smbd:force sync user chdir safe threadpool = yes
	smbd:force sync root path safe threadpool = yes
	smbd:force sync root chdir safe threadpool = yes

[vfs_aio_pthread_async_dosmode_force_sync2]
	path = $prefix_abs/share
	read only = no
	vfs objects = aio_pthread xattr_tdb
	store dos attributes = yes
	aio_pthread:aio open = yes
	smbd:async dosmode = yes
	# This simulates non linux systems
	smbd:force sync user path safe threadpool = yes
	smbd:force sync user chdir safe threadpool = yes
	smbd:force sync root path safe threadpool = yes
	smbd:force sync root chdir safe threadpool = yes

[vfs_aio_fork]
	path = $prefix_abs/share
        vfs objects = aio_fork
        read only = no
        vfs_aio_fork:erratic_testing_mode=yes
";
	return $self->setup_fileserver($path, $conf, "FILESERVERSMB1");
}

sub setup_fileserver_smb1_done
{
	my ($self, $path, $dep_env) = @_;
	return $self->return_alias_env($path, $dep_env);
}

sub setup_ktest
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
	server min protocol = SMB3_00
	client max protocol = SMB3

        # This disables NTLM auth against the local SAM, which
        # we use can then test this setting by.
        ntlm auth = disabled
";

	my $ret = $self->provision(
	    prefix => $prefix,
	    domain => "KTEST",
	    server => "LOCALKTEST6",
	    password => "localktest6pass",
	    extra_options => $ktest_options);

	$ret or return undef;

	my $ctx;
	my $prefix_abs = abs_path($prefix);
	$ctx = {};
	$ctx->{krb5_conf} = "$prefix_abs/lib/krb5.conf";
	$ctx->{domain} = "KTEST";
	$ctx->{realm} = "KTEST.SAMBA.EXAMPLE.COM";
	$ctx->{dnsname} = lc($ctx->{realm});
	$ctx->{kdc_ipv4} = "0.0.0.0";
	$ctx->{kdc_ipv6} = "::";
	$ctx->{krb5_ccname} = "$prefix_abs/krb5cc_%{uid}";
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
	$ret->{SAMSID} = "S-1-5-21-1911091480-1468226576-2729736297";
	$ret->{DOMSID} = "S-1-5-21-1071277805-689288055-3486227160";

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

	if (not $self->check_or_start(
		env_vars => $ret,
		nmbd => "yes",
		smbd => "yes")) {
	       return undef;
	}
	return $ret;
}

sub setup_maptoguest
{
	my ($self, $path) = @_;
	my $prefix_abs = abs_path($path);
	my $libdir="$prefix_abs/lib";
	my $share_dir="$prefix_abs/share";
	my $errorinjectconf="$libdir/error_inject.conf";

	print "PROVISIONING maptoguest...";

	my $options = "
map to guest = bad user
ntlm auth = yes

[force_user_error_inject]
	path = $share_dir
	vfs objects = acl_xattr fake_acls xattr_tdb error_inject
	force user = user1
	include = $errorinjectconf
";

	my $vars = $self->provision(
	    prefix => $path,
	    domain => "WORKGROUP",
	    server => "maptoguest",
	    password => "maptoguestpass",
	    extra_options => $options);

	$vars or return undef;

	if (not $self->check_or_start(
		env_vars => $vars,
		nmbd => "yes",
		smbd => "yes")) {
	       return undef;
	}

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

# builds up the cmd args to run an s3 binary (i.e. smbd, nmbd, etc)
sub make_bin_cmd
{
	my ($self, $binary, $env_vars, $options, $valgrind, $dont_log_stdout) = @_;

	my @optargs = ("-d0");
	if (defined($options)) {
		@optargs = split(/ /, $options);
	}
	my @preargs = (Samba::bindir_path($self, "timelimit"), $self->{server_maxtime});

	if (defined($valgrind)) {
		@preargs = split(/ /, $valgrind);
	}
	my @args = ("-F", "--no-process-group",
		    "-s", $env_vars->{SERVERCONFFILE},
		    "-l", $env_vars->{LOGDIR});

	if (not defined($dont_log_stdout)) {
		push(@args, "--log-stdout");
	}
	return (@preargs, $binary, @args, @optargs);
}

sub check_or_start($$) {
	my ($self, %args) = @_;
	my $env_vars = $args{env_vars};
	my $nmbd = $args{nmbd} // "no";
	my $winbindd = $args{winbindd} // "no";
	my $smbd = $args{smbd} // "no";
	my $child_cleanup = $args{child_cleanup};

	my $STDIN_READER;

	# use a pipe for stdin in the child processes. This allows
	# those processes to monitor the pipe for EOF to ensure they
	# exit when the test script exits
	pipe($STDIN_READER, $env_vars->{STDIN_PIPE});

	my $binary = Samba::bindir_path($self, "nmbd");
	my @full_cmd = $self->make_bin_cmd($binary, $env_vars,
					   $ENV{NMBD_OPTIONS}, $ENV{NMBD_VALGRIND},
					   $ENV{NMBD_DONT_LOG_STDOUT});
	my $nmbd_envs = Samba::get_env_for_process("nmbd", $env_vars);
	delete $nmbd_envs->{RESOLV_WRAPPER_CONF};
	delete $nmbd_envs->{RESOLV_WRAPPER_HOSTS};

	# fork and exec() nmbd in the child process
	my $daemon_ctx = {
		NAME => "nmbd",
		BINARY_PATH => $binary,
		FULL_CMD => [ @full_cmd ],
		LOG_FILE => $env_vars->{NMBD_TEST_LOG},
		PCAP_FILE => "env-$ENV{ENVNAME}-nmbd",
		ENV_VARS => $nmbd_envs,
	};
	if ($nmbd ne "yes") {
		$daemon_ctx->{SKIP_DAEMON} = 1;
	}
	my $pid = Samba::fork_and_exec(
	    $self, $env_vars, $daemon_ctx, $STDIN_READER, $child_cleanup);

	$env_vars->{NMBD_TL_PID} = $pid;
	write_pid($env_vars, "nmbd", $pid);

	$binary = Samba::bindir_path($self, "winbindd");
	@full_cmd = $self->make_bin_cmd($binary, $env_vars,
					 $ENV{WINBINDD_OPTIONS}, $ENV{WINBINDD_VALGRIND}, "N/A");

	if (not defined($ENV{WINBINDD_DONT_LOG_STDOUT})) {
		push(@full_cmd, "--stdout");
	}

	# fork and exec() winbindd in the child process
	$daemon_ctx = {
		NAME => "winbindd",
		BINARY_PATH => $binary,
		FULL_CMD => [ @full_cmd ],
		LOG_FILE => $env_vars->{WINBINDD_TEST_LOG},
		PCAP_FILE => "env-$ENV{ENVNAME}-winbindd",
	};
	if ($winbindd ne "yes" and $winbindd ne "offline") {
		$daemon_ctx->{SKIP_DAEMON} = 1;
	}

	$pid = Samba::fork_and_exec(
	    $self, $env_vars, $daemon_ctx, $STDIN_READER, $child_cleanup);

	$env_vars->{WINBINDD_TL_PID} = $pid;
	write_pid($env_vars, "winbindd", $pid);

	$binary = Samba::bindir_path($self, "smbd");
	@full_cmd = $self->make_bin_cmd($binary, $env_vars,
					 $ENV{SMBD_OPTIONS}, $ENV{SMBD_VALGRIND},
					 $ENV{SMBD_DONT_LOG_STDOUT});

	# fork and exec() smbd in the child process
	$daemon_ctx = {
		NAME => "smbd",
		BINARY_PATH => $binary,
		FULL_CMD => [ @full_cmd ],
		LOG_FILE => $env_vars->{SMBD_TEST_LOG},
		PCAP_FILE => "env-$ENV{ENVNAME}-smbd",
	};
	if ($smbd ne "yes") {
		$daemon_ctx->{SKIP_DAEMON} = 1;
	}

	$pid = Samba::fork_and_exec(
	    $self, $env_vars, $daemon_ctx, $STDIN_READER, $child_cleanup);

	$env_vars->{SMBD_TL_PID} = $pid;
	write_pid($env_vars, "smbd", $pid);

	# close the parent's read-end of the pipe
	close($STDIN_READER);

	return $self->wait_for_start($env_vars, $nmbd, $winbindd, $smbd);
}

sub createuser($$$$$)
{
	my ($self, $username, $password, $conffile, $env) = @_;
	my $cmd = "UID_WRAPPER_ROOT=1 " . Samba::bindir_path($self, "smbpasswd")." -c $conffile -L -s -a $username > /dev/null";

	keys %$env;
	while(my($var, $val) = each %$env) {
		$cmd = "$var=\"$val\" $cmd";
	}

	unless (open(PWD, "|$cmd")) {
	    warn("Unable to set password for $username account\n$cmd");
	    return undef;
	}
	print PWD "$password\n$password\n";
	unless (close(PWD)) {
	    warn("Unable to set password for $username account\n$cmd");
	    return undef;
	}
}

sub provision($$)
{
        my ($self, %args) = @_;

	my $prefix = $args{prefix};
	my $domain = $args{domain};
	my $realm = $args{realm};
	my $server = $args{server};
	my $password = $args{password};
	my $extra_options = $args{extra_options};
	my $resolv_conf = $args{resolv_conf};
	my $no_delete_prefix= $args{no_delete_prefix};
	my $netbios_name = $args{netbios_name} // $server;

	##
	## setup the various environment variables we need
	##

	my $samsid = Samba::random_domain_sid();
	my $swiface = Samba::get_interface($server);
	my %ret = ();
	my %createuser_env = ();
	my $server_ip = Samba::get_ipv4_addr($server);
	my $server_ipv6 = Samba::get_ipv6_addr($server);
	my $dns_domain;
	if (defined($realm)) {
	    $dns_domain = lc($realm);
	} else {
	    $dns_domain = "samba.example.com";
	}

	my $unix_name = ($ENV{USER} or $ENV{LOGNAME} or `PATH=/usr/ucb:$ENV{PATH} whoami`);
	chomp $unix_name;
	my $unix_uid = $>;
	my $unix_gids_str = $);
	my @unix_gids = split(" ", $unix_gids_str);

	my $prefix_abs = abs_path($prefix);
	my $bindir_abs = abs_path($self->{bindir});

	my @dirs = ();

	my $shrdir=$args{share_dir} // "$prefix_abs/share";
	push(@dirs,$shrdir);

	my $libdir="$prefix_abs/lib";
	push(@dirs,$libdir);

	my $piddir="$prefix_abs/pid";
	push(@dirs,$piddir);

	my $privatedir="$prefix_abs/private";
	push(@dirs,$privatedir);

	my $cachedir = "$prefix_abs/cachedir";
	push(@dirs, $cachedir);

	my $binddnsdir = "$prefix_abs/bind-dns";
	push(@dirs, $binddnsdir);

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

	my $noperm_shrdir="$shrdir/noperm-tmp";
	push(@dirs,$noperm_shrdir);

	my $msdfs_shrdir="$shrdir/msdfsshare";
	push(@dirs,$msdfs_shrdir);

	my $msdfs_deeppath="$msdfs_shrdir/deeppath";
	push(@dirs,$msdfs_deeppath);

	my $smbcacls_sharedir_dfs="$shrdir/smbcacls_sharedir_dfs";
	push(@dirs,$smbcacls_sharedir_dfs);

	my $badnames_shrdir="$shrdir/badnames";
	push(@dirs,$badnames_shrdir);

	my $lease1_shrdir="$shrdir/SMB2_10";
	push(@dirs,$lease1_shrdir);

	my $lease2_shrdir="$shrdir/SMB3_00";
	push(@dirs,$lease2_shrdir);

	my $manglenames_shrdir="$shrdir/manglenames";
	push(@dirs,$manglenames_shrdir);

	my $widelinks_shrdir="$shrdir/widelinks";
	push(@dirs,$widelinks_shrdir);

	my $widelinks_linkdir="$shrdir/widelinks_foo";
	push(@dirs,$widelinks_linkdir);

	my $fsrvp_shrdir="$shrdir/fsrvp";
	push(@dirs,$fsrvp_shrdir);

	my $shadow_tstdir="$shrdir/shadow";
	push(@dirs,$shadow_tstdir);
	my $shadow_mntdir="$shadow_tstdir/mount";
	push(@dirs,$shadow_mntdir);
	my $shadow_basedir="$shadow_mntdir/base";
	push(@dirs,$shadow_basedir);
	my $shadow_shrdir="$shadow_basedir/share";
	push(@dirs,$shadow_shrdir);

	my $nosymlinks_shrdir="$shrdir/nosymlinks";
	push(@dirs,$nosymlinks_shrdir);

	my $local_symlinks_shrdir="$shrdir/local_symlinks";
	push(@dirs,$local_symlinks_shrdir);

	# this gets autocreated by winbindd
	my $wbsockdir="$prefix_abs/winbindd";

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
	## Create a directory without permissions to enter
	##
	chmod 0000, $noperm_shrdir;

	##
	## create ro and msdfs share layout
	##

	chmod 0755, $ro_shrdir;

	create_file_chmod("$ro_shrdir/unreadable_file", 0600) or return undef;

	create_file_chmod("$ro_shrdir/msdfs-target", 0600) or return undef;
	symlink "msdfs:$server_ip\\ro-tmp,$server_ipv6\\ro-tmp",
		"$msdfs_shrdir/msdfs-src1";
	symlink "msdfs:$server_ipv6\\ro-tmp", "$msdfs_shrdir/deeppath/msdfs-src2";
	symlink "msdfs:$server_ip\\smbcacls_sharedir_dfs,$server_ipv6\\smbcacls_sharedir_dfs",
		"$msdfs_shrdir/smbcacls_sharedir_dfs";

	##
	## create bad names in $badnames_shrdir
	##
	## (An invalid name, would be mangled to 8.3).
	create_file_chmod("$badnames_shrdir/\340|\231\216\377\177",
			  0600) or return undef;

	## (A bad name, would not be mangled to 8.3).
	create_file_chmod("$badnames_shrdir/\240\276\346\327\377\177",
			  0666) or return undef;

	## (A bad good name).
	create_file_chmod("$badnames_shrdir/blank.txt",
			  0666) or return undef;

	##
	## create mangleable directory names in $manglenames_shrdir
	##
        my $manglename_target = "$manglenames_shrdir/foo:bar";
	mkdir($manglename_target, 0777);

	##
	## create symlinks for widelinks tests.
	##
	my $widelinks_target = "$widelinks_linkdir/target";
	create_file_chmod("$widelinks_target", 0666) or return undef;

	##
	## This link should get ACCESS_DENIED
	##
	symlink "$widelinks_target", "$widelinks_shrdir/source";
	##
	## This link should be allowed
	##
	symlink "$widelinks_shrdir", "$widelinks_shrdir/dot";

	my $conffile="$libdir/server.conf";
	my $dfqconffile="$libdir/dfq.conf";
	my $errorinjectconf="$libdir/error_inject.conf";
	my $delayinjectconf="$libdir/delay_inject.conf";
	my $globalinjectconf="$libdir/global_inject.conf";

	my $nss_wrapper_pl = "$ENV{PERL} $self->{srcdir}/third_party/nss_wrapper/nss_wrapper.pl";
	my $nss_wrapper_passwd = "$privatedir/passwd";
	my $nss_wrapper_group = "$privatedir/group";
	my $nss_wrapper_hosts = "$ENV{SELFTEST_PREFIX}/hosts";
	my $dns_host_file = "$ENV{SELFTEST_PREFIX}/dns_host_file";

	my $mod_printer_pl = "$ENV{PERL} $self->{srcdir}/source3/script/tests/printing/modprinter.pl";

	my $fake_snap_pl = "$ENV{PERL} $self->{srcdir}/source3/script/tests/fake_snap.pl";

	my @eventlog_list = ("dns server", "application");

	##
	## calculate uids and gids
	##

	my ($max_uid, $max_gid);
	my ($uid_nobody, $uid_root, $uid_pdbtest, $uid_pdbtest2, $uid_userdup);
	my ($uid_pdbtest_wkn);
	my ($uid_smbget);
	my ($uid_force_user);
	my ($gid_nobody, $gid_nogroup, $gid_root, $gid_domusers, $gid_domadmins);
	my ($gid_userdup, $gid_everyone);
	my ($gid_force_user);
	my ($uid_user1);
	my ($uid_user2);
	my ($uid_gooduser);
	my ($uid_eviluser);
	my ($uid_slashuser);

	if ($unix_uid < 0xffff - 13) {
		$max_uid = 0xffff;
	} else {
		$max_uid = $unix_uid;
	}

	$uid_root = $max_uid - 1;
	$uid_nobody = $max_uid - 2;
	$uid_pdbtest = $max_uid - 3;
	$uid_pdbtest2 = $max_uid - 4;
	$uid_userdup = $max_uid - 5;
	$uid_pdbtest_wkn = $max_uid - 6;
	$uid_force_user = $max_uid - 7;
	$uid_smbget = $max_uid - 8;
	$uid_user1 = $max_uid - 9;
	$uid_user2 = $max_uid - 10;
	$uid_gooduser = $max_uid - 11;
	$uid_eviluser = $max_uid - 12;
	$uid_slashuser = $max_uid - 13;

	if ($unix_gids[0] < 0xffff - 8) {
		$max_gid = 0xffff;
	} else {
		$max_gid = $unix_gids[0];
	}

	$gid_nobody = $max_gid - 1;
	$gid_nogroup = $max_gid - 2;
	$gid_root = $max_gid - 3;
	$gid_domusers = $max_gid - 4;
	$gid_domadmins = $max_gid - 5;
	$gid_userdup = $max_gid - 6;
	$gid_everyone = $max_gid - 7;
	$gid_force_user = $max_gid - 8;

	##
	## create conffile
	##

	unless (open(CONF, ">$conffile")) {
	        warn("Unable to open $conffile");
		return undef;
	}

	my $interfaces = Samba::get_interfaces_config($server);

	print CONF "
[global]
        dcesrv:fuzz directory = $cachedir/fuzz
	netbios name = $netbios_name
	interfaces = $interfaces
	bind interfaces only = yes
	panic action = cd $self->{srcdir} && $self->{srcdir}/selftest/gdb_backtrace %d %\$(MAKE_TEST_BINARY)
	smbd:suicide mode = yes
	smbd:FSCTL_SMBTORTURE = yes

	client min protocol = SMB2_02
	server min protocol = SMB2_02

	workgroup = $domain

	private dir = $privatedir
	binddns dir = $binddnsdir
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

	logging = file
	printing = bsd
	printcap name = /dev/null

	winbindd socket directory = $wbsockdir
	nmbd:socket dir = $nmbdsockdir
	idmap config * : range = 100000-200000
	winbind enum users = yes
	winbind enum groups = yes
	winbind separator = /
	include system krb5 conf = no

#	min receivefile size = 4000

	read only = no

	smbd:sharedelay = 100000
	smbd:writetimeupdatedelay = 500000
	map hidden = no
	map system = no
	map readonly = no
	store dos attributes = yes
	create mask = 755
	dos filemode = yes
	strict rename = yes
	strict sync = yes
	mangled names = yes
	vfs objects = acl_xattr fake_acls xattr_tdb streams_depot time_audit full_audit

	full_audit:syslog = no
	full_audit:success = none
	full_audit:failure = none

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

        # The samba3.blackbox.smbclient_s3 test uses this to test that
        # sending messages works, and that the %m sub works.
        message command = mv %s $shrdir/message.%m

	# fsrvp server requires registry shares
	registry shares = yes

	# Used by RPC SRVSVC tests
	add share command = $bindir_abs/smbaddshare
	change share command = $bindir_abs/smbchangeshare
	delete share command = $bindir_abs/smbdeleteshare

	# fruit:copyfile is a global option
	fruit:copyfile = yes

	#this does not mean that we use non-secure test env,
	#it just means we ALLOW one to be configured.
	allow insecure wide links = yes

	include = $globalinjectconf

	# Begin extra options
	$extra_options
	# End extra options

	#Include user defined custom parameters if set
";

	if (defined($ENV{INCLUDE_CUSTOM_CONF})) {
		print CONF "\t$ENV{INCLUDE_CUSTOM_CONF}\n";
	}

	print CONF "
[smbcacls_sharedir_dfs]
	path = $smbcacls_sharedir_dfs
        comment = smb username is [%U]
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
	comment = force a user with unix user SID and group SID
	path = $shrdir
	force user = pdbtest
	guest ok = yes
[forceuser_wkngroup]
	comment = force a user with well-known group SID
	path = $shrdir
	force user = pdbtest_wkn
	guest ok = yes
[forcegroup]
	path = $shrdir
        force group = nogroup
        guest ok = yes
[ro-tmp]
	path = $ro_shrdir
	guest ok = yes
[noperm]
	path = $noperm_shrdir
	wide links = yes
	guest ok = yes
[write-list-tmp]
	path = $shrdir
        read only = yes
	write list = $unix_name
[valid-users-tmp]
	path = $shrdir
	valid users = $unix_name
	access based share enum = yes
[msdfs-share]
	path = $msdfs_shrdir
	msdfs root = yes
	msdfs shuffle referrals = yes
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

[nfs4acl_simple_40]
	path = $shrdir
	comment = smb username is [%U]
	nfs4:mode = simple
	nfs4acl_xattr:version = 40
	vfs objects = nfs4acl_xattr xattr_tdb

[nfs4acl_special_40]
	path = $shrdir
	comment = smb username is [%U]
	nfs4:mode = special
	nfs4acl_xattr:version = 40
	vfs objects = nfs4acl_xattr xattr_tdb

[nfs4acl_simple_41]
	path = $shrdir
	comment = smb username is [%U]
	nfs4:mode = simple
	vfs objects = nfs4acl_xattr xattr_tdb

[nfs4acl_xdr_40]
	path = $shrdir
	comment = smb username is [%U]
	vfs objects = nfs4acl_xattr xattr_tdb
	nfs4:mode = simple
	nfs4acl_xattr:encoding = xdr
	nfs4acl_xattr:version = 40

[nfs4acl_xdr_41]
	path = $shrdir
	comment = smb username is [%U]
	vfs objects = nfs4acl_xattr xattr_tdb
	nfs4:mode = simple
	nfs4acl_xattr:encoding = xdr
	nfs4acl_xattr:version = 41

[nfs4acl_nfs_40]
	path = $shrdir
	comment = smb username is [%U]
	vfs objects = nfs4acl_xattr xattr_tdb
	nfs4:mode = simple
	nfs4acl_xattr:encoding = nfs
	nfs4acl_xattr:version = 40
	nfs4acl_xattr:xattr_name = security.nfs4acl_xdr

[nfs4acl_nfs_41]
	path = $shrdir
	comment = smb username is [%U]
	vfs objects = nfs4acl_xattr xattr_tdb
	nfs4:mode = simple
	nfs4acl_xattr:encoding = nfs
	nfs4acl_xattr:version = 41
	nfs4acl_xattr:xattr_name = security.nfs4acl_xdr

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
	vfs objects = xattr_tdb streams_depot
[aio]
	copy = durable
	aio read size = 1
	aio write size = 1

[print\$]
	copy = tmp

[vfs_fruit]
	path = $shrdir
	vfs objects = catia fruit streams_xattr acl_xattr xattr_tdb
	fruit:resource = file
	fruit:metadata = netatalk
	fruit:locking = netatalk
	fruit:encoding = native
	fruit:veto_appledouble = no

[vfs_fruit_xattr]
	path = $shrdir
        # This is used by vfs.fruit tests that require real fs xattr
	vfs objects = catia fruit streams_xattr acl_xattr
	fruit:resource = file
	fruit:metadata = netatalk
	fruit:locking = netatalk
	fruit:encoding = native
	fruit:veto_appledouble = no

[vfs_fruit_metadata_stream]
	path = $shrdir
	vfs objects = fruit streams_xattr acl_xattr xattr_tdb
	fruit:resource = file
	fruit:metadata = stream
	fruit:veto_appledouble = no

[vfs_fruit_stream_depot]
	path = $shrdir
	vfs objects = fruit streams_depot acl_xattr xattr_tdb
	fruit:resource = stream
	fruit:metadata = stream
	fruit:veto_appledouble = no

[vfs_wo_fruit]
	path = $shrdir
	vfs objects = streams_xattr acl_xattr xattr_tdb

[vfs_wo_fruit_stream_depot]
	path = $shrdir
	vfs objects = streams_depot acl_xattr xattr_tdb

[vfs_fruit_timemachine]
	path = $shrdir
	vfs objects = fruit streams_xattr acl_xattr xattr_tdb
	fruit:resource = file
	fruit:metadata = stream
	fruit:time machine = yes
	fruit:time machine max size = 32K

[vfs_fruit_wipe_intentionally_left_blank_rfork]
	path = $shrdir
	vfs objects = fruit streams_xattr acl_xattr xattr_tdb
	fruit:resource = file
	fruit:metadata = stream
	fruit:wipe_intentionally_left_blank_rfork = true
	fruit:delete_empty_adfiles = false
	fruit:veto_appledouble = no

[vfs_fruit_delete_empty_adfiles]
	path = $shrdir
	vfs objects = fruit streams_xattr acl_xattr xattr_tdb
	fruit:resource = file
	fruit:metadata = stream
	fruit:wipe_intentionally_left_blank_rfork = true
	fruit:delete_empty_adfiles = true
	fruit:veto_appledouble = no

[vfs_fruit_zero_fileid]
	path = $shrdir
	vfs objects = fruit streams_xattr acl_xattr xattr_tdb
	fruit:resource = file
	fruit:metadata = stream
	fruit:zero_file_id=yes

[badname-tmp]
	path = $badnames_shrdir
	guest ok = yes

[manglenames_share]
	path = $manglenames_shrdir
	guest ok = yes

[dynamic_share]
	path = $shrdir/%R
	guest ok = yes

[widelinks_share]
	path = $widelinks_shrdir
	wide links = no
	guest ok = yes

[fsrvp_share]
	path = $fsrvp_shrdir
	comment = fake shapshots using rsync
	vfs objects = shell_snap shadow_copy2
	shell_snap:check path command = $fake_snap_pl --check
	shell_snap:create command = $fake_snap_pl --create
	shell_snap:delete command = $fake_snap_pl --delete
	# a relative path here fails, the snapshot dir is no longer found
	shadow:snapdir = $fsrvp_shrdir/.snapshots

[shadow1]
	path = $shadow_shrdir
	comment = previous versions snapshots under mount point
	vfs objects = shadow_copy2
	shadow:mountpoint = $shadow_mntdir

[shadow2]
	path = $shadow_shrdir
	comment = previous versions snapshots outside mount point
	vfs objects = shadow_copy2
	shadow:mountpoint = $shadow_mntdir
	shadow:snapdir = $shadow_tstdir/.snapshots

[shadow3]
	path = $shadow_shrdir
	comment = previous versions with subvolume snapshots, snapshots under base dir
	vfs objects = shadow_copy2
	shadow:mountpoint = $shadow_mntdir
	shadow:basedir = $shadow_basedir
	shadow:snapdir = $shadow_basedir/.snapshots

[shadow4]
	path = $shadow_shrdir
	comment = previous versions with subvolume snapshots, snapshots outside mount point
	vfs objects = shadow_copy2
	shadow:mountpoint = $shadow_mntdir
	shadow:basedir = $shadow_basedir
	shadow:snapdir = $shadow_tstdir/.snapshots

[shadow5]
	path = $shadow_shrdir
	comment = previous versions at volume root snapshots under mount point
	vfs objects = shadow_copy2
	shadow:mountpoint = $shadow_shrdir

[shadow6]
	path = $shadow_shrdir
	comment = previous versions at volume root snapshots outside mount point
	vfs objects = shadow_copy2
	shadow:mountpoint = $shadow_shrdir
	shadow:snapdir = $shadow_tstdir/.snapshots

[shadow7]
	path = $shadow_shrdir
	comment = previous versions snapshots everywhere
	vfs objects = shadow_copy2
	shadow:mountpoint = $shadow_mntdir
	shadow:snapdirseverywhere = yes

[shadow8]
	path = $shadow_shrdir
	comment = previous versions using snapsharepath
	vfs objects = shadow_copy2
	shadow:mountpoint = $shadow_mntdir
	shadow:snapdir = $shadow_tstdir/.snapshots
	shadow:snapsharepath = share

[shadow_fmt0]
	comment = Testing shadow:format with default option
	vfs object = shadow_copy2
	path = $shadow_shrdir
	read only = no
	guest ok = yes
	shadow:mountpoint = $shadow_mntdir
	shadow:basedir = $shadow_basedir
	shadow:snapdir = $shadow_basedir/.snapshots
	shadow:format = \@GMT-%Y.%m.%d-%H.%M.%S

[shadow_fmt1]
	comment = Testing shadow:format with only date component
	vfs object = shadow_copy2
	path = $shadow_shrdir
	read only = no
	guest ok = yes
	shadow:mountpoint = $shadow_mntdir
	shadow:basedir = $shadow_basedir
	shadow:snapdir = $shadow_basedir/.snapshots
	shadow:format = \@GMT-%Y-%m-%d

[shadow_fmt2]
	comment = Testing shadow:format with some hardcoded prefix
	vfs object = shadow_copy2
	path = $shadow_shrdir
	read only = no
	guest ok = yes
	shadow:mountpoint = $shadow_mntdir
	shadow:basedir = $shadow_basedir
	shadow:snapdir = $shadow_basedir/.snapshots
	shadow:format = snap\@GMT-%Y.%m.%d-%H.%M.%S

[shadow_fmt3]
	comment = Testing shadow:format with modified format
	vfs object = shadow_copy2
	path = $shadow_shrdir
	read only = no
	guest ok = yes
	shadow:mountpoint = $shadow_mntdir
	shadow:basedir = $shadow_basedir
	shadow:snapdir = $shadow_basedir/.snapshots
	shadow:format = \@GMT-%Y.%m.%d-%H_%M_%S-snap

[shadow_fmt4]
	comment = Testing shadow:snapprefix regex
	vfs object = shadow_copy2
	path = $shadow_shrdir
	read only = no
	guest ok = yes
	shadow:mountpoint = $shadow_mntdir
	shadow:basedir = $shadow_basedir
	shadow:snapdir = $shadow_basedir/.snapshots
	shadow:snapprefix = \^s[a-z]*p\$
	shadow:format = _GMT-%Y.%m.%d-%H.%M.%S

[shadow_fmt5]
	comment = Testing shadow:snapprefix with delim regex
	vfs object = shadow_copy2
	path = $shadow_shrdir
	read only = no
	guest ok = yes
	shadow:mountpoint = $shadow_mntdir
	shadow:basedir = $shadow_basedir
	shadow:snapdir = $shadow_basedir/.snapshots
	shadow:delimiter = \@GMT
	shadow:snapprefix = [a-z]*
	shadow:format = \@GMT-%Y.%m.%d-%H.%M.%S

[shadow_wl]
	path = $shadow_shrdir
	comment = previous versions with wide links allowed
	vfs objects = shadow_copy2
	shadow:mountpoint = $shadow_mntdir
	wide links = yes

[shadow_write]
	path = $shadow_tstdir
	comment = previous versions snapshots under mount point
	vfs objects = shadow_copy2 streams_xattr error_inject
	aio write size = 0
	error_inject:pwrite = EBADF
	shadow:mountpoint = $shadow_tstdir

[dfq]
	path = $shrdir/dfree
	vfs objects = acl_xattr fake_acls xattr_tdb fake_dfq
	admin users = $unix_name
	include = $dfqconffile
[dfq_cache]
	path = $shrdir/dfree
	vfs objects = acl_xattr fake_acls xattr_tdb fake_dfq
	admin users = $unix_name
	include = $dfqconffile
	dfree cache time = 60
[dfq_owner]
	path = $shrdir/dfree
	vfs objects = acl_xattr fake_acls xattr_tdb fake_dfq
	inherit owner = yes
	include = $dfqconffile
[quotadir]
	path = $shrdir/quota
	admin users = $unix_name

[acl_xattr_ign_sysacl_posix]
	copy = tmp
	acl_xattr:ignore system acls = yes
	acl_xattr:default acl style = posix
[acl_xattr_ign_sysacl_windows]
	copy = tmp
	acl_xattr:ignore system acls = yes
	acl_xattr:default acl style = windows

[mangle_illegal]
	copy = tmp
        mangled names = illegal

[nosymlinks]
	copy = tmp
	path = $nosymlinks_shrdir
	follow symlinks = no

[local_symlinks]
	copy = tmp
	path = $local_symlinks_shrdir
	follow symlinks = yes

[kernel_oplocks]
	copy = tmp
	kernel oplocks = yes
	vfs objects = streams_xattr xattr_tdb

[streams_xattr]
	copy = tmp
	vfs objects = streams_xattr xattr_tdb

[compound_find]
	copy = tmp
	smbd:find async delay usec = 10000
[error_inject]
	copy = tmp
	vfs objects = error_inject
	include = $errorinjectconf

[delay_inject]
	copy = tmp
	vfs objects = delay_inject
	kernel share modes = no
	kernel oplocks = no
	posix locking = no
	include = $delayinjectconf

[aio_delay_inject]
	copy = tmp
	vfs objects = delay_inject
	delay_inject:pread_send = 2000
	delay_inject:pwrite_send = 2000

[brl_delay_inject1]
	copy = tmp
	vfs objects = delay_inject
	delay_inject:brl_lock_windows = 90
	delay_inject:brl_lock_windows_use_timer = yes

[brl_delay_inject2]
	copy = tmp
	vfs objects = delay_inject
	delay_inject:brl_lock_windows = 90
	delay_inject:brl_lock_windows_use_timer = no

[delete_readonly]
	path = $prefix_abs/share
	delete readonly = yes
	";
	close(CONF);

	my $net = Samba::bindir_path($self, "net");
	my $cmd = "";
	$cmd .= "UID_WRAPPER_ROOT=1 ";
	$cmd .= "SMB_CONF_PATH=\"$conffile\" ";
	$cmd .= "$net setlocalsid $samsid";

	my $net_ret = system($cmd);
	if ($net_ret != 0) {
	    warn("net setlocalsid failed: $net_ret\n$cmd");
	    return undef;
	}

	unless (open(ERRORCONF, ">$errorinjectconf")) {
		warn("Unable to open $errorinjectconf");
		return undef;
	}
	close(ERRORCONF);

	unless (open(DELAYCONF, ">$delayinjectconf")) {
		warn("Unable to open $delayinjectconf");
		return undef;
	}
	close(DELAYCONF);

	unless (open(DFQCONF, ">$dfqconffile")) {
	        warn("Unable to open $dfqconffile");
		return undef;
	}
	close(DFQCONF);

	unless (open(DELAYCONF, ">$globalinjectconf")) {
		warn("Unable to open $globalinjectconf");
		return undef;
	}
	close(DELAYCONF);

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
userdup:x:$uid_userdup:$gid_userdup:userdup gecos:$prefix_abs:/bin/false
pdbtest_wkn:x:$uid_pdbtest_wkn:$gid_everyone:pdbtest_wkn gecos:$prefix_abs:/bin/false
force_user:x:$uid_force_user:$gid_force_user:force user gecos:$prefix_abs:/bin/false
smbget_user:x:$uid_smbget:$gid_domusers:smbget_user gecos:$prefix_abs:/bin/false
user1:x:$uid_user1:$gid_nogroup:user1 gecos:$prefix_abs:/bin/false
user2:x:$uid_user2:$gid_nogroup:user2 gecos:$prefix_abs:/bin/false
gooduser:x:$uid_gooduser:$gid_domusers:gooduser gecos:$prefix_abs:/bin/false
eviluser:x:$uid_eviluser:$gid_domusers:eviluser gecos::/bin/false
slashuser:x:$uid_slashuser:$gid_domusers:slashuser gecos:/:/bin/false
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
userdup:x:$gid_userdup:$unix_name
everyone:x:$gid_everyone:
force_user:x:$gid_force_user:
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
	print HOSTS "${server_ip} ${hostname}.${dns_domain} ${hostname}\n";
	print HOSTS "${server_ipv6} ${hostname}.${dns_domain} ${hostname}\n";
	close(HOSTS);

	$resolv_conf = "$privatedir/no_resolv.conf" unless defined($resolv_conf);

	foreach my $evlog (@eventlog_list) {
		my $evlogtdb = "$eventlogdir/$evlog.tdb";
		open(EVENTLOG, ">$evlogtdb") or die("Unable to open $evlogtdb");
		close(EVENTLOG);
	}

	$createuser_env{NSS_WRAPPER_PASSWD} = $nss_wrapper_passwd;
	$createuser_env{NSS_WRAPPER_GROUP} = $nss_wrapper_group;
	$createuser_env{NSS_WRAPPER_HOSTS} = $nss_wrapper_hosts;
	$createuser_env{NSS_WRAPPER_HOSTNAME} = "${hostname}.samba.example.com";
	if ($ENV{SAMBA_DNS_FAKING}) {
		$createuser_env{RESOLV_WRAPPER_HOSTS} = $dns_host_file;
	} else {
		$createuser_env{RESOLV_WRAPPER_CONF} = $resolv_conf;
	}
	$createuser_env{RESOLV_CONF} = $resolv_conf;

	createuser($self, $unix_name, $password, $conffile, \%createuser_env) || die("Unable to create user");
	createuser($self, "force_user", $password, $conffile, \%createuser_env) || die("Unable to create force_user");
	createuser($self, "smbget_user", $password, $conffile, \%createuser_env) || die("Unable to create smbget_user");
	createuser($self, "user1", $password, $conffile, \%createuser_env) || die("Unable to create user1");
	createuser($self, "user2", $password, $conffile, \%createuser_env) || die("Unable to create user2");
	createuser($self, "gooduser", $password, $conffile, \%createuser_env) || die("Unable to create gooduser");
	createuser($self, "eviluser", $password, $conffile, \%createuser_env) || die("Unable to create eviluser");
	createuser($self, "slashuser", $password, $conffile, \%createuser_env) || die("Unable to create slashuser");

	open(DNS_UPDATE_LIST, ">$prefix/dns_update_list") or die("Unable to open $$prefix/dns_update_list");
	print DNS_UPDATE_LIST "A $server. $server_ip\n";
	print DNS_UPDATE_LIST "AAAA $server. $server_ipv6\n";
	close(DNS_UPDATE_LIST);

	print "DONE\n";

	$ret{SERVER_IP} = $server_ip;
	$ret{SERVER_IPV6} = $server_ipv6;
	$ret{NMBD_TEST_LOG} = "$prefix/nmbd_test.log";
	$ret{NMBD_TEST_LOG_POS} = 0;
	$ret{WINBINDD_TEST_LOG} = "$prefix/winbindd_test.log";
	$ret{WINBINDD_TEST_LOG_POS} = 0;
	$ret{SMBD_TEST_LOG} = "$prefix/smbd_test.log";
	$ret{SMBD_TEST_LOG_POS} = 0;
	$ret{SERVERCONFFILE} = $conffile;
	$ret{TESTENV_DIR} = $prefix_abs;
	$ret{CONFIGURATION} ="-s $conffile";
	$ret{LOCK_DIR} = $lockdir;
	$ret{SERVER} = $server;
	$ret{USERNAME} = $unix_name;
	$ret{USERID} = $unix_uid;
	$ret{DOMAIN} = $domain;
	$ret{SAMSID} = $samsid;
	$ret{NETBIOSNAME} = $server;
	$ret{PASSWORD} = $password;
	$ret{PIDDIR} = $piddir;
	$ret{SELFTEST_WINBINDD_SOCKET_DIR} = $wbsockdir;
	$ret{NMBD_SOCKET_DIR} = $nmbdsockdir;
	$ret{SOCKET_WRAPPER_DEFAULT_IFACE} = $swiface;
	$ret{NSS_WRAPPER_PASSWD} = $nss_wrapper_passwd;
	$ret{NSS_WRAPPER_GROUP} = $nss_wrapper_group;
	$ret{NSS_WRAPPER_HOSTS} = $nss_wrapper_hosts;
	$ret{NSS_WRAPPER_HOSTNAME} = "${hostname}.samba.example.com";
	$ret{NSS_WRAPPER_MODULE_SO_PATH} = Samba::nss_wrapper_winbind_so_path($self);
	$ret{NSS_WRAPPER_MODULE_FN_PREFIX} = "winbind";
	if ($ENV{SAMBA_DNS_FAKING}) {
		$ret{RESOLV_WRAPPER_HOSTS} = $dns_host_file;
	} else {
		$ret{RESOLV_WRAPPER_CONF} = $resolv_conf;
	}
	$ret{RESOLV_CONF} = $resolv_conf;
	$ret{LOCAL_PATH} = "$shrdir";
        $ret{LOGDIR} = $logdir;

	#
	# Avoid hitting system krb5.conf -
	# An env that needs Kerberos will reset this to the real
	# value.
	#
	$ret{KRB5_CONFIG} = abs_path($prefix) . "/no_krb5.conf";

	# Define KRB5CCNAME for each environment we set up
	$ret{KRB5_CCACHE} = abs_path($prefix) . "/krb5ccache";
	$ENV{KRB5CCNAME} = $ret{KRB5_CCACHE};

	return \%ret;
}

sub wait_for_start($$$$$)
{
	my ($self, $envvars, $nmbd, $winbindd, $smbd) = @_;
	my $cmd;
	my $netcmd;
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
				system("$nmblookup $envvars->{CONFIGURATION} -U 10.255.255.255 __SAMBA__");
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

	if ($winbindd eq "yes" or $winbindd eq "offline") {
	    print "checking for winbindd\n";
	    my $count = 0;
	    $cmd = "SELFTEST_WINBINDD_SOCKET_DIR='$envvars->{SELFTEST_WINBINDD_SOCKET_DIR}' ";
	    $cmd .= "NSS_WRAPPER_PASSWD='$envvars->{NSS_WRAPPER_PASSWD}' ";
	    $cmd .= "NSS_WRAPPER_GROUP='$envvars->{NSS_WRAPPER_GROUP}' ";
	    if ($winbindd eq "yes") {
		$cmd .= Samba::bindir_path($self, "wbinfo") . " --ping-dc";
	    } elsif ($winbindd eq "offline") {
		$cmd .= Samba::bindir_path($self, "wbinfo") . " --ping";
	    }

	    do {
		$ret = system($cmd);
		if ($ret != 0) {
		    sleep(1);
		}
		$count++;
	    } while ($ret != 0 && $count < 20);
	    if ($count == 20) {
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
		if (defined($envvars->{GNUTLS_FORCE_FIPS_MODE})) {
			# We don't have NTLM in FIPS mode, so lets use
			# smbcontrol instead of smbclient.
			$cmd = Samba::bindir_path($self, "smbcontrol");
			$cmd .= " $envvars->{CONFIGURATION}";
			$cmd .= " smbd ping";
		} else {
			# This uses NTLM which is not available in FIPS
			$cmd = Samba::bindir_path($self, "smbclient");
			$cmd .= " $envvars->{CONFIGURATION}";
			$cmd .= " -L $envvars->{SERVER}";
			$cmd .= " -U%";
			$cmd .= " -I $envvars->{SERVER_IP}";
			$cmd .= " -p 139";
		}

		$ret = system($cmd);
		if ($ret != 0) {
		    sleep(1);
		}
		$count++
	    } while ($ret != 0 && $count < 20);
	    if ($count == 20) {
		print "SMBD failed to start up in a reasonable time (20sec)\n";
		teardown_env($self, $envvars);
		return 0;
	    }
	}

	# Ensure we have domain users mapped.
	$netcmd = "NSS_WRAPPER_PASSWD='$envvars->{NSS_WRAPPER_PASSWD}' ";
	$netcmd .= "NSS_WRAPPER_GROUP='$envvars->{NSS_WRAPPER_GROUP}' ";
	$netcmd .= "UID_WRAPPER_ROOT='1' ";
	$netcmd .= Samba::bindir_path($self, "net") ." $envvars->{CONFIGURATION} ";

	$cmd = $netcmd . "groupmap delete ntgroup=domusers";
	$ret = system($cmd);

	$cmd = $netcmd . "groupmap add rid=513 unixgroup=domusers type=domain";
	$ret = system($cmd);
	if ($ret != 0) {
		print("\"$cmd\" failed\n");
		return 1;
	}

	$cmd = $netcmd . "groupmap delete ntgroup=domadmins";
	$ret = system($cmd);

	$cmd = $netcmd . "groupmap add rid=512 unixgroup=domadmins type=domain";
	$ret = system($cmd);
	if ($ret != 0) {
		print("\"$cmd\" failed\n");
		return 1;
	}

	$cmd = $netcmd . "groupmap delete ntgroup=everyone";
	$ret = system($cmd);

	$cmd = $netcmd . "groupmap add sid=S-1-1-0 unixgroup=everyone type=builtin";
	$ret = system($cmd);
	if ($ret != 0) {
		print("\"$cmd\" failed\n");
		return 1;
	}

	# note: creating builtin groups requires winbindd for the
	# unix id allocator
	my $create_builtin_users = "no";
	if ($winbindd eq "yes") {
		$cmd = "SELFTEST_WINBINDD_SOCKET_DIR='$envvars->{SELFTEST_WINBINDD_SOCKET_DIR}' ";
		$cmd .= "NSS_WRAPPER_PASSWD='$envvars->{NSS_WRAPPER_PASSWD}' ";
		$cmd .= "NSS_WRAPPER_GROUP='$envvars->{NSS_WRAPPER_GROUP}' ";
		$cmd .= Samba::bindir_path($self, "wbinfo") . " --sid-to-gid=S-1-5-32-545";
		my $wbinfo_out = qx($cmd 2>&1);
		if ($? != 0) {
			# wbinfo doesn't give us a better error code then
			# WBC_ERR_DOMAIN_NOT_FOUND, but at least that's
			# different then WBC_ERR_WINBIND_NOT_AVAILABLE
			if ($wbinfo_out !~ /WBC_ERR_DOMAIN_NOT_FOUND/) {
				print("Failed to run \"wbinfo --sid-to-gid=S-1-5-32-545\": $wbinfo_out");
				teardown_env($self, $envvars);
				return 0;
			}
			$create_builtin_users = "yes";
		}
	}
	if ($create_builtin_users eq "yes") {
	    $cmd = "SELFTEST_WINBINDD_SOCKET_DIR='$envvars->{SELFTEST_WINBINDD_SOCKET_DIR}' ";
	    $cmd .= "NSS_WRAPPER_PASSWD='$envvars->{NSS_WRAPPER_PASSWD}' ";
	    $cmd .= "NSS_WRAPPER_GROUP='$envvars->{NSS_WRAPPER_GROUP}' ";
	    $cmd .= Samba::bindir_path($self, "net") . " $envvars->{CONFIGURATION} ";
	    $cmd .= "sam createbuiltingroup Users";
	    $ret = system($cmd);
	    if ($ret != 0) {
	        print "Failed to create BUILTIN\\Users group\n";
		teardown_env($self, $envvars);
	        return 0;
	    }

	    $cmd = Samba::bindir_path($self, "net") . " $envvars->{CONFIGURATION} ";
	    $cmd .= "cache del IDMAP/SID2XID/S-1-5-32-545";
	    system($cmd);

	    $cmd = "SELFTEST_WINBINDD_SOCKET_DIR='$envvars->{SELFTEST_WINBINDD_SOCKET_DIR}' ";
	    $cmd .= "NSS_WRAPPER_PASSWD='$envvars->{NSS_WRAPPER_PASSWD}' ";
	    $cmd .= "NSS_WRAPPER_GROUP='$envvars->{NSS_WRAPPER_GROUP}' ";
	    $cmd .= Samba::bindir_path($self, "wbinfo") . " --sid-to-gid=S-1-5-32-545";
	    $ret = system($cmd);
	    if ($ret != 0) {
		print "Missing \"BUILTIN\\Users\", did net sam createbuiltingroup Users fail?\n";
		teardown_env($self, $envvars);
		return 0;
	    }
	}

	print $self->getlog_env($envvars);

	return 1;
}

##
## provision and start of ctdb
##
sub setup_ctdb($$)
{
	my ($self, $prefix) = @_;
	my $num_nodes = 3;

	my $data = $self->provision_ctdb($prefix, $num_nodes);
	$data or return undef;

	my $rc = $self->check_or_start_ctdb($data);
	if (not $rc) {
		print("check_or_start_ctdb() failed\n");
		return undef;
	}

	$rc = $self->wait_for_start_ctdb($data);
	if (not $rc) {
		print "Cluster startup failed\n";
		return undef;
	}

	return $data;
}

sub provision_ctdb($$$$)
{
	my ($self, $prefix, $num_nodes, $no_delete_prefix) = @_;
	my $rc;

	print "PROVISIONING CTDB...\n";

	my $prefix_abs = abs_path($prefix);

	#
	# check / create directories:
	#
	die ("prefix_abs = ''") if $prefix_abs eq "";
	die ("prefix_abs = '/'") if $prefix_abs eq "/";

	mkdir ($prefix_abs, 0777);

	print "CREATE CTDB TEST ENVIRONMENT in '$prefix_abs'...\n";

	if (not defined($no_delete_prefix) or not $no_delete_prefix) {
		system("rm -rf $prefix_abs/*");
	}

	#
	# Per-node data
	#
	my @nodes = ();
	for (my $i = 0; $i < $num_nodes; $i++) {
		my %node = ();
		my $server_name = "ctdb${i}";
		my $pub_iface = Samba::get_interface($server_name);
		my $ip = Samba::get_ipv4_addr($server_name);

		$node{NODE_NUMBER} = "$i";
		$node{SERVER_NAME} = "$server_name";
		$node{SOCKET_WRAPPER_DEFAULT_IFACE} = "$pub_iface";
		$node{IP} = "$ip";

		push(@nodes, \%node);
	}

	#
	# nodes
	#
	my $nodes_file = "$prefix/nodes.in";
	unless (open(NODES, ">$nodes_file")) {
		warn("Unable to open nodesfile '$nodes_file'");
		return undef;
	}
	for (my $i = 0; $i < $num_nodes; $i++) {
		my $ip = $nodes[$i]->{IP};
		print NODES "${ip}\n";
	}
	close(NODES);

	#
	# local_daemons.sh setup
	#
	# Socket wrapper setup is done by selftest.pl, so don't use
	# the CTDB-specific setup
	#
	my $cmd;
	$cmd .= "ctdb/tests/local_daemons.sh " . $prefix_abs . " setup";
	$cmd .= " -n " . $num_nodes;
	$cmd .= " -N " . $nodes_file;
	# CTDB should not attempt to manage public addresses -
	# clients should just connect to CTDB private addresses
	$cmd .= " -P " . "/dev/null";

	my $ret = system($cmd);
	if ($ret != 0) {
		print("\"$cmd\" failed\n");
		return undef;
	}

	#
	# Unix domain socket and node directory for each daemon
	#
	for (my $i = 0; $i < $num_nodes; $i++) {
		my ($cmd, $ret, $out);

		my $cmd_prefix = "ctdb/tests/local_daemons.sh ${prefix_abs}";

		#
		# socket
		#

		$cmd = "${cmd_prefix} print-socket ${i}";

		$out = `$cmd`;
		$ret = $?;
		if ($ret != 0) {
		    print("\"$cmd\" failed\n");
		    return undef;
		}
		chomp $out;
		$nodes[$i]->{SOCKET_FILE} = "$out";

		#
		# node directory
		#

		$cmd = "${cmd_prefix} onnode ${i} 'echo \$CTDB_BASE'";

		$out = `$cmd`;
		$ret = $?;
		if ($ret != 0) {
		    print("\"$cmd\" failed\n");
		    return undef;
		}
		chomp $out;
		$nodes[$i]->{NODE_PREFIX} = "$out";
	}

	my %ret = ();

	$ret{CTDB_PREFIX} = "$prefix";
	$ret{NUM_NODES} = $num_nodes;
	$ret{CTDB_NODES} = \@nodes;
	$ret{CTDB_NODES_FILE} = $nodes_file;

	return \%ret;
}

sub check_or_start_ctdb($$) {
	my ($self, $data) = @_;

	my $prefix = $data->{CTDB_PREFIX};
	my $num_nodes = $data->{NUM_NODES};
	my $nodes = $data->{CTDB_NODES};
	my $STDIN_READER;

	# Share a single stdin pipe for all nodes
	pipe($STDIN_READER, $data->{CTDB_STDIN_PIPE});

	for (my $i = 0; $i < $num_nodes; $i++) {
		my $node = $nodes->[$i];

		$node->{STDIN_PIPE} = $data->{CTDB_STDIN_PIPE};

		my $cmd = "ctdb/tests/local_daemons.sh";
		my @full_cmd = ("$cmd", "$prefix", "start", "$i");
		# Dummy environment variables to avoid
		# Samba3::get_env_for_process() from generating them
		# and including UID_WRAPPER_ROOT=1, which causes
		# "Unable to secure ctdb socket" error.
		my $env_vars = {
			CTDB_DUMMY => "1",
		};
		my $daemon_ctx = {
			NAME => "ctdbd",
			BINARY_PATH => $cmd,
			FULL_CMD => [ @full_cmd ],
			TEE_STDOUT => 1,
			LOG_FILE => "/dev/null",
			ENV_VARS => $env_vars,
		};

		print "STARTING CTDBD (node ${i})\n";

		# This does magic with $STDIN_READER, so use it
		my $ret = Samba::fork_and_exec($self,
					       $node,
					       $daemon_ctx,
					       $STDIN_READER);

		if ($ret == 0) {
			print("\"$cmd\" failed\n");
			teardown_env_ctdb($self, $data);
			return 0;
		}
	}

	close($STDIN_READER);

	return 1;
}

sub wait_for_start_ctdb($$)
{
	my ($self, $data) = @_;

	my $prefix = $data->{CTDB_PREFIX};

	print "Wait for ctdbd...\n";

	my $ctdb = Samba::bindir_path($self, "ctdb");
	my $cmd;
	$cmd .= "ctdb/tests/local_daemons.sh ${prefix} onnode all";
	$cmd .= " ${ctdb} nodestatus all 2>&1";

	my $count = 0;
	my $wait_seconds = 60;
	my $out;

	until ($count > $wait_seconds) {
		$out = `$cmd`;
		my $ret = $?;
		if ($ret == 0) {
			print "\ncluster became healthy\n";
			last;
		}
		print "Waiting for CTDB...\n";
		sleep(1);
		$count++;
	}

	if ($count > $wait_seconds) {
		print "\nGiving up to wait for CTDB...\n";
		print "${out}\n\n";
		print "CTDB log:\n";
		$cmd = "ctdb/tests/local_daemons.sh ${prefix} print-log all >&2";
		system($cmd);
		teardown_env_ctdb($self, $data);
		return 0;
	}

	print "\nCTDB initialized\n";

	return 1;
}

1;
