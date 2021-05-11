#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

package Samba;

use strict;
use warnings;
use target::Samba3;
use target::Samba4;
use POSIX;
use Cwd qw(abs_path);
use IO::Poll qw(POLLIN);

sub new($$$$$) {
	my ($classname, $bindir, $srcdir, $server_maxtime,
	    $opt_socket_wrapper_pcap, $opt_socket_wrapper_keep_pcap) = @_;

	my $self = {
	    opt_socket_wrapper_pcap => $opt_socket_wrapper_pcap,
	    opt_socket_wrapper_keep_pcap => $opt_socket_wrapper_keep_pcap,
	};
	$self->{samba3} = new Samba3($self, $bindir, $srcdir, $server_maxtime);
	$self->{samba4} = new Samba4($self, $bindir, $srcdir, $server_maxtime);
	bless $self;
	return $self;
}

%Samba::ENV_DEPS = (%Samba3::ENV_DEPS, %Samba4::ENV_DEPS);
our %ENV_DEPS;

%Samba::ENV_DEPS_POST = (%Samba3::ENV_DEPS_POST, %Samba4::ENV_DEPS_POST);
our %ENV_DEPS_POST;

%Samba::ENV_TARGETS = (
	(map { $_ => "Samba3" } keys %Samba3::ENV_DEPS),
	(map { $_ => "Samba4" } keys %Samba4::ENV_DEPS),
);
our %ENV_TARGETS;

%Samba::ENV_NEEDS_AD_DC = (
	(map { $_ => 1 } keys %Samba4::ENV_DEPS)
);
our %ENV_NEEDS_AD_DC;
foreach my $env (keys %Samba3::ENV_DEPS) {
    $ENV_NEEDS_AD_DC{$env} = ($env =~ /^ad_/);
}

sub setup_pcap($$)
{
	my ($self, $name) = @_;

	return unless ($self->{opt_socket_wrapper_pcap});
	return unless defined($ENV{SOCKET_WRAPPER_PCAP_DIR});

	my $fname = $name;
	$fname =~ s%[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\-]%_%g;

	my $pcap_file = "$ENV{SOCKET_WRAPPER_PCAP_DIR}/$fname.pcap";

	SocketWrapper::setup_pcap($pcap_file);

	return $pcap_file;
}

sub cleanup_pcap($$$)
{
	my ($self, $pcap_file, $exitcode) = @_;

	return unless ($self->{opt_socket_wrapper_pcap});
	return if ($self->{opt_socket_wrapper_keep_pcap});
	return unless ($exitcode == 0);
	return unless defined($pcap_file);

	unlink($pcap_file);
}

sub setup_env($$$)
{
	my ($self, $envname, $path) = @_;

	my $targetname = $ENV_TARGETS{$envname};
	if (not defined($targetname)) {
		warn("Samba can't provide environment '$envname'");
		return "UNKNOWN";
	}

	my %targetlookup = (
		"Samba3" => $self->{samba3},
		"Samba4" => $self->{samba4}
	);
	my $target = $targetlookup{$targetname};

	if (defined($target->{vars}->{$envname})) {
		return $target->{vars}->{$envname};
	}

	$target->{vars}->{$envname} = "";

	my @dep_vars;
	foreach(@{$ENV_DEPS{$envname}}) {
		my $vars = $self->setup_env($_, $path);
		if (defined($vars)) {
			push(@dep_vars, $vars);
		} else {
			warn("Failed setting up $_ as a dependency of $envname");
			return undef;
		}
	}

	$ENV{ENVNAME} = $envname;
	# Avoid hitting system krb5.conf -
	# An env that needs Kerberos will reset this to the real value.
	$ENV{KRB5_CONFIG} = "$path/no_krb5.conf";
	$ENV{RESOLV_CONF} = "$path/no_resolv.conf";

	my $setup_name = $ENV_TARGETS{$envname}."::setup_".$envname;
	my $setup_sub = \&$setup_name;
	my $setup_pcap_file = $self->setup_pcap("env-$ENV{ENVNAME}-setup");
	my $env = &$setup_sub($target, "$path/$envname", @dep_vars);
	$self->cleanup_pcap($setup_pcap_file, not defined($env));
	SocketWrapper::setup_pcap(undef);

	if (not defined($env)) {
		warn("failed to start up environment '$envname'");
		return undef;
	}

	$target->{vars}->{$envname} = $env;
	$target->{vars}->{$envname}->{target} = $target;

	foreach(@{$ENV_DEPS_POST{$envname}}) {
		if (not defined $_) {
			continue;
		}
		my $vars = $self->setup_env($_, $path);
		if (not defined($vars)) {
			return undef;
		}
	}

	return $env;
}

sub bindir_path($$) {
	my ($object, $path) = @_;

	my $valpath = "$object->{bindir}/$path";
	my $python_cmd = "";
	my $result = $path;
	if (defined $ENV{'PYTHON'}) {
		$python_cmd = $ENV{'PYTHON'} . " ";
	}

	if (-f $valpath or -d $valpath) {
		$result = $valpath;
	}
	# make sure we prepend samba-tool with calling $PYTHON python version
	if ($path eq "samba-tool") {
		$result = $python_cmd . $result;
	}
	return $result;
}

sub nss_wrapper_winbind_so_path($) {
        my ($object) = @_;
	my $ret = $ENV{NSS_WRAPPER_WINBIND_SO_PATH};
        if (not defined($ret)) {
	    $ret = bindir_path($object, "shared/libnss_wrapper_winbind.so.2");
	    $ret = abs_path($ret);
	}
	return $ret;
}

sub copy_file_content($$)
{
	my ($in, $out) = @_;
	open(IN, "${in}") or die("failed to open in[${in}] for reading: $!");
	open(OUT, ">${out}") or die("failed to open out[${out}] for writing: $!");
	while(<IN>) {
		print OUT $_;
	}
	close(OUT);
	close(IN);
}

sub prepare_keyblobs($)
{
	my ($ctx) = @_;

	my $cadir = "$ENV{SRCDIR_ABS}/selftest/manage-ca/CA-samba.example.com";
	my $cacert = "$cadir/Public/CA-samba.example.com-cert.pem";
	my $cacrl_pem = "$cadir/Public/CA-samba.example.com-crl.pem";
	my $dcdnsname = "$ctx->{hostname}.$ctx->{dnsname}";
	my $dcdir = "$cadir/DCs/$dcdnsname";
	my $dccert = "$dcdir/DC-$dcdnsname-cert.pem";
	my $dckey_private = "$dcdir/DC-$dcdnsname-private-key.pem";
	my $adminprincipalname = "administrator\@$ctx->{dnsname}";
	my $admindir = "$cadir/Users/$adminprincipalname";
	my $admincert = "$admindir/USER-$adminprincipalname-cert.pem";
	my $adminkey_private = "$admindir/USER-$adminprincipalname-private-key.pem";
	my $pkinitprincipalname = "pkinit\@$ctx->{dnsname}";
	my $ca_pkinitdir = "$cadir/Users/$pkinitprincipalname";
	my $pkinitcert = "$ca_pkinitdir/USER-$pkinitprincipalname-cert.pem";
	my $pkinitkey_private = "$ca_pkinitdir/USER-$pkinitprincipalname-private-key.pem";

	my $tlsdir = "$ctx->{tlsdir}";
	my $pkinitdir = "$ctx->{prefix_abs}/pkinit";
	#TLS and PKINIT crypto blobs
	my $dhfile = "$tlsdir/dhparms.pem";
	my $cafile = "$tlsdir/ca.pem";
	my $crlfile = "$tlsdir/crl.pem";
	my $certfile = "$tlsdir/cert.pem";
	my $keyfile = "$tlsdir/key.pem";
	my $admincertfile = "$pkinitdir/USER-$adminprincipalname-cert.pem";
	my $adminkeyfile = "$pkinitdir/USER-$adminprincipalname-private-key.pem";
	my $pkinitcertfile = "$pkinitdir/USER-$pkinitprincipalname-cert.pem";
	my $pkinitkeyfile = "$pkinitdir/USER-$pkinitprincipalname-private-key.pem";

	mkdir($tlsdir, 0700);
	mkdir($pkinitdir, 0700);
	my $oldumask = umask;
	umask 0077;

	# This is specified here to avoid draining entropy on every run
	# generate by
	# openssl dhparam -out dhparms.pem -text -2 8192
	open(DHFILE, ">$dhfile");
	print DHFILE <<EOF;
-----BEGIN DH PARAMETERS-----
MIIECAKCBAEAlcpjuJptCzC2bIIApLuyFLw2nODQUztqs/peysY9e3LgWh/xrc87
SWJNSUrqFJFh2m357WH0XGcTdTk0b/8aIYIWjbwEhWR/5hZ+1x2TDrX1awkYayAe
pr0arycmWHaAmhw+m+dBdj2O2jRMe7gn0ha85JALNl+Z3wv2q2eys8TIiQ2dbHPx
XvpMmlAv7QHZnpSpX/XgueQr6T3EYggljppZwk1fe4W2cxBjCv9w/Q83pJXMEVVB
WESEQPZC38v6hVIXIlF4J7jXjV3+NtCLL4nvsy0jrLEntyKz5OB8sNPRzJr0Ju2Y
yXORCSMMXMygP+dxJtQ6txzQYWyaCYN1HqHDZy3cFL9Qy8kTFqIcW56Lti2GsW/p
jSMzEOa1NevhKNFL3dSZJx5m+5ZeMvWXlCqXSptmVdbs5wz5jkMUm/E6pVfM5lyb
Ttlcq2iYPqnJz1jcL5xwhoufID8zSJCPJ7C0jb0Ngy5wLIUZfjXJUXxUyxTnNR9i
N9Sc+UkDvLxnCW+qzjyPXGlQU1SsJwMLWa2ZecL/uYE4bOdcN3g+5WHkevyDnXqR
+yy9x7sGXjBT3bRWK5tVHJWOi6eBu1hp39U6aK8oOJWiUt3vmC2qEdIsT6JaLNNi
YKrSfRGBf19IJBaagen1S19bb3dnmwoU1RaWM0EeJQW1oXOBg7zLisB2yuu5azBn
tse00+0nc+GbH2y+jP0sE7xil1QeilZl+aQ3tX9vL0cnCa+8602kXxU7P5HaX2+d
05pvoHmeZbDV85io36oF976gBYeYN+qAkTUMsIZhuLQDuyn0963XOLyn1Pm6SBrU
OkIZXW7WoKEuO/YSfizUIqXwmAMJjnEMJCWG51MZZKx//9Hsdp1RXSm/bRSbvXB7
MscjvQYWmfCFnIk8LYnEt3Yey40srEiS9xyZqdrvobxz+sU1XcqR38kpVf4gKASL
xURia64s4emuJF+YHIObyydazQ+6/wX/C+m+nyfhuxSO6j1janPwtYbU+Uj3TzeM
04K1mpPQpZcaMdZZiNiu7i8VJlOPKAz7aJT8TnMMF5GMyzyLpSMpc+NF9L/BSocV
/cUM4wQT2PTHrcyYzmTVH7c9bzBkuxqrwVB1BY1jitDV9LIYIVBglKcX88qrfHIM
XiXPAIwGclD59qm2cG8OdM9NA5pNMI119KuUAIJsUdgPbR1LkT2XTT15YVoHmFSQ
DlaWOXn4td031jr0EisX8QtFR7+/0Nfoni6ydFGs5fNH/L1ckq6FEO4OhgucJw9H
YRmiFlsQBQNny78vNchwZne3ZixkShtGW0hWDdi2n+h7St1peNJCNJjMbEhRsPRx
RmNGWh4AL8rho4RO9OBao0MnUdjbbffD+wIBAg==
-----END DH PARAMETERS-----
EOF
	close(DHFILE);

	if (! -e ${dckey_private}) {
		umask $oldumask;
		return;
	}

	copy_file_content(${cacert}, ${cafile});
	copy_file_content(${cacrl_pem}, ${crlfile});
	copy_file_content(${dccert}, ${certfile});
	copy_file_content(${dckey_private}, ${keyfile});
	if (-e ${adminkey_private}) {
		copy_file_content(${admincert}, ${admincertfile});
		copy_file_content(${adminkey_private}, ${adminkeyfile});
	}
	if (-e ${pkinitkey_private}) {
		copy_file_content(${pkinitcert}, ${pkinitcertfile});
		copy_file_content(${pkinitkey_private}, ${pkinitkeyfile});
	}

	# COMPAT stuff to be removed in a later commit
	my $kdccertfile = "$tlsdir/kdc.pem";
	copy_file_content(${dccert}, ${kdccertfile});

	umask $oldumask;
}

sub copy_gnupg_home($)
{
	my ($ctx) = @_;

	my $gnupg_srcdir = "$ENV{SRCDIR_ABS}/selftest/gnupg";
	my @files = (
		"gpg.conf",
		"pubring.gpg",
		"secring.gpg",
		"trustdb.gpg",
	);

	my $oldumask = umask;
	umask 0077;
	mkdir($ctx->{gnupghome}, 0777);
	umask 0177;
	foreach my $file (@files) {
		my $srcfile = "${gnupg_srcdir}/${file}";
		my $dstfile = "$ctx->{gnupghome}/${file}";
		copy_file_content(${srcfile}, ${dstfile});
	}
	umask $oldumask;
}

sub mk_krb5_conf($$)
{
	my ($ctx) = @_;

	unless (open(KRB5CONF, ">$ctx->{krb5_conf}")) {
	        warn("can't open $ctx->{krb5_conf}$?");
		return undef;
	}

	my $our_realms_stanza = mk_realms_stanza($ctx->{realm},
						 $ctx->{dnsname},
						 $ctx->{domain},
						 $ctx->{kdc_ipv4});
	print KRB5CONF "
#Generated krb5.conf for $ctx->{realm}

[libdefaults]
 default_realm = $ctx->{realm}
 dns_lookup_realm = false
 dns_lookup_kdc = true
 ticket_lifetime = 24h
 forwardable = yes

 # We are running on the same machine, do not correct
 # system clock differences
 kdc_timesync = 0

";

	if (defined($ENV{MITKRB5})) {
		print KRB5CONF "
 # Set the grace clocskew to 5 seconds
 # This is especially required by samba3.raw.session krb5 and
 # reauth tests when not using Heimdal
 clockskew = 5
    ";
	}

	if (defined($ctx->{krb5_ccname})) {
		print KRB5CONF "
 default_ccache_name = $ctx->{krb5_ccname}
";
	}


        if (defined($ctx->{supported_enctypes})) {
		print KRB5CONF "
 default_etypes = $ctx->{supported_enctypes}
 default_as_etypes = $ctx->{supported_enctypes}
 default_tgs_enctypes = $ctx->{supported_enctypes}
 default_tkt_enctypes = $ctx->{supported_enctypes}
 permitted_enctypes = $ctx->{supported_enctypes}
";
	}

	print KRB5CONF "
[realms]
 $our_realms_stanza
";


        if (defined($ctx->{tlsdir})) {
	       print KRB5CONF "

[appdefaults]
	pkinit_anchors = FILE:$ctx->{tlsdir}/ca.pem

[kdc]
	enable-pkinit = true
	pkinit_identity = FILE:$ctx->{tlsdir}/kdc.pem,$ctx->{tlsdir}/key.pem
	pkinit_anchors = FILE:$ctx->{tlsdir}/ca.pem

";
        }
	close(KRB5CONF);
}

sub mk_realms_stanza($$$$)
{
	my ($realm, $dnsname, $domain, $kdc_ipv4) = @_;
	my $lc_domain = lc($domain);

	my $realms_stanza = "
 $realm = {
  kdc = $kdc_ipv4:88
  admin_server = $kdc_ipv4:88
  default_domain = $dnsname
 }
 $dnsname = {
  kdc = $kdc_ipv4:88
  admin_server = $kdc_ipv4:88
  default_domain = $dnsname
 }
 $domain = {
  kdc = $kdc_ipv4:88
  admin_server = $kdc_ipv4:88
  default_domain = $dnsname
 }
 $lc_domain = {
  kdc = $kdc_ipv4:88
  admin_server = $kdc_ipv4:88
  default_domain = $dnsname
 }

";
        return $realms_stanza;
}

sub mk_mitkdc_conf($$)
{
	# samba_kdb_dir is the path to mit_samba.so
	my ($ctx, $samba_kdb_dir) = @_;

	unless (open(KDCCONF, ">$ctx->{mitkdc_conf}")) {
	        warn("can't open $ctx->{mitkdc_conf}$?");
		return undef;
	}

	print KDCCONF "
# Generated kdc.conf for $ctx->{realm}

[kdcdefaults]
	kdc_ports = 88
	kdc_tcp_ports = 88

[realms]
	$ctx->{realm} = {
	}

	$ctx->{dnsname} = {
	}

	$ctx->{domain} = {
	}

[dbmodules]
	db_module_dir = $samba_kdb_dir

	$ctx->{realm} = {
		db_library = samba
	}

	$ctx->{dnsname} = {
		db_library = samba
	}

	$ctx->{domain} = {
		db_library = samba
	}

[logging]
	kdc = FILE:$ctx->{logdir}/mit_kdc.log
";

	close(KDCCONF);
}

sub mk_resolv_conf($$)
{
	my ($ctx) = @_;

	unless (open(RESOLV_CONF, ">$ctx->{resolv_conf}")) {
		warn("can't open $ctx->{resolv_conf}$?");
		return undef;
	}

	print RESOLV_CONF "nameserver $ctx->{dns_ipv4}\n";
	print RESOLV_CONF "nameserver $ctx->{dns_ipv6}\n";
	close(RESOLV_CONF);
}

sub realm_to_ip_mappings
{
	# this maps the DNS realms for the various testenvs to the corresponding
	# PDC (i.e. the first DC created for that realm).
	my %realm_to_pdc_mapping = (
		'adnonssdom.samba.example.com'    => 'addc_no_nss',
		'adnontlmdom.samba.example.com'   => 'addc_no_ntlm',
		'samba2000.example.com'           => 'dc5',
		'samba2003.example.com'           => 'dc6',
		'samba2008r2.example.com'         => 'dc7',
		'addom.samba.example.com'         => 'addc',
		'addom2.samba.example.com'        => 'addcsmb1',
		'sub.samba.example.com'           => 'localsubdc',
		'chgdcpassword.samba.example.com' => 'chgdcpass',
		'backupdom.samba.example.com'     => 'backupfromdc',
		'renamedom.samba.example.com'     => 'renamedc',
		'labdom.samba.example.com'        => 'labdc',
		'schema.samba.example.com'        => 'liveupgrade1dc',
		'prockilldom.samba.example.com'   => 'prockilldc',
		'proclimit.samba.example.com'     => 'proclimitdc',
		'samba.example.com'               => 'localdc',
		'fips.samba.example.com'          => 'fipsdc',
	);

	my @mapping = ();

	# convert the hashmap to a list of key=value strings, where key is the
	# realm and value is the IP address
	foreach my $realm (sort(keys %realm_to_pdc_mapping)) {
		my $pdc = $realm_to_pdc_mapping{$realm};
		my $ipaddr = get_ipv4_addr($pdc);
		push(@mapping, "$realm=$ipaddr");
	}
	# return the mapping as a single comma-separated string
	return join(',', @mapping);
}

sub get_interface($)
{
	my ($netbiosname) = @_;
	$netbiosname = lc($netbiosname);

	# this maps the SOCKET_WRAPPER_DEFAULT_IFACE value for each possible
	# testenv to the DC's NETBIOS name. This value also corresponds to last
	# digit of the DC's IP address. Note that the NETBIOS name may differ from
	# the testenv name.
	# Note that when adding a DC with a new realm, also update
	# get_realm_ip_mappings() above.
	my %testenv_iface_mapping = (
		localnt4dc2       => 3,
		localnt4member3   => 4,
		localshare4       => 5,
		# 6 is spare
		localktest6       => 7,
		maptoguest        => 8,
		localnt4dc9       => 9,
		# 10 is spare

		# 11-16 are used by selftest.pl for the client.conf. Most tests only
		# use the first .11 IP. However, some tests (like winsreplication) rely
		# on the client having multiple IPs.
		client            => 11,

		addc_no_nss       => 17,
		addc_no_ntlm      => 18,
		idmapadmember     => 19,
		idmapridmember    => 20,
		localdc           => 21,
		localvampiredc    => 22,
		s4member          => 23,
		localrpcproxy     => 24,
		dc5               => 25,
		dc6               => 26,
		dc7               => 27,
		rodc              => 28,
		localadmember     => 29,
		addc              => 30,
		localsubdc        => 31,
		chgdcpass         => 32,
		promotedvdc       => 33,
		rfc2307member     => 34,
		fileserver        => 35,
		fakednsforwarder1 => 36,
		fakednsforwarder2 => 37,
		s4member_dflt     => 38,
		vampire2000dc     => 39,
		backupfromdc      => 40,
		restoredc         => 41,
		renamedc          => 42,
		labdc             => 43,
		offlinebackupdc   => 44,
		customdc          => 45,
		prockilldc        => 46,
		proclimitdc       => 47,
		liveupgrade1dc    => 48,
		liveupgrade2dc    => 49,
		ctdb0             => 50,
		ctdb1             => 51,
		ctdb2             => 52,
		fileserversmb1    => 53,
		addcsmb1	  => 54,
		lclnt4dc2smb1	  => 55,
		fipsdc            => 56,
		fipsadmember      => 57,

		rootdnsforwarder  => 64,

		# Note: that you also need to update dns_hub.py when adding a new
		# multi-DC testenv
		# update lib/socket_wrapper/socket_wrapper.c
		#  #define MAX_WRAPPED_INTERFACES 64
		# if you wish to have more than 64 interfaces
	);

	if (not defined($testenv_iface_mapping{$netbiosname})) {
		die();
	}

	return $testenv_iface_mapping{$netbiosname};
}

sub get_ipv4_addr
{
	my ($hostname, $iface_num) = @_;
	my $swiface = Samba::get_interface($hostname);

	# Handle testenvs with multiple different addresses, i.e. IP multihoming.
	# Currently only the selftest client has multiple IPv4 addresses.
	if (defined($iface_num)) {
		$swiface += $iface_num;
	}

	return "10.53.57.$swiface";
}

sub get_ipv6_addr
{
	(my $hostname) = @_;
	my $swiface = Samba::get_interface($hostname);

	return sprintf("fd00:0000:0000:0000:0000:0000:5357:5f%02x", $swiface);
}

# returns the 'interfaces' setting for smb.conf, i.e. the IPv4/IPv6
# addresses for testenv
sub get_interfaces_config
{
	my ($hostname, $num_ips) = @_;
	my $interfaces = "";

	# We give the client.conf multiple different IPv4 addresses.
	# All other testenvs generally just have one IPv4 address.
	if (! defined($num_ips)) {
		$num_ips = 1;
	}
	for (my $i = 0; $i < $num_ips; $i++) {
		my $ipv4_addr = Samba::get_ipv4_addr($hostname, $i);
		if (use_namespaces()) {
			# use a /24 subnet with network namespaces
			$interfaces .= "$ipv4_addr/24 ";
		} else {
			$interfaces .= "$ipv4_addr/8 ";
		}
	}

	my $ipv6_addr = Samba::get_ipv6_addr($hostname);
	$interfaces .= "$ipv6_addr/64";

	return $interfaces;
}

sub cleanup_child($$)
{
    my ($pid, $name) = @_;

    if (!defined($pid)) {
        print STDERR "cleanup_child: pid not defined ... not calling waitpid\n";
        return -1;
    }

    my $childpid = waitpid($pid, WNOHANG);

    if ($childpid == 0) {
    } elsif ($childpid < 0) {
	printf STDERR "%s child process %d isn't here any more\n", $name, $pid;
	return $childpid;
    } elsif ($? & 127) {
	printf STDERR "%s child process %d, died with signal %d, %s coredump\n",
		$name, $childpid, ($? & 127),  ($? & 128) ? 'with' : 'without';
    } else {
	printf STDERR "%s child process %d exited with value %d\n", $name, $childpid, $? >> 8;
    }
    return $childpid;
}

sub random_domain_sid()
{
	my $domain_sid = "S-1-5-21-". int(rand(4294967295)) . "-" . int(rand(4294967295)) . "-" . int(rand(4294967295));
	return $domain_sid;
}

# sets the environment variables ready for running a given process
sub set_env_for_process
{
	my ($proc_name, $env_vars, $proc_envs) = @_;

	if (not defined($proc_envs)) {
		$proc_envs = get_env_for_process($proc_name, $env_vars);
	}

	foreach my $key (keys %{ $proc_envs }) {
		$ENV{$key} = $proc_envs->{$key};
	}
}

sub get_env_for_process
{
	my ($proc_name, $env_vars) = @_;
	my $proc_envs = {
		RESOLV_CONF => $env_vars->{RESOLV_CONF},
		KRB5_CONFIG => $env_vars->{KRB5_CONFIG},
		KRB5CCNAME => "$env_vars->{KRB5_CCACHE}.$proc_name",
		GNUPGHOME => $env_vars->{GNUPGHOME},
		SELFTEST_WINBINDD_SOCKET_DIR => $env_vars->{SELFTEST_WINBINDD_SOCKET_DIR},
		NMBD_SOCKET_DIR => $env_vars->{NMBD_SOCKET_DIR},
		NSS_WRAPPER_PASSWD => $env_vars->{NSS_WRAPPER_PASSWD},
		NSS_WRAPPER_GROUP => $env_vars->{NSS_WRAPPER_GROUP},
		NSS_WRAPPER_HOSTS => $env_vars->{NSS_WRAPPER_HOSTS},
		NSS_WRAPPER_HOSTNAME => $env_vars->{NSS_WRAPPER_HOSTNAME},
		NSS_WRAPPER_MODULE_SO_PATH => $env_vars->{NSS_WRAPPER_MODULE_SO_PATH},
		NSS_WRAPPER_MODULE_FN_PREFIX => $env_vars->{NSS_WRAPPER_MODULE_FN_PREFIX},
		UID_WRAPPER_ROOT => "1",
		ENVNAME => "$ENV{ENVNAME}.$proc_name",
	};

	if (defined($env_vars->{RESOLV_WRAPPER_CONF})) {
		$proc_envs->{RESOLV_WRAPPER_CONF} = $env_vars->{RESOLV_WRAPPER_CONF};
	} else {
		$proc_envs->{RESOLV_WRAPPER_HOSTS} = $env_vars->{RESOLV_WRAPPER_HOSTS};
	}
	if (defined($env_vars->{GNUTLS_FORCE_FIPS_MODE})) {
		$proc_envs->{GNUTLS_FORCE_FIPS_MODE} = $env_vars->{GNUTLS_FORCE_FIPS_MODE};
	}
	if (defined($env_vars->{OPENSSL_FORCE_FIPS_MODE})) {
		$proc_envs->{OPENSSL_FORCE_FIPS_MODE} = $env_vars->{OPENSSL_FORCE_FIPS_MODE};
	}
	return $proc_envs;
}

sub fork_and_exec
{
	my ($self, $env_vars, $daemon_ctx, $STDIN_READER, $child_cleanup) = @_;
	my $SambaCtx = $self;
	$SambaCtx = $self->{SambaCtx} if defined($self->{SambaCtx});

	# we close the child's write-end of the pipe and redirect the
	# read-end to its stdin. That way the daemon will receive an
	# EOF on stdin when parent selftest process closes its
	# write-end.
	$child_cleanup //= sub { close($env_vars->{STDIN_PIPE}) };

	unlink($daemon_ctx->{LOG_FILE});
	print "STARTING $daemon_ctx->{NAME} for $ENV{ENVNAME}...";

	my $parent_pid = $$;
	my $pid = fork();

	# exec the daemon in the child process
	if ($pid == 0) {
		my @preargs = ();

		# redirect the daemon's stdout/stderr to a log file
		if (defined($daemon_ctx->{TEE_STDOUT})) {
			# in some cases, we want out from samba to go to the log file,
			# but also to the users terminal when running 'make test' on the
			# command line. This puts it on stderr on the terminal
			open STDOUT, "| tee $daemon_ctx->{LOG_FILE} 1>&2";
		} else {
			open STDOUT, ">$daemon_ctx->{LOG_FILE}";
		}
		open STDERR, '>&STDOUT';

		SocketWrapper::set_default_iface($env_vars->{SOCKET_WRAPPER_DEFAULT_IFACE});
		if (defined($daemon_ctx->{PCAP_FILE})) {
			$SambaCtx->setup_pcap("$daemon_ctx->{PCAP_FILE}");
		}

		# setup ENV variables in the child process
		set_env_for_process($daemon_ctx->{NAME}, $env_vars,
				    $daemon_ctx->{ENV_VARS});

		$child_cleanup->();

		# not all s3 daemons run in all testenvs (e.g. fileserver doesn't
		# run winbindd). In which case, the child process just sleeps
		if (defined($daemon_ctx->{SKIP_DAEMON})) {
			$SIG{USR1} = $SIG{ALRM} = $SIG{INT} = $SIG{QUIT} = $SIG{TERM} = sub {
				my $signame = shift;
				print("Skip $daemon_ctx->{NAME} received signal $signame");
				exit 0;
			};
			my $poll = IO::Poll->new();
			$poll->mask($STDIN_READER, POLLIN);
			$poll->poll($self->{server_maxtime});
			exit 0;
		}

		$ENV{MAKE_TEST_BINARY} = $daemon_ctx->{BINARY_PATH};

		open STDIN, ">&", $STDIN_READER or die "can't dup STDIN_READER to STDIN: $!";

		# if using kernel namespaces, prepend the command so the process runs in
		# its own namespace
		if (Samba::use_namespaces()) {
			@preargs = ns_exec_preargs($parent_pid, $env_vars);
		}

		# the command args are stored as an array reference (because...Perl),
		# so convert the reference back to an array
		my @full_cmd = @{ $daemon_ctx->{FULL_CMD} };

		exec(@preargs, @full_cmd) or die("Unable to start $ENV{MAKE_TEST_BINARY}: $!");
	}

	print "DONE ($pid)\n";

	# if using kernel namespaces, we now establish a connection between the
	# main selftest namespace (i.e. this process) and the new child namespace
	if (use_namespaces()) {
		ns_child_forked($pid, $env_vars);
	}

	return $pid;
}

my @exported_envvars = (
	# domain stuff
	"DOMAIN",
	"DNSNAME",
	"REALM",
	"DOMSID",

	# stuff related to a trusted domain
	"TRUST_SERVER",
	"TRUST_USERNAME",
	"TRUST_PASSWORD",
	"TRUST_DOMAIN",
	"TRUST_REALM",
	"TRUST_DOMSID",

	# stuff related to a trusted domain, on a trust_member
	# the domain behind a forest trust (two-way)
	"TRUST_F_BOTH_SERVER",
	"TRUST_F_BOTH_SERVER_IP",
	"TRUST_F_BOTH_SERVER_IPV6",
	"TRUST_F_BOTH_NETBIOSNAME",
	"TRUST_F_BOTH_USERNAME",
	"TRUST_F_BOTH_PASSWORD",
	"TRUST_F_BOTH_DOMAIN",
	"TRUST_F_BOTH_REALM",

	# stuff related to a trusted domain, on a trust_member
	# the domain behind an external trust (two-way)
	"TRUST_E_BOTH_SERVER",
	"TRUST_E_BOTH_SERVER_IP",
	"TRUST_E_BOTH_SERVER_IPV6",
	"TRUST_E_BOTH_NETBIOSNAME",
	"TRUST_E_BOTH_USERNAME",
	"TRUST_E_BOTH_PASSWORD",
	"TRUST_E_BOTH_DOMAIN",
	"TRUST_E_BOTH_REALM",

	# domain controller stuff
	"DC_SERVER",
	"DC_SERVER_IP",
	"DC_SERVER_IPV6",
	"DC_NETBIOSNAME",
	"DC_NETBIOSALIAS",

	# server stuff
	"SERVER",
	"SERVER_IP",
	"SERVER_IPV6",
	"NETBIOSNAME",
	"NETBIOSALIAS",
	"SAMSID",

	# only use these 2 as a last resort. Some tests need to test both client-
	# side and server-side. In this case, run as default client, ans access
	# server's smb.conf as needed, typically using:
	#  param.LoadParm(filename_for_non_global_lp=os.environ['SERVERCONFFILE'])
	"SERVERCONFFILE",
	"DC_SERVERCONFFILE",

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
	"GNUPGHOME",
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

	# crypto libraries
	"GNUTLS_FORCE_FIPS_MODE",
	"OPENSSL_FORCE_FIPS_MODE",
);

sub exported_envvars_str
{
	my ($testenv_vars) = @_;
	my $out = "";

	foreach (@exported_envvars) {
		next unless defined($testenv_vars->{$_});
		$out .= $_."=".$testenv_vars->{$_}."\n";
	}

	return $out;
}

sub clear_exported_envvars
{
	foreach (@exported_envvars) {
		delete $ENV{$_};
	}
}

sub export_envvars
{
	my ($testenv_vars) = @_;

	foreach (@exported_envvars) {
		if (defined($testenv_vars->{$_})) {
			$ENV{$_} = $testenv_vars->{$_};
		} else {
			delete $ENV{$_};
		}
	}
}

sub export_envvars_to_file
{
	my ($filepath, $testenv_vars) = @_;
	my $env_str = exported_envvars_str($testenv_vars);

	open(FILE, "> $filepath");
	print FILE "$env_str";
	close(FILE);
}

# Returns true if kernel namespaces are being used instead of socket-wrapper.
# The default is false.
sub use_namespaces
{
	return defined($ENV{USE_NAMESPACES});
}

# returns a given testenv's interface-name (only when USE_NAMESPACES=1)
sub ns_interface_name
{
	my ($hostname) = @_;

	# when using namespaces, each testenv has its own vethX interface,
	# where X = Samba::get_interface(testenv_name)
	my $iface = get_interface($hostname);
	return "veth$iface";
}

# Called after a new child namespace has been forked
sub ns_child_forked
{
	my ($child_pid, $env_vars) = @_;

	# we only need to do this for the first child forked for this testenv
	if (defined($env_vars->{NS_PID})) {
		return;
	}

	# store the child PID. It's the only way the main (selftest) namespace can
	# access the new child (testenv) namespace.
	$env_vars->{NS_PID} = $child_pid;

	# Add the new child namespace's interface to the main selftest bridge.
	# This connects together the various testenvs so that selftest can talk to
	# them all
	my $iface = ns_interface_name($env_vars->{NETBIOSNAME});
	system "$ENV{SRCDIR}/selftest/ns/add_bridge_iface.sh $iface-br selftest0";
}

# returns args to prepend to a command in order to execute it the correct
# namespace for the testenv (creating a new namespace if needed).
# This should only used when USE_NAMESPACES=1 is set.
sub ns_exec_preargs
{
	my ($parent_pid, $env_vars) = @_;

	# NS_PID stores the pid of the first child daemon run in this namespace
	if (defined($env_vars->{NS_PID})) {

		# the namespace has already been created previously. So we use nsenter
		# to execute the command in the given testenv's namespace. We need to
		# use the NS_PID to identify this particular namespace
		return ("nsenter", "-t", "$env_vars->{NS_PID}", "--net");
	} else {

		# We need to create a new namespace for this daemon (i.e. we're
		# setting up a new testenv). First, write the environment variables to
		# an exports.sh file for this testenv (for convenient access by the
		# namespace scripts).
		my $exports_file = "$env_vars->{TESTENV_DIR}/exports.sh";
		export_envvars_to_file($exports_file, $env_vars);

		# when using namespaces, each testenv has its own veth interface
		my $interface = ns_interface_name($env_vars->{NETBIOSNAME});

		# we use unshare to create a new network namespace. The start_in_ns.sh
		# helper script gets run first to setup the new namespace's interfaces.
		# (This all gets prepended around the actual command to run in the new
		# namespace)
		return ("unshare", "--net", "$ENV{SRCDIR}/selftest/ns/start_in_ns.sh",
				$interface, $exports_file, $parent_pid);
	}
}


sub check_env {
	my ($self, $envvars) = @_;
	return 1;
}

sub teardown_env {
	my ($self, $env) = @_;
	return 1;
}


sub getlog_env {
	return '';
}

1;
