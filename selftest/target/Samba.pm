#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

package Samba;

use strict;
use target::Samba3;
use target::Samba4;
use POSIX;

sub new($$$$$) {
	my ($classname, $bindir, $binary_mapping,$ldap, $srcdir, $server_maxtime) = @_;

	my $self = {
	    samba3 => new Samba3($bindir,$binary_mapping, $srcdir, $server_maxtime),
	    samba4 => new Samba4($bindir,$binary_mapping, $ldap, $srcdir, $server_maxtime),
	};
	bless $self;
	return $self;
}

sub setup_env($$$)
{
	my ($self, $envname, $path) = @_;

	$ENV{ENVNAME} = $envname;

	my $env = $self->{samba4}->setup_env($envname, $path);
	if (defined($env) and $env ne "UNKNOWN") {
	    if (not defined($env->{target})) {
		$env->{target} = $self->{samba4};
	    }
	} elsif (defined($env) and $env eq "UNKNOWN") {
	   	$env = $self->{samba3}->setup_env($envname, $path);
		if (defined($env) and $env ne "UNKNOWN") {
		    if (not defined($env->{target})) {
			$env->{target} = $self->{samba3};
		    }
		}
	}
	if (defined($env) and ($env eq "UNKNOWN")) {
		warn("Samba can't provide environment '$envname'");
		return "UNKNOWN";
	}
	if (not defined $env) {
		warn("failed to start up environment '$envname'");
		return undef;
	}
	return $env;
}

sub bindir_path($$) {
	my ($object, $path) = @_;

	if (defined($object->{binary_mapping}->{$path})) {
	    $path = $object->{binary_mapping}->{$path};
	}

	my $valpath = "$object->{bindir}/$path";

	return $valpath if (-f $valpath);
	return $path;
}

sub nss_wrapper_winbind_so_path($) {
        my ($object) = @_;
	my $ret = $ENV{NSS_WRAPPER_WINBIND_SO_PATH};
        if (not defined($ret)) {
	    $ret = bindir_path($object, "default/nsswitch/libnss-winbind.so");
	}
	return $ret;
}

sub mk_krb5_conf($$)
{
	my ($ctx, $other_realms_stanza) = @_;

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
 dns_lookup_kdc = false
 ticket_lifetime = 24h
 forwardable = yes
 allow_weak_crypto = yes

[realms]
 $our_realms_stanza
 $other_realms_stanza
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

";
        return $realms_stanza;
}

sub get_interface($)
{
    my ($netbiosname) = @_;
    $netbiosname = lc($netbiosname);

    my %interfaces = ();
    $interfaces{"locals3dc2"} = 2;
    $interfaces{"localmember3"} = 3;
    $interfaces{"localshare4"} = 4;
    $interfaces{"localktest6"} = 6;
    $interfaces{"maptoguest"} = 7;

    # 11-16 used by selftest.pl for client interfaces

    $interfaces{"localdc"} = 21;
    $interfaces{"localvampiredc"} = 22;
    $interfaces{"s4member"} = 23;
    $interfaces{"localrpcproxy"} = 24;
    $interfaces{"dc5"} = 25;
    $interfaces{"dc6"} = 26;
    $interfaces{"dc7"} = 27;
    $interfaces{"rodc"} = 28;
    $interfaces{"localadmember"} = 29;
    $interfaces{"plugindc"} = 30;
    $interfaces{"localsubdc"} = 31;
    $interfaces{"chgdcpass"} = 32;
    $interfaces{"promotedvdc"} = 33;

    # update lib/socket_wrapper/socket_wrapper.c
    #  #define MAX_WRAPPED_INTERFACES 32
    # if you wish to have more than 32 interfaces

    if (not defined($interfaces{$netbiosname})) {
	die();
    }

    return $interfaces{$netbiosname};
}

sub cleanup_child($$)
{
    my ($pid, $name) = @_;
    my $childpid = waitpid($pid, WNOHANG);
    if ($childpid == 0) {
    } elsif ($childpid < 0) {
	printf STDERR "%s child process %d isn't here any more\n",
	return $childpid;
    }
    elsif ($? & 127) {
	printf STDERR "%s child process %d, died with signal %d, %s coredump\n",
	$name, $childpid, ($? & 127),  ($? & 128) ? 'with' : 'without';
    } else {
	printf STDERR "%s child process %d exited with value %d\n", $name, $childpid, $? >> 8;
    }
    return $childpid;
}

1;
