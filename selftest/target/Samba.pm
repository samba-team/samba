#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

package Samba;

use strict;
use target::Samba3;
use target::Samba4;

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
	} else {
	   	$env = $self->{samba3}->setup_env($envname, $path);
		if (defined($env) and $env ne "UNKNOWN") {
		    if (not defined($env->{target})) {
			$env->{target} = $self->{samba3};
		    }
		}
	}
	if (not defined $env) {
		warn("Samba can't provide environment '$envname'");
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

1;
