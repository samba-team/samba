#!/usr/bin/perl
# Start a KVM machine and run a number of tests against it.
# Copyright (C) 2005-2008 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

package Kvm;

use strict;
use Cwd qw(abs_path);
use FindBin qw($RealBin);
use POSIX;

sub new($$$$) {
	my ($classname, $dc_image) = @_;
	my $self = { 
		dc_image => $dc_image,
	};
	bless $self;
	return $self;
}

sub teardown_env($$)
{
	my ($self, $envvars) = @_;

	print "Killing kvm instance $envvars->{KVM_PID}\n";

	kill 9, $envvars->{KVM_PID};

	return 0;
}

sub getlog_env($$)
{
	my ($self, $envvars) = @_;

	return "";
}

sub check_env($$)
{
	my ($self, $envvars) = @_;

	# FIXME: Check whether $self->{pid} is still running

	return 1;
}

sub start($$$)
{
	my ($self, $path, $image) = @_;

	my $pidfile = "$path/kvm.pid";

	my $opts = ($ENV{KVM_OPTIONS} or "");

	system("kvm $opts -daemonize -pidfile $pidfile -vnc unix:$path/kvm.vnc -snapshot $image");

	open(PID, $pidfile);
	<PID> =~ /([0-9]+)/;
	my ($pid) = $1;
	close(PID);
	return $pid;
}

sub setup_env($$$)
{
	my ($self, $envname, $path) = @_;

	if ($envname eq "dc") {
		$self->{dc_pid} = $self->start($path, $self->{dc_image});
		if ($envname eq "dc") {
			return {
				KVM_PID => $self->{dc_pid},
				USERNAME => "Administrator",
				PASSWORD => "penguin",
				DOMAIN => "SAMBA",
				REALM => "SAMBA",
				SERVER => "",
				SERVER_IP => "",
				NETBIOSNAME => "",
				NETBIOSALIAS => "",
			};
		} else {
			return undef;
		}
	} else {
		return undef;
	}
}

sub stop($)
{
	my ($self) = @_;
}

1;
