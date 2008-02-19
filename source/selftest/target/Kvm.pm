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
	my ($classname, $image) = @_;
	my $self = { 
		image => $image
	};
	bless $self;
	return $self;
}

sub teardown_env($$)
{
	my ($self, $envvars) = @_;

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

	return 1;
}

sub start($)
{
	my ($self) = @_;

	my $pidfile = "kvm.pid";

	my $opts = ($ENV{KVM_OPTIONS} or "");

	system("kvm $opts -daemonize -pidfile $pidfile -vnc unix:kvm.vnc -snapshot $self->{image}");

	open(PID, $pidfile);
	$self->{pid} = <PID>;
	close(PID);
}

sub setup_env($$$)
{
	my ($self, $envname, $path) = @_;

	if ($envname eq "dc") {
		unless (defined($self->{pid})) {
			$self->start();
		}
	} elsif ($envname eq "member") {
		return undef;
	}

	die("No implemented yet");
}

sub stop($)
{
	my ($self) = @_;

	kill $self->{pid};
}

1;
