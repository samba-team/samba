#
# Environment class
#
# Samba Build Environment
#
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>
#
# Published under the GNU GPL

package smb_build::env;
use smb_build::input;

use strict;

sub new($$)
{ 
	my ($name, $config) = @_;
	my $self = { };
	bless $self, $name;
	$self->set_config($config);
	return $self;
}

sub set_config($$)
{
	my ($self, $config) = @_;

	$self->{config} = $config;

	$self->{config}->{srcdir} = '.';
	$self->{config}->{builddir} = '.';

	if ($self->{config}->{prefix} eq "NONE") {
		$self->{config}->{prefix} = $self->{config}->{ac_default_prefix};
	}

	if ($self->{config}->{exec_prefix} eq "NONE") {
		$self->{config}->{exec_prefix} = $self->{config}->{prefix};
	}
}


1;
