# Environment class
#
# Samba Build Environment
#
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>
#
# Published under the GNU GPL

package smb_build::env;
use smb_build::input;
use File::Path;
use File::Basename;

use strict;

sub new($$)
{ 
	my ($name, $config) = @_;
	my $self = { };
	bless $self, $name;

	$self->{items} = {};
	$self->{info} = {};
	
	$self->_set_config($config);

	return $self;
}

sub _set_config($$)
{
	my ($self, $config) = @_;

	$self->{config} = $config;

	if (not defined($self->{config}->{srcdir})) {
		$self->{config}->{srcdir} = '.';
	}

	if (not defined($self->{config}->{builddir})) {
		$self->{config}->{builddir}  = '.';
	}

	if ($self->{config}->{prefix} eq "NONE") {
		$self->{config}->{prefix} = $self->{config}->{ac_default_prefix};
	}

	if ($self->{config}->{exec_prefix} eq "NONE") {
		$self->{config}->{exec_prefix} = $self->{config}->{prefix};
	}
	
	$self->{developer} = ($self->{config}->{developer} eq "yes");
	$self->{automatic_deps} = ($self->{config}->{automatic_dependencies} eq "yes");
}

1;
