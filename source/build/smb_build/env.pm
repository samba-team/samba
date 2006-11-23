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

sub PkgConfig($$$$$$$$$$$)
{
	my ($self,$path,$name,$libs,$cflags,$version,$desc,$hasmodules,$pubdep,$privdep,$dirs) = @_;

	print __FILE__.": creating $path\n";

	if ($self->{config}->{libreplace_cv_immediate_structures} eq "yes") {
		$cflags .= " -DHAVE_IMMEDIATE_STRUCTURES=1";
	}

	mkpath(dirname($path),0,0755);
	open(OUT, ">$path") or die("Can't open $path: $!");

	foreach (keys %$dirs) {
		print OUT "$_=" . $dirs->{$_} . "\n";
	}
	if ($hasmodules) {
		print OUT "modulesdir=$self->{config}->{modulesdir}/$name\n" ;
	}

	print OUT "\n";

	print OUT "Name: $name\n";
	if (defined($desc)) {
		print OUT "Description: $desc\n";
	}
	print OUT "Requires: $pubdep\n" if defined($pubdep);
	print OUT "Requires.private: $privdep\n" if defined($privdep);
	print OUT "Version: $version\n";
	print OUT "Libs: $libs\n";
	print OUT "Cflags: -I\${includedir} $cflags\n";

	close(OUT);
}

sub Import($$)
{
	my ($self,$items) = @_;

	foreach (keys %$items) {
		if (defined($self->{items})) {
			print "Warning: Importing $_ twice!\n";
		}
		$self->{items}->{$_} = $items->{$_};
	}
}

sub GetInfo($$)
{
	my ($self,$name) = @_;

	unless (defined($self->{info}->{$name})) 
	{
		$self->{info}->{$name} = $self->{items}->Build($self);
	}

	return $self->{info}->{$name};
}

1;
