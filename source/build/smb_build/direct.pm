# Subs for build system stuff without the .mk files
# Copyright (C) 2004 Jelmer Vernooij <jelmer@samba.org>

use strict;

our $SMB_BUILD_CTX;

sub Subsystem($$)
{
	my $name = shift;
	my $data = shift;
	$data->{NAME} = $name;
	%{$SMB_BUILD_CTX->{INPUT}{SUBSYSTEM}{$name}} = %{$data};
}

sub Module($$)
{
	my $name = shift;
	my $data = shift;
	$data->{NAME} = $name;
	%{$SMB_BUILD_CTX->{INPUT}{MODULES}{$name}} = %{$data};
}

sub ExternalLibrary($$)
{
	my $name = shift;
	my $data = shift;
	$data->{NAME} = $name;
	%{$SMB_BUILD_CTX->{INPUT}{EXT_LIBS}{$name}} = %{$data};
}

sub Library($$)
{
	my $name = shift;
	my $data = shift;
	$data->{NAME} = $name;
	%{$SMB_BUILD_CTX->{INPUT}{LIBRARIES}{$name}} = %{$data};
}

sub Binary($$)
{
	my $name = shift;
	my $data = shift;
	$data->{NAME} = $name;
	%{$SMB_BUILD_CTX->{INPUT}{BINARIES}{$name}} = %{$data};
}

sub DisableModule($)
{
	$SMB_BUILD_CTX->{INPUT}{MODULES}{shift}{ENABLE} = "NO";
}

sub DisableBinary($)
{
	$SMB_BUILD_CTX->{INPUT}{BINARIES}{shift}{ENABLE} = "NO";
}

sub DisableLibrary($)
{
	$SMB_BUILD_CTX->{INPUT}{LIBRARIES}{shift}{ENABLE} = "NO";
}

1;
