# Subs for build system stuff without the .mk files
# Copyright (C) 2004 Jelmer Vernooij <jelmer@samba.org>

use strict;

our $SMB_BUILD_CTX;

sub Subsystem($$)
{
	my $name = shift;
	my $data = shift;
	$data->{NAME} = $name;
	$data->{TYPE} = "SUBSYSTEM";
	%{$SMB_BUILD_CTX->{INPUT}{$name}} = %{$data};
}

sub Module($$)
{
	my $name = shift;
	my $data = shift;
	$data->{NAME} = $name;
	$data->{TYPE} = "MODULE";
	%{$SMB_BUILD_CTX->{INPUT}{$name}} = %{$data};
}

sub ExternalLibrary($$)
{
	my $name = shift;
	my $data = shift;
	$data->{NAME} = $name;
	$data->{TYPE} = "EXT_LIB";
	%{$SMB_BUILD_CTX->{INPUT}{$name}} = %{$data};
}

sub Library($$)
{
	my $name = shift;
	my $data = shift;
	$data->{NAME} = $name;
	$data->{TYPE} = "LIBRARY";
	%{$SMB_BUILD_CTX->{INPUT}{$name}} = %{$data};
}

sub Binary($$)
{
	my $name = shift;
	my $data = shift;
	$data->{NAME} = $name;
	$data->{TYPE} = "BINARY";
	%{$SMB_BUILD_CTX->{INPUT}{$name}} = %{$data};
}

sub Disable($)
{
	$SMB_BUILD_CTX->{INPUT}{shift}{ENABLE} = "NO";
}

1;
