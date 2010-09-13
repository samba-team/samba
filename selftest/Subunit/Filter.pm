#!/usr/bin/perl
# Filter a subunit stream
# Copyright (C) Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later

package Subunit::Filter;

use strict;

sub start_test($$)
{
	my ($self, $testname) = @_;

	if (defined($self->{prefix})) {
		$testname = $self->{prefix}.$testname;
	}

	Subunit::start_test($testname);
}

sub end_test($$$$)
{
	my ($self, $testname, $result, $reason) = @_;

	if (defined($self->{prefix})) {
		$testname = $self->{prefix}.$testname;
	}

	Subunit::end_test($testname, $result, $reason);
}

sub new {
	my ($class, $prefix) = @_;

	my $self = {
		prefix => $prefix,
	};
	bless($self, $class);
}

1;
