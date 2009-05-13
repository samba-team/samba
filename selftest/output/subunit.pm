#!/usr/bin/perl
# Subunit output for selftest
# Copyright (C) 2009 Jelmer Vernooij <jelmer@samba.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

package output::subunit;

use Exporter;
@ISA = qw(Exporter);

use FindBin qw($RealBin);
use lib "$RealBin/..";

use Subunit qw(parse_results);

use strict;

sub new($) {
	my ($class) = @_;
	my $self = { };
	bless($self, $class);
}

sub start_testsuite($$)
{
	my ($self, $name) = @_;

	$self->{NAME} = $name;
	
	print "test: $self->{NAME}\n";
}

sub output_msg($$)
{
	my ($self, $output) = @_;

	print $output;
}

sub control_msg($$)
{
	my ($self, $output) = @_;
}

sub end_testsuite($$$$$$)
{
	my ($self, $name, $result, $unexpected, $reason) = @_;

	if ($result eq "failure" and not $unexpected) { $result = "xfail"; }

	if ($reason) {
		print "$result: $name [ $reason ]\n";
	} else {
		print "$result: $name\n";
	}
}

sub start_test($$$)
{
	my ($self, $parents, $testname) = @_;

	print "test: $testname\n";
}

sub end_test($$$$$)
{
	my ($self, $parents, $testname, $result, $unexpected, $reason) = @_;

	if ($result eq "fail" and not $unexpected) { $result = "xfail"; }

	if ($reason) {
		print "$result: $testname [ $reason ]\n";
	} else {
		print "$result: $testname\n";
	}
}

sub summary($)
{
	my ($self) = @_;
}

sub skip_testsuite($$$$)
{
	my ($self, $name, $reason) = @_;

	print "skip: $name\n";
}

1;
