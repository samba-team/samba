#!/usr/bin/perl
# Buildfarm output for selftest
# Copyright (C) 2008 Jelmer Vernooij <jelmer@samba.org>
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

package output::buildfarm;

use Exporter;
@ISA = qw(Exporter);

use FindBin qw($RealBin);
use lib "$RealBin/..";

use Subunit qw(parse_results);
use BuildFarm;

use strict;

sub new($$$) {
	my ($class) = @_;
	my $self = {
		test_output => {},
		last_time => 0,
		start_time => undef,
	};
	bless($self, $class);
}

sub report_time($$)
{
	my ($self, $time) = @_;

	unless ($self->{start_time}) {
		$self->{start_time} = $time;
	}

	$self->{last_time} = $time;
}

sub start_testsuite($$)
{
	my ($self, $name) = @_;

	$self->{NAME} = $name;
	$self->{START_TIME} = $self->{last_time};

	my $duration = $self->{START_TIME} - $self->{start_time};
	BuildFarm::start_testsuite($name, $duration);
	$self->{test_output}->{$name} = "";
}

sub output_msg($$)
{
	my ($self, $output) = @_;

	$self->{test_output}->{$self->{NAME}} .= $output;
}

sub control_msg($$)
{
	my ($self, $output) = @_;

	$self->{test_output}->{$self->{NAME}} .= $output;
}

sub end_testsuite($$$$$$)
{
	my ($self, $name, $result, $unexpected, $reason) = @_;

	BuildFarm::end_testsuite($name, ($self->{last_time} - $self->{START_TIME}), 
		                     (not $unexpected), $self->{test_output}->{$name}, 
							 $reason);
}

sub start_test($$$)
{
	my ($self, $parents, $testname) = @_;

	if ($#$parents == -1) {
		$self->start_testsuite($testname);
	}
}

sub end_test($$$$$)
{
	my ($self, $parents, $testname, $result, $unexpected, $reason) = @_;

	if ($unexpected) {
		$self->{test_output}->{$self->{NAME}} .= "UNEXPECTED($result): $testname\n";
	}

	if ($#$parents == -1) {
		$self->end_testsuite($testname, $result, $unexpected, $reason); 
	}
}

sub summary($)
{
	my ($self) = @_;
	
	BuildFarm::summary($self->{last_time} - $self->{start_time});
}

sub skip_testsuite($$$)
{
	my ($self, $name, $reason) = @_;

	BuildFarm::skip_testsuite($name);
}

1;
