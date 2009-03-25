# Simple Perl module for parsing the Subunit protocol
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

package Subunit;

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(parse_results);

use strict;

sub parse_results($$$$$)
{
	my ($msg_ops, $statistics, $fh, $expecting_failure, $open_tests) = @_;
	my $unexpected_ok = 0;
	my $expected_fail = 0;
	my $unexpected_fail = 0;
	my $unexpected_err = 0;
	my $orig_open_len = $#$open_tests;

	while(<$fh>) {
		if (/^test: (.+)\n/) {
			$msg_ops->control_msg($_);
			$msg_ops->start_test($open_tests, $1);
			push (@$open_tests, $1);
		} elsif (/^(success|successful|failure|skip|knownfail|error): (.*?)( \[)?([ \t]*)\n/) {
			$msg_ops->control_msg($_);
			my $reason = undef;
			if ($3) {
				$reason = "";
				# reason may be specified in next lines
				my $terminated = 0;
				while(<$fh>) {
					$msg_ops->control_msg($_);
					if ($_ eq "]\n") { $terminated = 1; last; } else { $reason .= $_; }
				}
				
				unless ($terminated) {
					$statistics->{TESTS_ERROR}++;
					$msg_ops->end_test($open_tests, $2, $1, 1, "reason interrupted");
					return 1;
				}
			}
			my $result = $1;
			if ($1 eq "success" or $1 eq "successful") {
				pop(@$open_tests); #FIXME: Check that popped value == $2
				if ($expecting_failure->(join(".", @$open_tests) . ".$2")) {
					$statistics->{TESTS_UNEXPECTED_OK}++;
					$msg_ops->end_test($open_tests, $2, $1, 1, $reason);
					$unexpected_ok++;
				} else {
					$statistics->{TESTS_EXPECTED_OK}++;
					$msg_ops->end_test($open_tests, $2, $1, 0, $reason);
				}
			} elsif ($1 eq "failure") {
				pop(@$open_tests); #FIXME: Check that popped value == $2
				if ($expecting_failure->(join(".", @$open_tests) . ".$2")) {
					$statistics->{TESTS_EXPECTED_FAIL}++;
					$msg_ops->end_test($open_tests, $2, $1, 0, $reason);
					$expected_fail++;
				} else {
					$statistics->{TESTS_UNEXPECTED_FAIL}++;
					$msg_ops->end_test($open_tests, $2, $1, 1, $reason);
					$unexpected_fail++;
				}
			} elsif ($1 eq "knownfail") {
				pop(@$open_tests); #FIXME: Check that popped value == $2
				$statistics->{TESTS_EXPECTED_FAIL}++;
				$msg_ops->end_test($open_tests, $2, $1, 0, $reason);
			} elsif ($1 eq "skip") {
				$statistics->{TESTS_SKIP}++;
				pop(@$open_tests); #FIXME: Check that popped value == $2
				$msg_ops->end_test($open_tests, $2, $1, 0, $reason);
			} elsif ($1 eq "error") {
				$statistics->{TESTS_ERROR}++;
				pop(@$open_tests); #FIXME: Check that popped value == $2
				$msg_ops->end_test($open_tests, $2, $1, 1, $reason);
				$unexpected_err++;
			}
		} else {
			$msg_ops->output_msg($_);
		}
	}

	while ($#$open_tests > $orig_open_len) {
		$msg_ops->end_test($open_tests, pop(@$open_tests), "error", 1,
				   "was started but never finished!");
		$statistics->{TESTS_ERROR}++;
		$unexpected_err++;
	}

	return 1 if $unexpected_err > 0;
	return 1 if $unexpected_fail > 0;
	return 1 if $unexpected_ok > 0 and $expected_fail > 0;
	return 0 if $unexpected_ok > 0 and $expected_fail == 0;
	return 0 if $expected_fail > 0;
	return 1;
}

1;
