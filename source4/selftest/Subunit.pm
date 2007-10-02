package Subunit;

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(parse_results);

use strict;

sub parse_results($$$$$)
{
	my ($msg_ops, $msg_state, $statistics, $fh, $expecting_failure) = @_;
	my $unexpected_ok = 0;
	my $expected_fail = 0;
	my $unexpected_fail = 0;
	my $unexpected_err = 0;
	my $open_tests = {};

	while(<$fh>) {
		if (/^test: (.+)\n/) {
			$msg_ops->control_msg($msg_state, $_);
			$open_tests->{$1} = 1;
			$msg_ops->start_test($msg_state, $1);
		} elsif (/^(success|failure|skip|error): (.*?)( \[)?([ \t]*)\n/) {
			$msg_ops->control_msg($msg_state, $_);
			my $reason = undef;
			if ($3) {
				$reason = "";
				# reason may be specified in next lines
				while(<$fh>) {
					$msg_ops->control_msg($msg_state, $_);
					if ($_ eq "]\n") { last; } else { $reason .= $_; }
				}
			}
			my $result = $1;
			if ($1 eq "success") {
				delete $open_tests->{$2};
				if ($expecting_failure->("$msg_state->{NAME}/$2")) {
					$statistics->{TESTS_UNEXPECTED_OK}++;
					$msg_ops->end_test($msg_state, $2, $1, 1, $reason);
					$unexpected_ok++;
				} else {
					$statistics->{TESTS_EXPECTED_OK}++;
					$msg_ops->end_test($msg_state, $2, $1, 0, $reason);
				}
			} elsif ($1 eq "failure") {
				delete $open_tests->{$2};
				if ($expecting_failure->("$msg_state->{NAME}/$2")) {
					$statistics->{TESTS_EXPECTED_FAIL}++;
					$msg_ops->end_test($msg_state, $2, $1, 0, $reason);
					$expected_fail++;
				} else {
					$statistics->{TESTS_UNEXPECTED_FAIL}++;
					$msg_ops->end_test($msg_state, $2, $1, 1, $reason);
					$unexpected_fail++;
				}
			} elsif ($1 eq "skip") {
				$statistics->{TESTS_SKIP}++;
				delete $open_tests->{$2};
				$msg_ops->end_test($msg_state, $2, $1, 0, $reason);
			} elsif ($1 eq "error") {
				$statistics->{TESTS_ERROR}++;
				delete $open_tests->{$2};
				$msg_ops->end_test($msg_state, $2, $1, 1, $reason);
				$unexpected_err++;
			}
		} else {
			$msg_ops->output_msg($msg_state, $_);
		}
	}

	foreach (keys %$open_tests) {
		$msg_ops->end_test($msg_state, $_, "error", 1,
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
