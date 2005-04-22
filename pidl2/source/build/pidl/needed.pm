###################################################
# Samba4 parser generator for IDL structures
# Copyright tridge@samba.org 2000-2004
# Copyright jelmer@samba.org 2004
# released under the GNU GPL

package needed;

use strict;

sub NeededFunction($$)
{
	my $fn = shift;
	my $needed = shift;
	$needed->{"pull_$fn->{NAME}"} = 1;
	$needed->{"push_$fn->{NAME}"} = 1;
	$needed->{"print_$fn->{NAME}"} = 1;
	foreach my $e (@{$fn->{ELEMENTS}}) {
		$e->{PARENT} = $fn;
		unless(defined($needed->{"pull_$e->{TYPE}"})) {
			$needed->{"pull_$e->{TYPE}"} = 1;
		}
		unless(defined($needed->{"push_$e->{TYPE}"})) {
			$needed->{"push_$e->{TYPE}"} = 1;
		}
		unless(defined($needed->{"print_$e->{TYPE}"})) {
			$needed->{"print_$e->{TYPE}"} = 1;
		}
	}
}

sub NeededTypedef($$)
{
	my $t = shift;
	my $needed = shift;
	if (util::has_property($t, "public")) {
		$needed->{"pull_$t->{NAME}"} = not util::has_property($t, "nopull");
		$needed->{"push_$t->{NAME}"} = not util::has_property($t, "nopush");
		$needed->{"print_$t->{NAME}"} = not util::has_property($t, "noprint");
	}

	if ($t->{DATA}->{TYPE} eq "STRUCT" or $t->{DATA}->{TYPE} eq "UNION") {
		if (util::has_property($t, "gensize")) {
			$needed->{"ndr_size_$t->{NAME}"} = 1;
		}

		for my $e (@{$t->{DATA}->{ELEMENTS}}) {
			$e->{PARENT} = $t->{DATA};
			if ($needed->{"pull_$t->{NAME}"} and
				not defined($needed->{"pull_$e->{TYPE}"})) {
				$needed->{"pull_$e->{TYPE}"} = 1;
			}
			if ($needed->{"push_$t->{NAME}"} and
				not defined($needed->{"push_$e->{TYPE}"})) {
				$needed->{"push_$e->{TYPE}"} = 1;
			}
			if ($needed->{"print_$t->{NAME}"} and 
				not defined($needed->{"print_$e->{TYPE}"})) {
				$needed->{"print_$e->{TYPE}"} = 1;
			}
		}
	}
}

#####################################################################
# work out what parse functions are needed
sub NeededInterface($$)
{
	my($interface) = shift;
	my $needed = shift;
	my($data) = $interface->{DATA};
	foreach my $d (@{$data}) {
		($d->{TYPE} eq "FUNCTION") && 
		    NeededFunction($d, $needed);
	}
	foreach my $d (reverse @{$data}) {
		($d->{TYPE} eq "TYPEDEF") &&
		    NeededTypedef($d, $needed);
	}
}

sub BuildNeeded($)
{
	my $pidl = shift;
	my %needed;
	foreach my $d (@{$pidl}) {
		($d->{TYPE} eq "INTERFACE") && NeededInterface($d, \%needed);
	}
	return \%needed;
}

1;
