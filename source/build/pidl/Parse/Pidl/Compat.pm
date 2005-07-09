###################################################
# IDL Compatibility checker
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Compat;

use strict;

my($res);

sub warning($$)
{
	my $l = shift;
	my $m = shift;

	print "$l->{FILE}:$l->{LINE}:$m\n";
}

sub CheckInterface($)
{
	my $if = shift;
	if (util::has_property($if, "pointer_default_top")) {
		warning($if, "pointer_default_top() is pidl-specific");
	}

	foreach my $x (@{$if->{DATA}}) {
		if ($x->{TYPE} eq "DECLARE") {
			warning($if, "the declare keyword is pidl-specific");
			next;
		}

		if ($x->{TYPE} eq "TYPEDEF") {
			if ($x->{DATA}->{TYPE} eq "UNION") {
				if (util::has_property($x, "nodiscriminant")) {
					warning($x, "nodiscriminant property is pidl-specific");
				}
			}
		}
	}
}

sub Check($)
{
	my $pidl = shift;
	my $res = "";

	foreach my $x (@{$pidl}) {
		CheckInterface($x) if ($x->{TYPE} eq "INTERFACE");
	}

	return $res;
}

1;
