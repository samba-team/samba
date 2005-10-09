# Samba4 Dependency Graph Generator
# (C) 2004 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL

package dot;
use strict;

sub generate($)
{
	my $depend = shift;
	my $res = "digraph samba4 {\n";

	foreach my $part (values %{$depend}) {
		foreach my $elem (@{$part->{DEPENDENCIES}}) {
			next if $part == $elem;
			$res .= "\t\"$part->{NAME}\" -> \"$$elem->{NAME}\";\n";
		}
	}

	return $res . "}\n";
}

1;
