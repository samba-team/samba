#!/usr/bin/perl
# Samba4 Dependency Graph Generator
# (C) 2004-2005 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL

use strict;
use lib 'build';
use smb_build::config_mk;

sub generate($)
{
	my $depend = shift;
	my $res = "digraph samba4 {\n";

	foreach my $part (values %{$depend}) {
		foreach my $elem (@{$part->{REQUIRED_SUBSYSTEMS}}) {
			$res .= "\t\"$part->{NAME}\" -> \"$elem\";\n";
		}
	}

	return $res . "}\n";
}

my $INPUT = {};
smb_build::config_mk::run_config_mk($INPUT, '.', "main.mk");

print __FILE__.": creating samba4-deps.dot\n";
open DOTTY, ">samba4-deps.dot";
print DOTTY generate($INPUT);
close DOTTY;

1;
