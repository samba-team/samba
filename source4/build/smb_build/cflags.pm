# SMB Build System
#
#  Copyright (C) Jelmer Vernooij 2006
#  Released under the GNU GPL

package cflags;
use strict;

sub create_cflags($$)
{
	my ($CTX, $file) = @_;

	open(CFLAGS_TXT,">$file") || die ("Can't open `$file'\n");

	foreach my $key (values %{$CTX}) {
		next unless defined ($key->{OBJ_LIST});
		next unless defined ($key->{EXTRA_CFLAGS});

		foreach (@{$key->{OBJ_LIST}}) {
			print CFLAGS_TXT "$_: $key->{EXTRA_CFLAGS}\n";
		}
	}
	close(CFLAGS_TXT);

	print __FILE__.": creating $file\n";
}
1;
