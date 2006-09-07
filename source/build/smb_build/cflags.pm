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

		next unless defined ($key->{FINAL_CFLAGS});
		next unless ($#{$key->{FINAL_CFLAGS}} >= 0);

		my $cflags = join(' ', @{$key->{FINAL_CFLAGS}});

		foreach (@{$key->{OBJ_LIST}}) {
			my $ofile = $_;
			my $dfile = $_;
			$dfile =~ s/\.o$/.d/;
			$dfile =~ s/\.ho$/.d/;
			print CFLAGS_TXT "$ofile $dfile: CFLAGS+= $cflags\n";
		}
	}
	close(CFLAGS_TXT);

	print __FILE__.": creating $file\n";
}
1;
