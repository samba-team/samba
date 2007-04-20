# SMB Build System
#
#  Copyright (C) Jelmer Vernooij 2006
#  Released under the GNU GPL

package cflags;
use strict;

sub create_cflags($$$$)
{
	my $CTX = shift;
	my $srcdir = shift;
	my $builddir = shift;
	my $file = shift;

	open(CFLAGS_TXT,">$file") || die ("Can't open `$file'\n");

	my $src_ne_build = 0;
	$src_ne_build = 1 unless ($srcdir eq $builddir);

	foreach my $key (values %{$CTX}) {
		next unless defined ($key->{OBJ_LIST});

		next unless defined ($key->{FINAL_CFLAGS});
		next unless ($#{$key->{FINAL_CFLAGS}} >= 0);

		# Rewrite CFLAGS so that both the source and the build
		# directories are in the path.
		my $cflags = "";
		foreach my $flag (@{$key->{FINAL_CFLAGS}}) {
			my $dir;
			if ($src_ne_build and ($dir) = ($flag =~ /^-I([^\/].*)$/)) {
				$cflags .= " -I$builddir/$dir";
				$cflags .= " -I$srcdir/$dir";
			} else {
				$cflags .= " $flag";
			}
		}

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
