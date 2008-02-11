# SMB Build System
#
#  Copyright (C) Jelmer Vernooij 2006
#  Released under the GNU GPL

package cflags;
use strict;

my $sort_available = eval "use sort 'stable'; return 1;";
$sort_available = 0 unless defined($sort_available);

sub by_path {
	return  1 if($a =~ m#^\-I/#);
    	return -1 if($b =~ m#^\-I/#);
	return  0;
}

sub create_cflags($$$$) {
	my $CTX = shift;
	my $srcdir = shift;
	my $builddir = shift;
	my $file = shift;

	open(CFLAGS_TXT,">$file") || die ("Can't open `$file'\n");

	print CFLAGS_TXT "include mkconfig.mk\n";

	my $src_ne_build = ($srcdir ne $builddir) ? 1 : 0;

	foreach my $key (values %{$CTX}) {
		next unless defined ($key->{OBJ_LIST});
		next unless defined ($key->{FINAL_CFLAGS});
		next unless (@{$key->{FINAL_CFLAGS}} > 0);

		my @sorted_cflags = @{$key->{FINAL_CFLAGS}};
		if ($sort_available) {
			@sorted_cflags = sort by_path @{$key->{FINAL_CFLAGS}};
		}

		# Rewrite CFLAGS so that both the source and the build
		# directories are in the path.
		my @cflags = ();
		foreach my $flag (@sorted_cflags) {
			if($src_ne_build) {
			        if($flag =~ m#^-I([^/].*$)#) {
				        my $dir = $1;
				        $dir =~ s#^\$\((?:src|build)dir\)/?##;
					push(@cflags, "-I$builddir/$dir", "-I$srcdir/$dir");
				        next;
			        }
			}
			push(@cflags, $flag);
		}
		
		my $cflags = join(' ', @cflags);

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
