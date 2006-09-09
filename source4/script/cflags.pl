#!/usr/bin/env perl

# This is a hack to allow per target cflags. It isn't very elegant, but it
# is the most portable idea we have come up with yet
# tridge@samba.org, July 2005
# jelmer@samba.org, March 2006
use strict;

my $target = shift;

sub check_flags($)
{
	my ($name)=@_;
	open (IN, "extra_cflags.txt");
	while (<IN> =~ /^([^:]+): (.*)$/) {
		next unless (grep(/^$target$/, (split / /, $1)));
		$_ = $2;
		s/^CFLAGS\+=//;
		print "$_ ";
	}
	close(IN);
	print "\n";
}

check_flags($target);

exit 0;
