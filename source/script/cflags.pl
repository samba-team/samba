#!/usr/bin/perl

# This is a hack to allow per target cflags. It isn't very elegant, but it
# is the most portable idea we have come up with yet
# tridge@samba.org, July 2005
# jelmer@samba.org, March 2006
use strict;
use warnings;

my $target = shift;

sub check_flags($)
{
    my ($name)=@_;
	open (IN, "extra_cflags.txt");
    while (<IN> =~ /^([^:]+): (.*)$/) {
		next unless ($1 eq $target);
		print "$2 ";
	}
	close(IN);
	print "\n";
}

check_flags($target);

exit 0;
