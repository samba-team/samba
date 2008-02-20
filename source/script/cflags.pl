#!/usr/bin/env perl

# This is a hack to allow per target cflags. It isn't very elegant, but it
# is the most portable idea we have come up with yet
# tridge@samba.org, July 2005
# jelmer@samba.org, March 2006
use strict;

my $target = shift;

my $vars = {};

sub check_flags($$);
sub check_flags($$)
{
	my ($path, $name)=@_;
	open (IN, $path);
	foreach my $line (<IN>) {
		if ($line =~ /^include (.*)$/) {
			check_flags($1, $name);
		} elsif ($line =~ /^([A-Za-z0-9_]+) =(.*)$/) {
			$vars->{$1} = $2;
		} elsif ($line =~ /^([^:]+): (.*)$/) {
			next unless (grep(/^$target$/, (split / /, $1)));
			my $data = $2;
			$data =~ s/^CFLAGS\+=//;
			foreach my $key (keys %$vars) {
				my $val = $vars->{$key};
				$data =~ s/\$\($key\)/$val/g;
			}
			# Remove undefined variables
			$data =~ s/\$\([A-Za-z0-9_]+\)//g;
			print "$data ";
		}
	}
	close(IN);
}

check_flags("extra_cflags.txt", $target);
print "\n";

exit 0;
