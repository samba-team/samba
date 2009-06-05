#!/usr/bin/perl
# Diff two subunit streams
# Copyright (C) Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later

use Getopt::Long;
use strict;
use FindBin qw($RealBin $Script);
use lib "$RealBin";
use Subunit::Diff;

open(FH1, $ARGV[0]) or die("Unable to open $ARGV[0]: $!");
open(FH2, $ARGV[1]) or die("Unable to open $ARGV[1]: $!");

my $ret = Subunit::Diff::diff(*FH1, *FH2);

close(FH1);
close(FH2);

foreach my $e (keys %$ret) {
	printf "%s: %s -> %s\n", $e, $ret->{$e}[0], $ret->{$e}[1];
}

0;
