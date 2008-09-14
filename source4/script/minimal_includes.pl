#!/usr/bin/perl -w
# find a list of #include lines in C code that might not be needed
# usually called with something like this:
#    minimal_includes.pl `find . -name "*.c"`
# Andrew Tridgell <tridge@samba.org>

use strict;
use Data::Dumper;
use Getopt::Long;

my $opt_help = 0;
my $opt_remove = 0;

#####################################################################
# write a string into a file
sub FileSave($$)
{
    my($filename) = shift;
    my($v) = shift;
    local(*FILE);
    open(FILE, ">$filename") || die "can't open $filename";    
    print FILE $v;
    close(FILE);
}

sub load_lines($)
{
	my $fname = shift;
	my @lines = split(/^/m, `cat $fname`);
	return @lines;
}

sub save_lines($$)
{
	my $fname = shift;
	my $lines = shift;
	my $data = join('', @{$lines});
	FileSave($fname, $data);
}

sub test_compile($)
{
	my $fname = shift;
	my $obj;
	if ($fname =~ s/(.*)\.c$/$1.o/) {
		$obj = "$1.o";
	} else {
		return "NOT A C FILE";
	}
	unlink($obj);
	my $ret = `make $obj 2>&1`;
	if (!unlink("$obj")) {
		return "COMPILE FAILED";
	}
	return $ret;
}

sub test_include($$$$)
{
	my $fname = shift;
	my $lines = shift;
	my $i = shift;
	my $original = shift;
	my $line = $lines->[$i];

	$lines->[$i] = "";
	save_lines("_testcompile.c", $lines);
	
	my $out = test_compile("_testcompile.c");
	$out =~ s/_testcompile.c/$fname/g;

	if ($out eq $original) {
		if ($opt_remove) {
			print "$fname: removing $line\n";
			save_lines($fname, $lines);
			return;
		}
		print "$fname: might be able to remove $line\n";
	}

	$lines->[$i] = $line;
	unlink("_testcompile.c");
}

sub process_file($)
{
	my $fname = shift;
	my @lines = load_lines($fname);
	my $num_lines = $#lines;

	my $original = test_compile($fname);

	if ($original eq "COMPILE FAILED") {
		print "Failed to compile $fname\n";
		return;
	}

	print "Processing $fname (with $num_lines lines)\n";
	
	my $if_level = 0;

	for (my $i=0;$i<=$num_lines;$i++) {
		my $line = $lines[$i];
		if ($line =~ /^\#\s*if/) {
			$if_level++;
		}
		if ($line =~ /^\#\s*endif/) {
			$if_level--;
		}
		if ($if_level == 0 &&
		    $line =~ /^\#\s*include/ && 
		    !($line =~ /needed/)) {
			test_include($fname, \@lines, $i, $original);
		}
	}
}


#########################################
# display help text
sub ShowHelp()
{
    print "
           minimise includes
           Copyright (C) tridge\@samba.org

	   Usage: minimal_includes.pl [options] <C files....>
	   
	   Options:
                 --help       show help
                 --remove     remove includes, don't just list them
";
}


# main program
GetOptions (
	    'h|help|?' => \$opt_help,
	    'remove' => \$opt_remove,
	    );

if ($opt_help) {
	ShowHelp();
	exit(0);
}

for (my $i=0;$i<=$#ARGV;$i++) {
	my $fname = $ARGV[$i];
	process_file($fname);
}
