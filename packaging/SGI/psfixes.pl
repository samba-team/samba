#!/usr/bin/perl

while (<>) {
# strip any ctrl-d's
    $_ =~ s/^//;
# get rid of any non-postscript commands
    if (/^%/) {
	do {
	    $_ = <>;
	} until ( /^%/ ) || eof() ;
	if (! eof()) {
	    print;
	}
    }
# fix bug in long titles from MS Word
    elsif (/^%%Title:/) {
	    s/.$//;
	    print;
    }
# remove VM test
    elsif (/^\/VM?/) {
	print "/VM? { pop } bind def\n";
	do {
	    $_ = <>;
	} until (/def/) || eof() ;
    }
    else {
	print;
    }
}
