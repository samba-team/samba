#!/usr/bin/perl

$found_vm = 0;

while (<>) {
  if (not $found_vm) {
    if (not /^%/) {
	if (/^%%Title:/) {
	    s/.$//;
	    print;
	}
	elsif (/^\/VM?/) {
	    print "/VM? { pop } bind def\n";
	    $found_vm = 1;
	}
	else {
	    print;
	}
    }
  }
  else {
    if (/def/) {
	$found_vm = 0;
    }
  }
}
