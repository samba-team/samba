#!/usr/bin/perl

use strict;

my $dc 		= "192.168.45.44";
my $adminuser 	= "administrator";
my $adminpw 	= "geheim";
my $maxgroups 	= 5000;
my $startgroup  = 0;
my $rpccli_cmd	= "/usr/bin/rpcclient";
my $testuser	= "testgroups";

for (my $num = $startgroup; $num <= $maxgroups; ++$num) {
	my $group = sprintf "%s%.05d", "group", $num;
	print "adding user $testuser to group $group\n";
	system("net rpc -I $dc -U$adminuser\%$adminpw group addmem $group $testuser");
}
