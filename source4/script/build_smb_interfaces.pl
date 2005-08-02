#!/usr/bin/perl

my $idl_file = shift;

require smb_interfaces;
my $idl_parser = new smb_interfaces;
$parse = $idl_parser->parse($idl_file);

use Data::Dumper;
print Dumper($parse);
