#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;

use Test::More tests => 29;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";
use Parse::Pidl::Util;

# has_property()
is(undef, has_property({}, "foo"));
is(undef, has_property({PROPERTIES => {}}, "foo"));
is("data", has_property({PROPERTIES => {foo => "data"}}, "foo"));
is(undef, has_property({PROPERTIES => {foo => undef}}, "foo"));

# is_constant()
ok(is_constant("2"));
ok(is_constant("256"));
ok(is_constant("0x400"));
ok(is_constant("0x4BC"));
ok(not is_constant("0x4BGC"));
ok(not is_constant("str"));
ok(not is_constant("2 * expr"));

# make_str()
is("\"bla\"", make_str("bla"));
is("\"bla\"", make_str("\"bla\""));
is("\"\"bla\"\"", make_str("\"\"bla\"\""));
is("\"bla\"\"", make_str("bla\""));
is("\"foo\"bar\"", make_str("foo\"bar"));

# print_uuid()
is(undef, print_uuid("invalid"));
is("{0x12345778,0x1234,0xabcd,{0xef,0x00},{0x01,0x23,0x45,0x67,0x89,0xac}}", 
   print_uuid("12345778-1234-abcd-ef00-0123456789ac"));
is("{0x12345778,0x1234,0xabcd,{0xef,0x00},{0x01,0x23,0x45,0x67,0x89,0xac}}", 
   print_uuid("\"12345778-1234-abcd-ef00-0123456789ac\""));

# property_matches()
# missing property
ok(not property_matches({PROPERTIES => {}}, "x", "data"));
# data not matching
ok(not property_matches({PROPERTIES => {x => "bar"}}, "x", "data"));
# data matching exactly
ok(property_matches({PROPERTIES => {x => "data"}}, "x", "data"));
# regex matching
ok(property_matches({PROPERTIES => {x => "data"}}, "x", "^([dat]+)\$"));

# ParseExpr()
is("", ParseExpr("", {}));
is("a", ParseExpr("a", {"b" => "2"}));
is("2", ParseExpr("a", {"a" => "2"}));
is("2*2", ParseExpr("a*a", {"a" => "2"}));
is("r->length+r->length", 
   ParseExpr("length+length", {"length" => "r->length"}));
is("2/2*(r->length)", 
	ParseExpr("constant/constant*(len)", {"constant" => "2", 
			                              "len" => "r->length"}));
