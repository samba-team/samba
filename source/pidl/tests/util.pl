#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;

use Test::More tests => 53;
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
#is("", ParseExpr("", {}));
is("a", ParseExpr("a", {"b" => "2"}));
is("2", ParseExpr("a", {"a" => "2"}));
is("2 * 2", ParseExpr("a*a", {"a" => "2"}));
is("r->length + r->length", 
   ParseExpr("length+length", {"length" => "r->length"}));
is("2 / 2 * (r->length)", 
	ParseExpr("constant/constant*(len)", {"constant" => "2", 
			                              "len" => "r->length"}));
is("2 + 2 - r->length", 
	ParseExpr("constant+constant-len", {"constant" => "2", 
			                              "len" => "r->length"}));
is("*r->length", ParseExpr("*len", { "len" => "r->length"}));
is("**r->length", ParseExpr("**len", { "len" => "r->length"}));
is("r->length & 2", ParseExpr("len&2", { "len" => "r->length"}));
is("&r->length", ParseExpr("&len", { "len" => "r->length"}));
is("calc()", ParseExpr("calc()", { "foo" => "2"}));
is("calc(2 * 2)", ParseExpr("calc(foo * 2)", { "foo" => "2"}));
is("strlen(\"data\")", ParseExpr("strlen(foo)", { "foo" => "\"data\""}));
is("strlen(\"data\", 4)", ParseExpr("strlen(foo, 4)", { "foo" => "\"data\""}));
is("foo / bar", ParseExpr("foo / bar", { "bla" => "\"data\""}));
is("r->length % 2", ParseExpr("len%2", { "len" => "r->length"}));
is("r->length == 2", ParseExpr("len==2", { "len" => "r->length"}));
is("r->length != 2", ParseExpr("len!=2", { "len" => "r->length"}));
is("pr->length", ParseExpr("pr->length", { "p" => "r"}));
is("r->length", ParseExpr("p->length", { "p" => "r"}));
is("_foo / bla32", ParseExpr("_foo / bla32", { "bla" => "\"data\""}));
is("foo.bar.blah", ParseExpr("foo.blah", { "foo" => "foo.bar"}));
is("\"bla\"", ParseExpr("\"bla\"", {}));
is("1 << 2", ParseExpr("1 << 2", {}));
is("1 >> 2", ParseExpr("1 >> 2", {}));
is("0x200", ParseExpr("0x200", {}));
is("2?3:0", ParseExpr("2?3:0", {}));
is("~0", ParseExpr("~0", {}));
is("b->a->a", ParseExpr("a->a->a", {"a" => "b"}));
is("b.a.a", ParseExpr("a.a.a", {"a" => "b"}));
