# Make prototypes from .c files
# $Id$

$brace = 0;
$line = "";
$debug = 0;

while(<>) {
    print $brace, " ", $_ if($debug);
    if(/^\#if 0/) {
	$if_0 = 1;
    }
    if($if_0 && /^\#endif/) {
	$if_0 = 0;
    }
    if($if_0) { next }
    if(/^\s*\#/) {
	next;
    }
    if(/^\s*$/) {
	$line = "";
	next;
    }
    if(/\{/){
	if($line =~ /\)\s$/){
	    $_ = $line;
	    while(s/\*\//\ca/){
		s/\/\*(.|\n)*\ca//;
	    }
	    s/^\s*//;
	    s/\s$//;
	    s/\s+/ /g;
	    if(!/^static/){
		# remove outer ()
		s/\s*\(/@/;
		s/\)$/@/;
		# remove , within ()
		while(s/\(([^()]*),(.*)\)/($1\$$2)/g){}
		s/,\s*/,\n\t/g;
		# fix removed ,
		s/\$/,/g;
		# match function name
		/([a-zA-Z0-9_]+)\s*@/;
		$f = $1;
		# only add newline if more than one parameter
                if(/,/){ 
		    s/@/ __P((\n\t/;
		}else{
		    s/@/ __P((/;
		}
		s/@/))/;
		$_ = $_ . ";";
		# insert newline before function name
		s/(.*)\s([a-zA-Z0-9_]+ __P)/$1\n$2/;
		$funcs{$f} = $_;
	    }
	}
	$line = "";
	$brace++;
    }
    if(/\}/){
	$brace--;
    }
    if(/^\}/){
	$brace = 0;
    }
    if($brace == 0) {
	$line = $line . " " . $_;
    }
}

print '/* This is a generated file */
#ifndef __krb5_protos_h__
#define __krb5_protos_h__

#ifdef __STDC__
#include <stdarg.h>
#ifndef __P
#define __P(x) x
#endif
#else
#ifndef __P
#define __P(x) ()
#endif
#endif

';

foreach(sort keys %funcs){
    if(/^(main)$/) { next }
    print $funcs{$_}, "\n\n";
}

print "#endif /* __krb5_protos_h__ */\n";
