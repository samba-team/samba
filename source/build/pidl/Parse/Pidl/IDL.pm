####################################################################
#
#    This file was generated using Parse::Yapp version 1.05.
#
#        Don't edit this file, use source file instead.
#
#             ANY CHANGE MADE HERE WILL BE LOST !
#
####################################################################
package Parse::Pidl::IDL;
use vars qw ( @ISA );
use strict;

@ISA= qw ( Parse::Yapp::Driver );
#Included Parse/Yapp/Driver.pm file----------------------------------------
{
#
# Module Parse::Yapp::Driver
#
# This module is part of the Parse::Yapp package available on your
# nearest CPAN
#
# Any use of this module in a standalone parser make the included
# text under the same copyright as the Parse::Yapp module itself.
#
# This notice should remain unchanged.
#
# (c) Copyright 1998-2001 Francois Desarmenien, all rights reserved.
# (see the pod text in Parse::Yapp module for use and distribution rights)
#

package Parse::Yapp::Driver;

require 5.004;

use strict;

use vars qw ( $VERSION $COMPATIBLE $FILENAME );

$VERSION = '1.05';
$COMPATIBLE = '0.07';
$FILENAME=__FILE__;

use Carp;

#Known parameters, all starting with YY (leading YY will be discarded)
my(%params)=(YYLEX => 'CODE', 'YYERROR' => 'CODE', YYVERSION => '',
			 YYRULES => 'ARRAY', YYSTATES => 'ARRAY', YYDEBUG => '');
#Mandatory parameters
my(@params)=('LEX','RULES','STATES');

sub new {
    my($class)=shift;
	my($errst,$nberr,$token,$value,$check,$dotpos);
    my($self)={ ERROR => \&_Error,
				ERRST => \$errst,
                NBERR => \$nberr,
				TOKEN => \$token,
				VALUE => \$value,
				DOTPOS => \$dotpos,
				STACK => [],
				DEBUG => 0,
				CHECK => \$check };

	_CheckParams( [], \%params, \@_, $self );

		exists($$self{VERSION})
	and	$$self{VERSION} < $COMPATIBLE
	and	croak "Yapp driver version $VERSION ".
			  "incompatible with version $$self{VERSION}:\n".
			  "Please recompile parser module.";

        ref($class)
    and $class=ref($class);

    bless($self,$class);
}

sub YYParse {
    my($self)=shift;
    my($retval);

	_CheckParams( \@params, \%params, \@_, $self );

	if($$self{DEBUG}) {
		_DBLoad();
		$retval = eval '$self->_DBParse()';#Do not create stab entry on compile
        $@ and die $@;
	}
	else {
		$retval = $self->_Parse();
	}
    $retval
}

sub YYData {
	my($self)=shift;

		exists($$self{USER})
	or	$$self{USER}={};

	$$self{USER};
	
}

sub YYErrok {
	my($self)=shift;

	${$$self{ERRST}}=0;
    undef;
}

sub YYNberr {
	my($self)=shift;

	${$$self{NBERR}};
}

sub YYRecovering {
	my($self)=shift;

	${$$self{ERRST}} != 0;
}

sub YYAbort {
	my($self)=shift;

	${$$self{CHECK}}='ABORT';
    undef;
}

sub YYAccept {
	my($self)=shift;

	${$$self{CHECK}}='ACCEPT';
    undef;
}

sub YYError {
	my($self)=shift;

	${$$self{CHECK}}='ERROR';
    undef;
}

sub YYSemval {
	my($self)=shift;
	my($index)= $_[0] - ${$$self{DOTPOS}} - 1;

		$index < 0
	and	-$index <= @{$$self{STACK}}
	and	return $$self{STACK}[$index][1];

	undef;	#Invalid index
}

sub YYCurtok {
	my($self)=shift;

        @_
    and ${$$self{TOKEN}}=$_[0];
    ${$$self{TOKEN}};
}

sub YYCurval {
	my($self)=shift;

        @_
    and ${$$self{VALUE}}=$_[0];
    ${$$self{VALUE}};
}

sub YYExpect {
    my($self)=shift;

    keys %{$self->{STATES}[$self->{STACK}[-1][0]]{ACTIONS}}
}

sub YYLexer {
    my($self)=shift;

	$$self{LEX};
}


#################
# Private stuff #
#################


sub _CheckParams {
	my($mandatory,$checklist,$inarray,$outhash)=@_;
	my($prm,$value);
	my($prmlst)={};

	while(($prm,$value)=splice(@$inarray,0,2)) {
        $prm=uc($prm);
			exists($$checklist{$prm})
		or	croak("Unknow parameter '$prm'");
			ref($value) eq $$checklist{$prm}
		or	croak("Invalid value for parameter '$prm'");
        $prm=unpack('@2A*',$prm);
		$$outhash{$prm}=$value;
	}
	for (@$mandatory) {
			exists($$outhash{$_})
		or	croak("Missing mandatory parameter '".lc($_)."'");
	}
}

sub _Error {
	print "Parse error.\n";
}

sub _DBLoad {
	{
		no strict 'refs';

			exists(${__PACKAGE__.'::'}{_DBParse})#Already loaded ?
		and	return;
	}
	my($fname)=__FILE__;
	my(@drv);
	open(DRV,"<$fname") or die "Report this as a BUG: Cannot open $fname";
	while(<DRV>) {
                	/^\s*sub\s+_Parse\s*{\s*$/ .. /^\s*}\s*#\s*_Parse\s*$/
        	and     do {
                	s/^#DBG>//;
                	push(@drv,$_);
        	}
	}
	close(DRV);

	$drv[0]=~s/_P/_DBP/;
	eval join('',@drv);
}

#Note that for loading debugging version of the driver,
#this file will be parsed from 'sub _Parse' up to '}#_Parse' inclusive.
#So, DO NOT remove comment at end of sub !!!
sub _Parse {
    my($self)=shift;

	my($rules,$states,$lex,$error)
     = @$self{ 'RULES', 'STATES', 'LEX', 'ERROR' };
	my($errstatus,$nberror,$token,$value,$stack,$check,$dotpos)
     = @$self{ 'ERRST', 'NBERR', 'TOKEN', 'VALUE', 'STACK', 'CHECK', 'DOTPOS' };

#DBG>	my($debug)=$$self{DEBUG};
#DBG>	my($dbgerror)=0;

#DBG>	my($ShowCurToken) = sub {
#DBG>		my($tok)='>';
#DBG>		for (split('',$$token)) {
#DBG>			$tok.=		(ord($_) < 32 or ord($_) > 126)
#DBG>					?	sprintf('<%02X>',ord($_))
#DBG>					:	$_;
#DBG>		}
#DBG>		$tok.='<';
#DBG>	};

	$$errstatus=0;
	$$nberror=0;
	($$token,$$value)=(undef,undef);
	@$stack=( [ 0, undef ] );
	$$check='';

    while(1) {
        my($actions,$act,$stateno);

        $stateno=$$stack[-1][0];
        $actions=$$states[$stateno];

#DBG>	print STDERR ('-' x 40),"\n";
#DBG>		$debug & 0x2
#DBG>	and	print STDERR "In state $stateno:\n";
#DBG>		$debug & 0x08
#DBG>	and	print STDERR "Stack:[".
#DBG>					 join(',',map { $$_[0] } @$stack).
#DBG>					 "]\n";


        if  (exists($$actions{ACTIONS})) {

				defined($$token)
            or	do {
				($$token,$$value)=&$lex($self);
#DBG>				$debug & 0x01
#DBG>			and	print STDERR "Need token. Got ".&$ShowCurToken."\n";
			};

            $act=   exists($$actions{ACTIONS}{$$token})
                    ?   $$actions{ACTIONS}{$$token}
                    :   exists($$actions{DEFAULT})
                        ?   $$actions{DEFAULT}
                        :   undef;
        }
        else {
            $act=$$actions{DEFAULT};
#DBG>			$debug & 0x01
#DBG>		and	print STDERR "Don't need token.\n";
        }

            defined($act)
        and do {

                $act > 0
            and do {        #shift

#DBG>				$debug & 0x04
#DBG>			and	print STDERR "Shift and go to state $act.\n";

					$$errstatus
				and	do {
					--$$errstatus;

#DBG>					$debug & 0x10
#DBG>				and	$dbgerror
#DBG>				and	$$errstatus == 0
#DBG>				and	do {
#DBG>					print STDERR "**End of Error recovery.\n";
#DBG>					$dbgerror=0;
#DBG>				};
				};


                push(@$stack,[ $act, $$value ]);

					$$token ne ''	#Don't eat the eof
				and	$$token=$$value=undef;
                next;
            };

            #reduce
            my($lhs,$len,$code,@sempar,$semval);
            ($lhs,$len,$code)=@{$$rules[-$act]};

#DBG>			$debug & 0x04
#DBG>		and	$act
#DBG>		and	print STDERR "Reduce using rule ".-$act." ($lhs,$len): ";

                $act
            or  $self->YYAccept();

            $$dotpos=$len;

                unpack('A1',$lhs) eq '@'    #In line rule
            and do {
                    $lhs =~ /^\@[0-9]+\-([0-9]+)$/
                or  die "In line rule name '$lhs' ill formed: ".
                        "report it as a BUG.\n";
                $$dotpos = $1;
            };

            @sempar =       $$dotpos
                        ?   map { $$_[1] } @$stack[ -$$dotpos .. -1 ]
                        :   ();

            $semval = $code ? &$code( $self, @sempar )
                            : @sempar ? $sempar[0] : undef;

            splice(@$stack,-$len,$len);

                $$check eq 'ACCEPT'
            and do {

#DBG>			$debug & 0x04
#DBG>		and	print STDERR "Accept.\n";

				return($semval);
			};

                $$check eq 'ABORT'
            and	do {

#DBG>			$debug & 0x04
#DBG>		and	print STDERR "Abort.\n";

				return(undef);

			};

#DBG>			$debug & 0x04
#DBG>		and	print STDERR "Back to state $$stack[-1][0], then ";

                $$check eq 'ERROR'
            or  do {
#DBG>				$debug & 0x04
#DBG>			and	print STDERR 
#DBG>				    "go to state $$states[$$stack[-1][0]]{GOTOS}{$lhs}.\n";

#DBG>				$debug & 0x10
#DBG>			and	$dbgerror
#DBG>			and	$$errstatus == 0
#DBG>			and	do {
#DBG>				print STDERR "**End of Error recovery.\n";
#DBG>				$dbgerror=0;
#DBG>			};

			    push(@$stack,
                     [ $$states[$$stack[-1][0]]{GOTOS}{$lhs}, $semval ]);
                $$check='';
                next;
            };

#DBG>			$debug & 0x04
#DBG>		and	print STDERR "Forced Error recovery.\n";

            $$check='';

        };

        #Error
            $$errstatus
        or   do {

            $$errstatus = 1;
            &$error($self);
                $$errstatus # if 0, then YYErrok has been called
            or  next;       # so continue parsing

#DBG>			$debug & 0x10
#DBG>		and	do {
#DBG>			print STDERR "**Entering Error recovery.\n";
#DBG>			++$dbgerror;
#DBG>		};

            ++$$nberror;

        };

			$$errstatus == 3	#The next token is not valid: discard it
		and	do {
				$$token eq ''	# End of input: no hope
			and	do {
#DBG>				$debug & 0x10
#DBG>			and	print STDERR "**At eof: aborting.\n";
				return(undef);
			};

#DBG>			$debug & 0x10
#DBG>		and	print STDERR "**Dicard invalid token ".&$ShowCurToken.".\n";

			$$token=$$value=undef;
		};

        $$errstatus=3;

		while(	  @$stack
			  and (		not exists($$states[$$stack[-1][0]]{ACTIONS})
			        or  not exists($$states[$$stack[-1][0]]{ACTIONS}{error})
					or	$$states[$$stack[-1][0]]{ACTIONS}{error} <= 0)) {

#DBG>			$debug & 0x10
#DBG>		and	print STDERR "**Pop state $$stack[-1][0].\n";

			pop(@$stack);
		}

			@$stack
		or	do {

#DBG>			$debug & 0x10
#DBG>		and	print STDERR "**No state left on stack: aborting.\n";

			return(undef);
		};

		#shift the error token

#DBG>			$debug & 0x10
#DBG>		and	print STDERR "**Shift \$error token and go to state ".
#DBG>						 $$states[$$stack[-1][0]]{ACTIONS}{error}.
#DBG>						 ".\n";

		push(@$stack, [ $$states[$$stack[-1][0]]{ACTIONS}{error}, undef ]);

    }

    #never reached
	croak("Error in driver logic. Please, report it as a BUG");

}#_Parse
#DO NOT remove comment

1;

}
#End of include--------------------------------------------------




sub new {
        my($class)=shift;
        ref($class)
    and $class=ref($class);

    my($self)=$class->SUPER::new( yyversion => '1.05',
                                  yystates =>
[
	{#State 0
		DEFAULT => -1,
		GOTOS => {
			'idl' => 1
		}
	},
	{#State 1
		ACTIONS => {
			'' => 2
		},
		DEFAULT => -63,
		GOTOS => {
			'interface' => 3,
			'coclass' => 4,
			'property_list' => 5
		}
	},
	{#State 2
		DEFAULT => 0
	},
	{#State 3
		DEFAULT => -2
	},
	{#State 4
		DEFAULT => -3
	},
	{#State 5
		ACTIONS => {
			"coclass" => 6,
			"interface" => 8,
			"[" => 7
		}
	},
	{#State 6
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 10
		}
	},
	{#State 7
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 11,
			'properties' => 13,
			'property' => 12
		}
	},
	{#State 8
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 14
		}
	},
	{#State 9
		DEFAULT => -89
	},
	{#State 10
		ACTIONS => {
			"{" => 15
		}
	},
	{#State 11
		ACTIONS => {
			"(" => 16
		},
		DEFAULT => -67
	},
	{#State 12
		DEFAULT => -65
	},
	{#State 13
		ACTIONS => {
			"," => 17,
			"]" => 18
		}
	},
	{#State 14
		ACTIONS => {
			":" => 19
		},
		DEFAULT => -8,
		GOTOS => {
			'base_interface' => 20
		}
	},
	{#State 15
		DEFAULT => -5,
		GOTOS => {
			'interface_names' => 21
		}
	},
	{#State 16
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'listtext' => 26,
			'anytext' => 25,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 17
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 11,
			'property' => 29
		}
	},
	{#State 18
		DEFAULT => -64
	},
	{#State 19
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 30
		}
	},
	{#State 20
		ACTIONS => {
			"{" => 31
		}
	},
	{#State 21
		ACTIONS => {
			"}" => 32,
			"interface" => 33
		}
	},
	{#State 22
		DEFAULT => -93
	},
	{#State 23
		DEFAULT => -74
	},
	{#State 24
		DEFAULT => -76
	},
	{#State 25
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"&" => 39,
			"{" => 38,
			"/" => 40,
			"(" => 41,
			"|" => 42,
			"*" => 43,
			"." => 44,
			">" => 45
		},
		DEFAULT => -69
	},
	{#State 26
		ACTIONS => {
			"," => 46,
			")" => 47
		}
	},
	{#State 27
		DEFAULT => -75
	},
	{#State 28
		DEFAULT => -92
	},
	{#State 29
		DEFAULT => -66
	},
	{#State 30
		DEFAULT => -9
	},
	{#State 31
		ACTIONS => {
			"typedef" => 48,
			"union" => 49,
			"enum" => 62,
			"bitmap" => 63,
			"declare" => 55,
			"const" => 57,
			"struct" => 60
		},
		DEFAULT => -63,
		GOTOS => {
			'typedecl' => 61,
			'function' => 50,
			'bitmap' => 64,
			'definitions' => 51,
			'definition' => 54,
			'property_list' => 53,
			'usertype' => 52,
			'declare' => 66,
			'const' => 65,
			'struct' => 56,
			'enum' => 58,
			'typedef' => 59,
			'union' => 67
		}
	},
	{#State 32
		ACTIONS => {
			";" => 68
		},
		DEFAULT => -94,
		GOTOS => {
			'optional_semicolon' => 69
		}
	},
	{#State 33
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 70
		}
	},
	{#State 34
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 71,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 35
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 72,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 36
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 73,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 37
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 74,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 38
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 75,
			'text' => 24,
			'constant' => 27,
			'commalisttext' => 76
		}
	},
	{#State 39
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 77,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 40
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 78,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 41
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 75,
			'text' => 24,
			'constant' => 27,
			'commalisttext' => 79
		}
	},
	{#State 42
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 80,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 43
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 81,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 44
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 82,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 45
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 83,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 46
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 84,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 47
		DEFAULT => -68
	},
	{#State 48
		DEFAULT => -63,
		GOTOS => {
			'property_list' => 85
		}
	},
	{#State 49
		ACTIONS => {
			'IDENTIFIER' => 86
		},
		DEFAULT => -91,
		GOTOS => {
			'optional_identifier' => 87
		}
	},
	{#State 50
		DEFAULT => -12
	},
	{#State 51
		ACTIONS => {
			"}" => 88,
			"typedef" => 48,
			"union" => 49,
			"enum" => 62,
			"bitmap" => 63,
			"declare" => 55,
			"const" => 57,
			"struct" => 60
		},
		DEFAULT => -63,
		GOTOS => {
			'typedecl' => 61,
			'function' => 50,
			'bitmap' => 64,
			'definition' => 89,
			'property_list' => 53,
			'usertype' => 52,
			'const' => 65,
			'struct' => 56,
			'declare' => 66,
			'enum' => 58,
			'typedef' => 59,
			'union' => 67
		}
	},
	{#State 52
		ACTIONS => {
			";" => 90
		}
	},
	{#State 53
		ACTIONS => {
			'IDENTIFIER' => 9,
			"union" => 49,
			"enum" => 62,
			"bitmap" => 63,
			"[" => 7,
			'void' => 91,
			"struct" => 60
		},
		GOTOS => {
			'identifier' => 93,
			'struct' => 56,
			'enum' => 58,
			'type' => 94,
			'union' => 67,
			'bitmap' => 64,
			'usertype' => 92
		}
	},
	{#State 54
		DEFAULT => -10
	},
	{#State 55
		DEFAULT => -63,
		GOTOS => {
			'property_list' => 95
		}
	},
	{#State 56
		DEFAULT => -26
	},
	{#State 57
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 96
		}
	},
	{#State 58
		DEFAULT => -28
	},
	{#State 59
		DEFAULT => -14
	},
	{#State 60
		ACTIONS => {
			'IDENTIFIER' => 86
		},
		DEFAULT => -91,
		GOTOS => {
			'optional_identifier' => 97
		}
	},
	{#State 61
		DEFAULT => -16
	},
	{#State 62
		ACTIONS => {
			'IDENTIFIER' => 86
		},
		DEFAULT => -91,
		GOTOS => {
			'optional_identifier' => 98
		}
	},
	{#State 63
		ACTIONS => {
			'IDENTIFIER' => 86
		},
		DEFAULT => -91,
		GOTOS => {
			'optional_identifier' => 99
		}
	},
	{#State 64
		DEFAULT => -29
	},
	{#State 65
		DEFAULT => -13
	},
	{#State 66
		DEFAULT => -15
	},
	{#State 67
		DEFAULT => -27
	},
	{#State 68
		DEFAULT => -95
	},
	{#State 69
		DEFAULT => -4
	},
	{#State 70
		ACTIONS => {
			";" => 100
		}
	},
	{#State 71
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -77
	},
	{#State 72
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"*" => 43,
			"{" => 38,
			"&" => 39,
			"/" => 40,
			"(" => 41,
			"|" => 42,
			"." => 44,
			">" => 45
		},
		DEFAULT => -81
	},
	{#State 73
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"*" => 43,
			"{" => 38,
			"&" => 39,
			"/" => 40,
			"(" => 41,
			"|" => 42,
			"." => 44,
			">" => 45
		},
		DEFAULT => -86
	},
	{#State 74
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -85
	},
	{#State 75
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"*" => 43,
			"{" => 38,
			"&" => 39,
			"/" => 40,
			"(" => 41,
			"|" => 42,
			"." => 44,
			">" => 45
		},
		DEFAULT => -71
	},
	{#State 76
		ACTIONS => {
			"}" => 101,
			"," => 102
		}
	},
	{#State 77
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -83
	},
	{#State 78
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -84
	},
	{#State 79
		ACTIONS => {
			"," => 102,
			")" => 103
		}
	},
	{#State 80
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -82
	},
	{#State 81
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -79
	},
	{#State 82
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -78
	},
	{#State 83
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -80
	},
	{#State 84
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"&" => 39,
			"{" => 38,
			"/" => 40,
			"|" => 42,
			"(" => 41,
			"*" => 43,
			"." => 44,
			">" => 45
		},
		DEFAULT => -70
	},
	{#State 85
		ACTIONS => {
			'IDENTIFIER' => 9,
			"union" => 49,
			"enum" => 62,
			"bitmap" => 63,
			"[" => 7,
			'void' => 91,
			"struct" => 60
		},
		GOTOS => {
			'identifier' => 93,
			'struct' => 56,
			'enum' => 58,
			'type' => 104,
			'union' => 67,
			'bitmap' => 64,
			'usertype' => 92
		}
	},
	{#State 86
		DEFAULT => -90
	},
	{#State 87
		ACTIONS => {
			"{" => 105
		}
	},
	{#State 88
		ACTIONS => {
			";" => 68
		},
		DEFAULT => -94,
		GOTOS => {
			'optional_semicolon' => 106
		}
	},
	{#State 89
		DEFAULT => -11
	},
	{#State 90
		DEFAULT => -30
	},
	{#State 91
		DEFAULT => -33
	},
	{#State 92
		DEFAULT => -31
	},
	{#State 93
		DEFAULT => -32
	},
	{#State 94
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 107
		}
	},
	{#State 95
		ACTIONS => {
			"enum" => 111,
			"bitmap" => 112,
			"[" => 7
		},
		GOTOS => {
			'decl_enum' => 108,
			'decl_bitmap' => 109,
			'decl_type' => 110
		}
	},
	{#State 96
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 113
		}
	},
	{#State 97
		ACTIONS => {
			"{" => 114
		}
	},
	{#State 98
		ACTIONS => {
			"{" => 115
		}
	},
	{#State 99
		ACTIONS => {
			"{" => 116
		}
	},
	{#State 100
		DEFAULT => -6
	},
	{#State 101
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 117,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 102
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 118,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 103
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 119,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 104
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 120
		}
	},
	{#State 105
		DEFAULT => -48,
		GOTOS => {
			'union_elements' => 121
		}
	},
	{#State 106
		DEFAULT => -7
	},
	{#State 107
		ACTIONS => {
			"(" => 122
		}
	},
	{#State 108
		DEFAULT => -21
	},
	{#State 109
		DEFAULT => -22
	},
	{#State 110
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 123
		}
	},
	{#State 111
		DEFAULT => -23
	},
	{#State 112
		DEFAULT => -24
	},
	{#State 113
		ACTIONS => {
			"[" => 124,
			"=" => 126
		},
		GOTOS => {
			'array_len' => 125
		}
	},
	{#State 114
		DEFAULT => -54,
		GOTOS => {
			'element_list1' => 127
		}
	},
	{#State 115
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 128,
			'enum_element' => 129,
			'enum_elements' => 130
		}
	},
	{#State 116
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 133,
			'bitmap_elements' => 132,
			'bitmap_element' => 131
		}
	},
	{#State 117
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"*" => 43,
			"{" => 38,
			"&" => 39,
			"/" => 40,
			"(" => 41,
			"|" => 42,
			"." => 44,
			">" => 45
		},
		DEFAULT => -88
	},
	{#State 118
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"*" => 43,
			"{" => 38,
			"&" => 39,
			"/" => 40,
			"(" => 41,
			"|" => 42,
			"." => 44,
			">" => 45
		},
		DEFAULT => -72
	},
	{#State 119
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -87
	},
	{#State 120
		ACTIONS => {
			"[" => 124
		},
		DEFAULT => -60,
		GOTOS => {
			'array_len' => 134
		}
	},
	{#State 121
		ACTIONS => {
			"}" => 135
		},
		DEFAULT => -63,
		GOTOS => {
			'optional_base_element' => 137,
			'property_list' => 136
		}
	},
	{#State 122
		ACTIONS => {
			"," => -56,
			"void" => 141,
			")" => -56
		},
		DEFAULT => -63,
		GOTOS => {
			'base_element' => 138,
			'element_list2' => 140,
			'property_list' => 139
		}
	},
	{#State 123
		ACTIONS => {
			";" => 142
		}
	},
	{#State 124
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			"]" => 143,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 144,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 125
		ACTIONS => {
			"=" => 145
		}
	},
	{#State 126
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 146,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 127
		ACTIONS => {
			"}" => 147
		},
		DEFAULT => -63,
		GOTOS => {
			'base_element' => 148,
			'property_list' => 139
		}
	},
	{#State 128
		ACTIONS => {
			"=" => 149
		},
		DEFAULT => -37
	},
	{#State 129
		DEFAULT => -35
	},
	{#State 130
		ACTIONS => {
			"}" => 150,
			"," => 151
		}
	},
	{#State 131
		DEFAULT => -40
	},
	{#State 132
		ACTIONS => {
			"}" => 152,
			"," => 153
		}
	},
	{#State 133
		ACTIONS => {
			"=" => 154
		}
	},
	{#State 134
		ACTIONS => {
			";" => 155
		}
	},
	{#State 135
		DEFAULT => -50
	},
	{#State 136
		ACTIONS => {
			"[" => 7
		},
		DEFAULT => -63,
		GOTOS => {
			'base_or_empty' => 156,
			'base_element' => 157,
			'empty_element' => 158,
			'property_list' => 159
		}
	},
	{#State 137
		DEFAULT => -49
	},
	{#State 138
		DEFAULT => -58
	},
	{#State 139
		ACTIONS => {
			'IDENTIFIER' => 9,
			"union" => 49,
			"enum" => 62,
			"bitmap" => 63,
			"[" => 7,
			'void' => 91,
			"struct" => 60
		},
		GOTOS => {
			'identifier' => 93,
			'struct' => 56,
			'enum' => 58,
			'type' => 160,
			'union' => 67,
			'bitmap' => 64,
			'usertype' => 92
		}
	},
	{#State 140
		ACTIONS => {
			"," => 161,
			")" => 162
		}
	},
	{#State 141
		DEFAULT => -57
	},
	{#State 142
		DEFAULT => -20
	},
	{#State 143
		ACTIONS => {
			"[" => 124
		},
		DEFAULT => -60,
		GOTOS => {
			'array_len' => 163
		}
	},
	{#State 144
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"&" => 39,
			"{" => 38,
			"/" => 40,
			"|" => 42,
			"(" => 41,
			"*" => 43,
			"." => 44,
			"]" => 164,
			">" => 45
		}
	},
	{#State 145
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 165,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 146
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			";" => 166,
			"+" => 37,
			"~" => 36,
			"&" => 39,
			"{" => 38,
			"/" => 40,
			"|" => 42,
			"(" => 41,
			"*" => 43,
			"." => 44,
			">" => 45
		}
	},
	{#State 147
		DEFAULT => -43
	},
	{#State 148
		ACTIONS => {
			";" => 167
		}
	},
	{#State 149
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 168,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 150
		DEFAULT => -34
	},
	{#State 151
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 128,
			'enum_element' => 169
		}
	},
	{#State 152
		DEFAULT => -39
	},
	{#State 153
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 133,
			'bitmap_element' => 170
		}
	},
	{#State 154
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 171,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 155
		DEFAULT => -25
	},
	{#State 156
		DEFAULT => -47
	},
	{#State 157
		ACTIONS => {
			";" => 172
		}
	},
	{#State 158
		DEFAULT => -46
	},
	{#State 159
		ACTIONS => {
			'IDENTIFIER' => 9,
			"union" => 49,
			";" => 173,
			"enum" => 62,
			"bitmap" => 63,
			'void' => 91,
			"[" => 7,
			"struct" => 60
		},
		GOTOS => {
			'identifier' => 93,
			'struct' => 56,
			'enum' => 58,
			'type' => 160,
			'union' => 67,
			'bitmap' => 64,
			'usertype' => 92
		}
	},
	{#State 160
		DEFAULT => -52,
		GOTOS => {
			'pointers' => 174
		}
	},
	{#State 161
		DEFAULT => -63,
		GOTOS => {
			'base_element' => 175,
			'property_list' => 139
		}
	},
	{#State 162
		ACTIONS => {
			";" => 176
		}
	},
	{#State 163
		DEFAULT => -61
	},
	{#State 164
		ACTIONS => {
			"[" => 124
		},
		DEFAULT => -60,
		GOTOS => {
			'array_len' => 177
		}
	},
	{#State 165
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			";" => 178,
			"+" => 37,
			"~" => 36,
			"&" => 39,
			"{" => 38,
			"/" => 40,
			"|" => 42,
			"(" => 41,
			"*" => 43,
			"." => 44,
			">" => 45
		}
	},
	{#State 166
		DEFAULT => -17
	},
	{#State 167
		DEFAULT => -55
	},
	{#State 168
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"&" => 39,
			"{" => 38,
			"/" => 40,
			"|" => 42,
			"(" => 41,
			"*" => 43,
			"." => 44,
			">" => 45
		},
		DEFAULT => -38
	},
	{#State 169
		DEFAULT => -36
	},
	{#State 170
		DEFAULT => -41
	},
	{#State 171
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"&" => 39,
			"{" => 38,
			"/" => 40,
			"|" => 42,
			"(" => 41,
			"*" => 43,
			"." => 44,
			">" => 45
		},
		DEFAULT => -42
	},
	{#State 172
		DEFAULT => -45
	},
	{#State 173
		DEFAULT => -44
	},
	{#State 174
		ACTIONS => {
			'IDENTIFIER' => 9,
			"*" => 180
		},
		GOTOS => {
			'identifier' => 179
		}
	},
	{#State 175
		DEFAULT => -59
	},
	{#State 176
		DEFAULT => -19
	},
	{#State 177
		DEFAULT => -62
	},
	{#State 178
		DEFAULT => -18
	},
	{#State 179
		ACTIONS => {
			"[" => 124
		},
		DEFAULT => -60,
		GOTOS => {
			'array_len' => 181
		}
	},
	{#State 180
		DEFAULT => -53
	},
	{#State 181
		DEFAULT => -51
	}
],
                                  yyrules  =>
[
	[#Rule 0
		 '$start', 2, undef
	],
	[#Rule 1
		 'idl', 0, undef
	],
	[#Rule 2
		 'idl', 2,
sub
#line 19 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 3
		 'idl', 2,
sub
#line 20 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 4
		 'coclass', 7,
sub
#line 24 "build/pidl/idl.yp"
{$_[3] => {
               "TYPE" => "COCLASS", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "DATA" => $_[5],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 5
		 'interface_names', 0, undef
	],
	[#Rule 6
		 'interface_names', 4,
sub
#line 36 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 7
		 'interface', 8,
sub
#line 40 "build/pidl/idl.yp"
{$_[3] => {
               "TYPE" => "INTERFACE", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "BASE" => $_[4],
	       "DATA" => $_[6],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 8
		 'base_interface', 0, undef
	],
	[#Rule 9
		 'base_interface', 2,
sub
#line 53 "build/pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 10
		 'definitions', 1,
sub
#line 57 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 11
		 'definitions', 2,
sub
#line 58 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 12
		 'definition', 1, undef
	],
	[#Rule 13
		 'definition', 1, undef
	],
	[#Rule 14
		 'definition', 1, undef
	],
	[#Rule 15
		 'definition', 1, undef
	],
	[#Rule 16
		 'definition', 1, undef
	],
	[#Rule 17
		 'const', 6,
sub
#line 66 "build/pidl/idl.yp"
{{
                     "TYPE"  => "CONST", 
		     "DTYPE"  => $_[2],
		     "NAME"  => $_[3],
		     "VALUE" => $_[5],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 18
		 'const', 7,
sub
#line 75 "build/pidl/idl.yp"
{{
                     "TYPE"  => "CONST", 
		     "DTYPE"  => $_[2],
		     "NAME"  => $_[3],
		     "ARRAY_LEN" => $_[4],
		     "VALUE" => $_[6],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 19
		 'function', 7,
sub
#line 88 "build/pidl/idl.yp"
{{
		"TYPE" => "FUNCTION",
		"NAME" => $_[3],
		"RETURN_TYPE" => $_[2],
		"PROPERTIES" => $_[1],
		"ELEMENTS" => $_[5],
		"FILE" => $_[0]->YYData->{INPUT_FILENAME},
		"LINE" => $_[0]->YYData->{LINE},
	  }}
	],
	[#Rule 20
		 'declare', 5,
sub
#line 100 "build/pidl/idl.yp"
{{
	             "TYPE" => "DECLARE", 
                     "PROPERTIES" => $_[2],
		     "NAME" => $_[4],
		     "DATA" => $_[3],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 21
		 'decl_type', 1, undef
	],
	[#Rule 22
		 'decl_type', 1, undef
	],
	[#Rule 23
		 'decl_enum', 1,
sub
#line 114 "build/pidl/idl.yp"
{{
                     "TYPE" => "ENUM"
        }}
	],
	[#Rule 24
		 'decl_bitmap', 1,
sub
#line 120 "build/pidl/idl.yp"
{{
                     "TYPE" => "BITMAP"
        }}
	],
	[#Rule 25
		 'typedef', 6,
sub
#line 126 "build/pidl/idl.yp"
{{
	             "TYPE" => "TYPEDEF", 
                     "PROPERTIES" => $_[2],
		     "NAME" => $_[4],
		     "DATA" => $_[3],
		     "ARRAY_LEN" => $_[5],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 26
		 'usertype', 1, undef
	],
	[#Rule 27
		 'usertype', 1, undef
	],
	[#Rule 28
		 'usertype', 1, undef
	],
	[#Rule 29
		 'usertype', 1, undef
	],
	[#Rule 30
		 'typedecl', 2,
sub
#line 139 "build/pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 31
		 'type', 1, undef
	],
	[#Rule 32
		 'type', 1, undef
	],
	[#Rule 33
		 'type', 1,
sub
#line 142 "build/pidl/idl.yp"
{ "void" }
	],
	[#Rule 34
		 'enum', 5,
sub
#line 146 "build/pidl/idl.yp"
{{
             "TYPE" => "ENUM", 
			 "NAME" => $_[2],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 35
		 'enum_elements', 1,
sub
#line 154 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 36
		 'enum_elements', 3,
sub
#line 155 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 37
		 'enum_element', 1, undef
	],
	[#Rule 38
		 'enum_element', 3,
sub
#line 159 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 39
		 'bitmap', 5,
sub
#line 163 "build/pidl/idl.yp"
{{
             "TYPE" => "BITMAP", 
			 "NAME" => $_[2],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 40
		 'bitmap_elements', 1,
sub
#line 171 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 41
		 'bitmap_elements', 3,
sub
#line 172 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 42
		 'bitmap_element', 3,
sub
#line 175 "build/pidl/idl.yp"
{ "$_[1] ( $_[3] )" }
	],
	[#Rule 43
		 'struct', 5,
sub
#line 179 "build/pidl/idl.yp"
{{
             "TYPE" => "STRUCT", 
			 "NAME" => $_[2],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 44
		 'empty_element', 2,
sub
#line 187 "build/pidl/idl.yp"
{{
		 "NAME" => "",
		 "TYPE" => "EMPTY",
		 "PROPERTIES" => $_[1],
		 "POINTERS" => 0,
		 "ARRAY_LEN" => [],
		 "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		 "LINE" => $_[0]->YYData->{LINE},
	 }}
	],
	[#Rule 45
		 'base_or_empty', 2, undef
	],
	[#Rule 46
		 'base_or_empty', 1, undef
	],
	[#Rule 47
		 'optional_base_element', 2,
sub
#line 201 "build/pidl/idl.yp"
{ $_[2]->{PROPERTIES} = Parse::Pidl::Util::FlattenHash([$_[1],$_[2]->{PROPERTIES}]); $_[2] }
	],
	[#Rule 48
		 'union_elements', 0, undef
	],
	[#Rule 49
		 'union_elements', 2,
sub
#line 206 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 50
		 'union', 5,
sub
#line 210 "build/pidl/idl.yp"
{{
             "TYPE" => "UNION", 
		     "NAME" => $_[2],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 51
		 'base_element', 5,
sub
#line 218 "build/pidl/idl.yp"
{{
			   "NAME" => $_[4],
			   "TYPE" => $_[2],
			   "PROPERTIES" => $_[1],
			   "POINTERS" => $_[3],
			   "ARRAY_LEN" => $_[5],
		       "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		       "LINE" => $_[0]->YYData->{LINE},
              }}
	],
	[#Rule 52
		 'pointers', 0,
sub
#line 232 "build/pidl/idl.yp"
{ 0 }
	],
	[#Rule 53
		 'pointers', 2,
sub
#line 233 "build/pidl/idl.yp"
{ $_[1]+1 }
	],
	[#Rule 54
		 'element_list1', 0, undef
	],
	[#Rule 55
		 'element_list1', 3,
sub
#line 238 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 56
		 'element_list2', 0, undef
	],
	[#Rule 57
		 'element_list2', 1, undef
	],
	[#Rule 58
		 'element_list2', 1,
sub
#line 244 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 59
		 'element_list2', 3,
sub
#line 245 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 60
		 'array_len', 0, undef
	],
	[#Rule 61
		 'array_len', 3,
sub
#line 250 "build/pidl/idl.yp"
{ push(@{$_[3]}, "*"); $_[3] }
	],
	[#Rule 62
		 'array_len', 4,
sub
#line 251 "build/pidl/idl.yp"
{ push(@{$_[4]}, "$_[2]"); $_[4] }
	],
	[#Rule 63
		 'property_list', 0, undef
	],
	[#Rule 64
		 'property_list', 4,
sub
#line 257 "build/pidl/idl.yp"
{ Parse::Pidl::Util::FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 65
		 'properties', 1,
sub
#line 260 "build/pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 66
		 'properties', 3,
sub
#line 261 "build/pidl/idl.yp"
{ Parse::Pidl::Util::FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 67
		 'property', 1,
sub
#line 264 "build/pidl/idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 68
		 'property', 4,
sub
#line 265 "build/pidl/idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 69
		 'listtext', 1, undef
	],
	[#Rule 70
		 'listtext', 3,
sub
#line 270 "build/pidl/idl.yp"
{ "$_[1] $_[3]" }
	],
	[#Rule 71
		 'commalisttext', 1, undef
	],
	[#Rule 72
		 'commalisttext', 3,
sub
#line 275 "build/pidl/idl.yp"
{ "$_[1],$_[3]" }
	],
	[#Rule 73
		 'anytext', 0,
sub
#line 279 "build/pidl/idl.yp"
{ "" }
	],
	[#Rule 74
		 'anytext', 1, undef
	],
	[#Rule 75
		 'anytext', 1, undef
	],
	[#Rule 76
		 'anytext', 1, undef
	],
	[#Rule 77
		 'anytext', 3,
sub
#line 281 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 78
		 'anytext', 3,
sub
#line 282 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 79
		 'anytext', 3,
sub
#line 283 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 80
		 'anytext', 3,
sub
#line 284 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 81
		 'anytext', 3,
sub
#line 285 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 82
		 'anytext', 3,
sub
#line 286 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 83
		 'anytext', 3,
sub
#line 287 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 84
		 'anytext', 3,
sub
#line 288 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 85
		 'anytext', 3,
sub
#line 289 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 86
		 'anytext', 3,
sub
#line 290 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 87
		 'anytext', 5,
sub
#line 291 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 88
		 'anytext', 5,
sub
#line 292 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 89
		 'identifier', 1, undef
	],
	[#Rule 90
		 'optional_identifier', 1, undef
	],
	[#Rule 91
		 'optional_identifier', 0, undef
	],
	[#Rule 92
		 'constant', 1, undef
	],
	[#Rule 93
		 'text', 1,
sub
#line 306 "build/pidl/idl.yp"
{ "\"$_[1]\"" }
	],
	[#Rule 94
		 'optional_semicolon', 0, undef
	],
	[#Rule 95
		 'optional_semicolon', 1, undef
	]
],
                                  @_);
    bless($self,$class);
}

#line 317 "build/pidl/idl.yp"


use Parse::Pidl::Util;

#####################################################################
# traverse a perl data structure removing any empty arrays or
# hashes and any hash elements that map to undef
sub CleanData($)
{
    sub CleanData($);
    my($v) = shift;
    if (ref($v) eq "ARRAY") {
	foreach my $i (0 .. $#{$v}) {
	    CleanData($v->[$i]);
	    if (ref($v->[$i]) eq "ARRAY" && $#{$v->[$i]}==-1) { 
		    $v->[$i] = undef; 
		    next; 
	    }
	}
	# this removes any undefined elements from the array
	@{$v} = grep { defined $_ } @{$v};
    } elsif (ref($v) eq "HASH") {
	foreach my $x (keys %{$v}) {
	    CleanData($v->{$x});
	    if (!defined $v->{$x}) { delete($v->{$x}); next; }
	    if (ref($v->{$x}) eq "ARRAY" && $#{$v->{$x}}==-1) { delete($v->{$x}); next; }
	}
    }
	return $v;
}

sub _Error {
    if (exists $_[0]->YYData->{ERRMSG}) {
		print $_[0]->YYData->{ERRMSG};
		delete $_[0]->YYData->{ERRMSG};
		return;
	};
	my $line = $_[0]->YYData->{LINE};
	my $last_token = $_[0]->YYData->{LAST_TOKEN};
	my $file = $_[0]->YYData->{INPUT_FILENAME};
	
	print "$file:$line: Syntax error near '$last_token'\n";
}

sub _Lexer($)
{
	my($parser)=shift;

        $parser->YYData->{INPUT}
        or  return('',undef);

again:
	$parser->YYData->{INPUT} =~ s/^[ \t]*//;

	for ($parser->YYData->{INPUT}) {
		if (/^\#/) {
			if (s/^\# (\d+) \"(.*?)\"( \d+|)//) {
				$parser->YYData->{LINE} = $1-1;
				$parser->YYData->{INPUT_FILENAME} = $2;
				goto again;
			}
			if (s/^\#line (\d+) \"(.*?)\"( \d+|)//) {
				$parser->YYData->{LINE} = $1-1;
				$parser->YYData->{INPUT_FILENAME} = $2;
				goto again;
			}
			if (s/^(\#.*)$//m) {
				goto again;
			}
		}
		if (s/^(\n)//) {
			$parser->YYData->{LINE}++;
			goto again;
		}
		if (s/^\"(.*?)\"//) {
			$parser->YYData->{LAST_TOKEN} = $1;
			return('TEXT',$1); 
		}
		if (s/^(\d+)(\W|$)/$2/) {
			$parser->YYData->{LAST_TOKEN} = $1;
			return('CONSTANT',$1); 
		}
		if (s/^([\w_]+)//) {
			$parser->YYData->{LAST_TOKEN} = $1;
			if ($1 =~ 
			    /^(coclass|interface|const|typedef|declare|union
			      |struct|enum|bitmap|void)$/x) {
				return $1;
			}
			return('IDENTIFIER',$1);
		}
		if (s/^(.)//s) {
			$parser->YYData->{LAST_TOKEN} = $1;
			return($1,$1);
		}
	}
}

sub parse_idl($$)
{
	my $self = shift;
	my $filename = shift;

	my $saved_delim = $/;
	undef $/;
	my $cpp = $ENV{CPP};
	if (! defined $cpp) {
		$cpp = "cpp"
	}
	my $data = `$cpp -D__PIDL__ -xc $filename`;
	$/ = $saved_delim;

    $self->YYData->{INPUT} = $data;
    $self->YYData->{LINE} = 0;
    $self->YYData->{LAST_TOKEN} = "NONE";

	my $idl = $self->YYParse( yylex => \&_Lexer, yyerror => \&_Error );

	return CleanData($idl);
}

1;
