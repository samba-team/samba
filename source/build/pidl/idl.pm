####################################################################
#
#    This file was generated using Parse::Yapp version 1.05.
#
#        Don't edit this file, use source file instead.
#
#             ANY CHANGE MADE HERE WILL BE LOST !
#
####################################################################
package idl;
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
		DEFAULT => -48,
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
		DEFAULT => -71
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
		DEFAULT => -52
	},
	{#State 12
		DEFAULT => -50
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
			'interfaces' => 21
		}
	},
	{#State 16
		ACTIONS => {
			'IDENTIFIER' => 9,
			'CONSTANT' => 28,
			'TEXT' => 22
		},
		DEFAULT => -58,
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
		DEFAULT => -49
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
			"}" => 32
		},
		DEFAULT => -48,
		GOTOS => {
			'interface' => 33,
			'property_list' => 34
		}
	},
	{#State 22
		DEFAULT => -73
	},
	{#State 23
		DEFAULT => -59
	},
	{#State 24
		DEFAULT => -61
	},
	{#State 25
		ACTIONS => {
			"-" => 35,
			"+" => 36,
			"&" => 37,
			"/" => 38,
			"|" => 39,
			"(" => 40,
			"*" => 41,
			"." => 42,
			">" => 43
		},
		DEFAULT => -54
	},
	{#State 26
		ACTIONS => {
			"," => 44,
			")" => 45
		}
	},
	{#State 27
		DEFAULT => -60
	},
	{#State 28
		DEFAULT => -72
	},
	{#State 29
		DEFAULT => -51
	},
	{#State 30
		DEFAULT => -9
	},
	{#State 31
		ACTIONS => {
			"typedef" => 46,
			"const" => 52
		},
		DEFAULT => -48,
		GOTOS => {
			'const' => 51,
			'function' => 47,
			'typedef' => 53,
			'definitions' => 48,
			'definition' => 50,
			'property_list' => 49
		}
	},
	{#State 32
		ACTIONS => {
			";" => 55
		},
		DEFAULT => -74,
		GOTOS => {
			'optional_semicolon' => 54
		}
	},
	{#State 33
		DEFAULT => -6
	},
	{#State 34
		ACTIONS => {
			"[" => 7,
			"interface" => 8
		}
	},
	{#State 35
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 56,
			'constant' => 27
		}
	},
	{#State 36
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 57,
			'constant' => 27
		}
	},
	{#State 37
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 58,
			'constant' => 27
		}
	},
	{#State 38
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 59,
			'constant' => 27
		}
	},
	{#State 39
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 60,
			'constant' => 27
		}
	},
	{#State 40
		ACTIONS => {
			'IDENTIFIER' => 9,
			'CONSTANT' => 28,
			'TEXT' => 22
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 61,
			'constant' => 27,
			'commalisttext' => 62
		}
	},
	{#State 41
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 63,
			'constant' => 27
		}
	},
	{#State 42
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 64,
			'constant' => 27
		}
	},
	{#State 43
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 65,
			'constant' => 27
		}
	},
	{#State 44
		ACTIONS => {
			'IDENTIFIER' => 9,
			'CONSTANT' => 28,
			'TEXT' => 22
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 66,
			'constant' => 27
		}
	},
	{#State 45
		DEFAULT => -53
	},
	{#State 46
		ACTIONS => {
			'IDENTIFIER' => 9,
			"enum" => 67,
			'void' => 68
		},
		DEFAULT => -48,
		GOTOS => {
			'identifier' => 70,
			'struct' => 71,
			'enum' => 72,
			'type' => 73,
			'union' => 74,
			'property_list' => 69
		}
	},
	{#State 47
		DEFAULT => -12
	},
	{#State 48
		ACTIONS => {
			"}" => 75,
			"typedef" => 46,
			"const" => 52
		},
		DEFAULT => -48,
		GOTOS => {
			'const' => 51,
			'function' => 47,
			'typedef' => 53,
			'definition' => 76,
			'property_list' => 49
		}
	},
	{#State 49
		ACTIONS => {
			'IDENTIFIER' => 9,
			"enum" => 67,
			"[" => 7,
			'void' => 68
		},
		DEFAULT => -48,
		GOTOS => {
			'identifier' => 70,
			'struct' => 71,
			'enum' => 72,
			'type' => 77,
			'union' => 74,
			'property_list' => 69
		}
	},
	{#State 50
		DEFAULT => -10
	},
	{#State 51
		DEFAULT => -13
	},
	{#State 52
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 78
		}
	},
	{#State 53
		DEFAULT => -14
	},
	{#State 54
		DEFAULT => -4
	},
	{#State 55
		DEFAULT => -75
	},
	{#State 56
		DEFAULT => -62
	},
	{#State 57
		DEFAULT => -69
	},
	{#State 58
		DEFAULT => -67
	},
	{#State 59
		DEFAULT => -68
	},
	{#State 60
		DEFAULT => -66
	},
	{#State 61
		ACTIONS => {
			"-" => 35,
			"+" => 36,
			"&" => 37,
			"/" => 38,
			"(" => 40,
			"|" => 39,
			"*" => 41,
			"." => 42,
			">" => 43
		},
		DEFAULT => -56
	},
	{#State 62
		ACTIONS => {
			"," => 79,
			")" => 80
		}
	},
	{#State 63
		DEFAULT => -64
	},
	{#State 64
		DEFAULT => -63
	},
	{#State 65
		DEFAULT => -65
	},
	{#State 66
		ACTIONS => {
			"-" => 35,
			"+" => 36,
			"&" => 37,
			"/" => 38,
			"(" => 40,
			"|" => 39,
			"*" => 41,
			"." => 42,
			">" => 43
		},
		DEFAULT => -55
	},
	{#State 67
		ACTIONS => {
			"{" => 81
		}
	},
	{#State 68
		DEFAULT => -22
	},
	{#State 69
		ACTIONS => {
			"union" => 82,
			"[" => 7,
			"struct" => 83
		}
	},
	{#State 70
		DEFAULT => -21
	},
	{#State 71
		DEFAULT => -18
	},
	{#State 72
		DEFAULT => -20
	},
	{#State 73
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 84
		}
	},
	{#State 74
		DEFAULT => -19
	},
	{#State 75
		ACTIONS => {
			";" => 55
		},
		DEFAULT => -74,
		GOTOS => {
			'optional_semicolon' => 85
		}
	},
	{#State 76
		DEFAULT => -11
	},
	{#State 77
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 86
		}
	},
	{#State 78
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 87
		}
	},
	{#State 79
		ACTIONS => {
			'IDENTIFIER' => 9,
			'CONSTANT' => 28,
			'TEXT' => 22
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 88,
			'constant' => 27
		}
	},
	{#State 80
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 89,
			'constant' => 27
		}
	},
	{#State 81
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 90,
			'enum_element' => 91,
			'enum_elements' => 92
		}
	},
	{#State 82
		ACTIONS => {
			"{" => 93
		}
	},
	{#State 83
		ACTIONS => {
			"{" => 94
		}
	},
	{#State 84
		ACTIONS => {
			"[" => 96
		},
		DEFAULT => -45,
		GOTOS => {
			'array_len' => 95
		}
	},
	{#State 85
		DEFAULT => -7
	},
	{#State 86
		ACTIONS => {
			"(" => 97
		}
	},
	{#State 87
		ACTIONS => {
			"=" => 98
		}
	},
	{#State 88
		ACTIONS => {
			"-" => 35,
			"+" => 36,
			"&" => 37,
			"/" => 38,
			"(" => 40,
			"|" => 39,
			"*" => 41,
			"." => 42,
			">" => 43
		},
		DEFAULT => -57
	},
	{#State 89
		DEFAULT => -70
	},
	{#State 90
		ACTIONS => {
			"=" => 99
		},
		DEFAULT => -26
	},
	{#State 91
		DEFAULT => -24
	},
	{#State 92
		ACTIONS => {
			"}" => 100,
			"," => 101
		}
	},
	{#State 93
		ACTIONS => {
			"[" => 104
		},
		GOTOS => {
			'union_elements' => 102,
			'union_element' => 103
		}
	},
	{#State 94
		DEFAULT => -39,
		GOTOS => {
			'element_list1' => 105
		}
	},
	{#State 95
		ACTIONS => {
			";" => 106
		}
	},
	{#State 96
		ACTIONS => {
			'IDENTIFIER' => 9,
			'CONSTANT' => 28,
			'TEXT' => 22,
			"]" => 108
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 107,
			'constant' => 27
		}
	},
	{#State 97
		ACTIONS => {
			"," => -41,
			"void" => 111,
			")" => -41
		},
		DEFAULT => -48,
		GOTOS => {
			'base_element' => 109,
			'element_list2' => 112,
			'property_list' => 110
		}
	},
	{#State 98
		ACTIONS => {
			'IDENTIFIER' => 9,
			'CONSTANT' => 28,
			'TEXT' => 22
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 113,
			'constant' => 27
		}
	},
	{#State 99
		ACTIONS => {
			'IDENTIFIER' => 9,
			'CONSTANT' => 28,
			'TEXT' => 22
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 114,
			'constant' => 27
		}
	},
	{#State 100
		DEFAULT => -23
	},
	{#State 101
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 90,
			'enum_element' => 115
		}
	},
	{#State 102
		ACTIONS => {
			"}" => 116,
			"[" => 104
		},
		GOTOS => {
			'union_element' => 117
		}
	},
	{#State 103
		DEFAULT => -30
	},
	{#State 104
		ACTIONS => {
			"case" => 118,
			"default" => 119
		}
	},
	{#State 105
		ACTIONS => {
			"}" => 120
		},
		DEFAULT => -48,
		GOTOS => {
			'base_element' => 121,
			'property_list' => 110
		}
	},
	{#State 106
		DEFAULT => -17
	},
	{#State 107
		ACTIONS => {
			"-" => 35,
			"+" => 36,
			"&" => 37,
			"/" => 38,
			"(" => 40,
			"|" => 39,
			"*" => 41,
			"." => 42,
			"]" => 122,
			">" => 43
		}
	},
	{#State 108
		DEFAULT => -46
	},
	{#State 109
		DEFAULT => -43
	},
	{#State 110
		ACTIONS => {
			'IDENTIFIER' => 9,
			"enum" => 67,
			"[" => 7,
			'void' => 68
		},
		DEFAULT => -48,
		GOTOS => {
			'identifier' => 70,
			'struct' => 71,
			'enum' => 72,
			'type' => 123,
			'union' => 74,
			'property_list' => 69
		}
	},
	{#State 111
		DEFAULT => -42
	},
	{#State 112
		ACTIONS => {
			"," => 124,
			")" => 125
		}
	},
	{#State 113
		ACTIONS => {
			"-" => 35,
			"|" => 39,
			"(" => 40,
			"*" => 41,
			";" => 126,
			"+" => 36,
			"&" => 37,
			"/" => 38,
			"." => 42,
			">" => 43
		}
	},
	{#State 114
		ACTIONS => {
			"-" => 35,
			"+" => 36,
			"&" => 37,
			"/" => 38,
			"(" => 40,
			"|" => 39,
			"*" => 41,
			"." => 42,
			">" => 43
		},
		DEFAULT => -27
	},
	{#State 115
		DEFAULT => -25
	},
	{#State 116
		DEFAULT => -29
	},
	{#State 117
		DEFAULT => -31
	},
	{#State 118
		ACTIONS => {
			"(" => 127
		}
	},
	{#State 119
		ACTIONS => {
			"]" => 128
		}
	},
	{#State 120
		DEFAULT => -28
	},
	{#State 121
		ACTIONS => {
			";" => 129
		}
	},
	{#State 122
		DEFAULT => -47
	},
	{#State 123
		DEFAULT => -37,
		GOTOS => {
			'pointers' => 130
		}
	},
	{#State 124
		DEFAULT => -48,
		GOTOS => {
			'base_element' => 131,
			'property_list' => 110
		}
	},
	{#State 125
		ACTIONS => {
			";" => 132
		}
	},
	{#State 126
		DEFAULT => -15
	},
	{#State 127
		ACTIONS => {
			'IDENTIFIER' => 9,
			'CONSTANT' => 28,
			'TEXT' => 22
		},
		DEFAULT => -58,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 133,
			'constant' => 27
		}
	},
	{#State 128
		ACTIONS => {
			";" => 134
		},
		DEFAULT => -48,
		GOTOS => {
			'base_element' => 135,
			'property_list' => 110
		}
	},
	{#State 129
		DEFAULT => -40
	},
	{#State 130
		ACTIONS => {
			'IDENTIFIER' => 9,
			"*" => 137
		},
		GOTOS => {
			'identifier' => 136
		}
	},
	{#State 131
		DEFAULT => -44
	},
	{#State 132
		DEFAULT => -16
	},
	{#State 133
		ACTIONS => {
			"-" => 35,
			"+" => 36,
			"&" => 37,
			"/" => 38,
			"(" => 40,
			"|" => 39,
			"*" => 41,
			"." => 42,
			")" => 138,
			">" => 43
		}
	},
	{#State 134
		DEFAULT => -35
	},
	{#State 135
		ACTIONS => {
			";" => 139
		}
	},
	{#State 136
		ACTIONS => {
			"[" => 96
		},
		DEFAULT => -45,
		GOTOS => {
			'array_len' => 140
		}
	},
	{#State 137
		DEFAULT => -38
	},
	{#State 138
		ACTIONS => {
			"]" => 141
		}
	},
	{#State 139
		DEFAULT => -34
	},
	{#State 140
		DEFAULT => -36
	},
	{#State 141
		ACTIONS => {
			";" => 142
		},
		DEFAULT => -48,
		GOTOS => {
			'base_element' => 143,
			'property_list' => 110
		}
	},
	{#State 142
		DEFAULT => -33
	},
	{#State 143
		ACTIONS => {
			";" => 144
		}
	},
	{#State 144
		DEFAULT => -32
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
          }}
	],
	[#Rule 5
		 'interfaces', 0, undef
	],
	[#Rule 6
		 'interfaces', 2,
sub
#line 34 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 7
		 'interface', 8,
sub
#line 38 "build/pidl/idl.yp"
{$_[3] => {
               "TYPE" => "INTERFACE", 
			   "PROPERTIES" => $_[1],
		       "NAME" => $_[3],
			   "BASE" => $_[4],
		       "DATA" => $_[6],
          }}
	],
	[#Rule 8
		 'base_interface', 0, undef
	],
	[#Rule 9
		 'base_interface', 2,
sub
#line 49 "build/pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 10
		 'definitions', 1,
sub
#line 53 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 11
		 'definitions', 2,
sub
#line 54 "build/pidl/idl.yp"
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
		 'const', 6,
sub
#line 62 "build/pidl/idl.yp"
{{
                     "TYPE"  => "CONST", 
		     "DTYPE"  => $_[2],
		     "NAME"  => $_[3],
		     "VALUE" => $_[5]
        }}
	],
	[#Rule 16
		 'function', 7,
sub
#line 72 "build/pidl/idl.yp"
{{
		"TYPE" => "FUNCTION",
		"NAME" => $_[3],
		"RETURN_TYPE" => $_[2],
		"PROPERTIES" => $_[1],
		"DATA" => $_[5]
	 }}
	],
	[#Rule 17
		 'typedef', 5,
sub
#line 82 "build/pidl/idl.yp"
{{
                     "TYPE" => "TYPEDEF", 
		     "NAME" => $_[3],
		     "DATA" => $_[2],
		     "ARRAY_LEN" => $_[4]
        }}
	],
	[#Rule 18
		 'type', 1, undef
	],
	[#Rule 19
		 'type', 1, undef
	],
	[#Rule 20
		 'type', 1, undef
	],
	[#Rule 21
		 'type', 1, undef
	],
	[#Rule 22
		 'type', 1,
sub
#line 91 "build/pidl/idl.yp"
{ "void" }
	],
	[#Rule 23
		 'enum', 4,
sub
#line 96 "build/pidl/idl.yp"
{{
                     "TYPE" => "ENUM", 
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 24
		 'enum_elements', 1,
sub
#line 103 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 25
		 'enum_elements', 3,
sub
#line 104 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 26
		 'enum_element', 1, undef
	],
	[#Rule 27
		 'enum_element', 3,
sub
#line 108 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 28
		 'struct', 5,
sub
#line 112 "build/pidl/idl.yp"
{{
                     "TYPE" => "STRUCT", 
		     "PROPERTIES" => $_[1],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 29
		 'union', 5,
sub
#line 120 "build/pidl/idl.yp"
{{
		"TYPE" => "UNION",
		"PROPERTIES" => $_[1],
		"DATA" => $_[4]
	 }}
	],
	[#Rule 30
		 'union_elements', 1,
sub
#line 128 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 31
		 'union_elements', 2,
sub
#line 129 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 32
		 'union_element', 8,
sub
#line 134 "build/pidl/idl.yp"
{{
		"TYPE" => "UNION_ELEMENT",
		"CASE" => $_[4],
		"DATA" => $_[7]
	 }}
	],
	[#Rule 33
		 'union_element', 7,
sub
#line 140 "build/pidl/idl.yp"
{{
		"TYPE" => "EMPTY",
		"CASE" => $_[4],
	 }}
	],
	[#Rule 34
		 'union_element', 5,
sub
#line 145 "build/pidl/idl.yp"
{{
		"TYPE" => "UNION_ELEMENT",
		"CASE" => "default",
		"DATA" => $_[4]
	 }}
	],
	[#Rule 35
		 'union_element', 4,
sub
#line 151 "build/pidl/idl.yp"
{{
		"TYPE" => "EMPTY",
		"CASE" => "default",
	 }}
	],
	[#Rule 36
		 'base_element', 5,
sub
#line 158 "build/pidl/idl.yp"
{{
			   "NAME" => $_[4],
			   "TYPE" => $_[2],
			   "PROPERTIES" => $_[1],
			   "POINTERS" => $_[3],
			   "ARRAY_LEN" => $_[5]
              }}
	],
	[#Rule 37
		 'pointers', 0,
sub
#line 170 "build/pidl/idl.yp"
{ 0 }
	],
	[#Rule 38
		 'pointers', 2,
sub
#line 171 "build/pidl/idl.yp"
{ $_[1]+1 }
	],
	[#Rule 39
		 'element_list1', 0, undef
	],
	[#Rule 40
		 'element_list1', 3,
sub
#line 178 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 41
		 'element_list2', 0, undef
	],
	[#Rule 42
		 'element_list2', 1, undef
	],
	[#Rule 43
		 'element_list2', 1,
sub
#line 184 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 44
		 'element_list2', 3,
sub
#line 185 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 45
		 'array_len', 0, undef
	],
	[#Rule 46
		 'array_len', 2,
sub
#line 190 "build/pidl/idl.yp"
{ "*" }
	],
	[#Rule 47
		 'array_len', 3,
sub
#line 191 "build/pidl/idl.yp"
{ "$_[2]" }
	],
	[#Rule 48
		 'property_list', 0, undef
	],
	[#Rule 49
		 'property_list', 4,
sub
#line 197 "build/pidl/idl.yp"
{ util::FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 50
		 'properties', 1,
sub
#line 200 "build/pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 51
		 'properties', 3,
sub
#line 201 "build/pidl/idl.yp"
{ util::FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 52
		 'property', 1,
sub
#line 204 "build/pidl/idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 53
		 'property', 4,
sub
#line 205 "build/pidl/idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 54
		 'listtext', 1, undef
	],
	[#Rule 55
		 'listtext', 3,
sub
#line 210 "build/pidl/idl.yp"
{ "$_[1] $_[3]" }
	],
	[#Rule 56
		 'commalisttext', 1, undef
	],
	[#Rule 57
		 'commalisttext', 3,
sub
#line 215 "build/pidl/idl.yp"
{ "$_[1],$_[3]" }
	],
	[#Rule 58
		 'anytext', 0,
sub
#line 219 "build/pidl/idl.yp"
{ "" }
	],
	[#Rule 59
		 'anytext', 1, undef
	],
	[#Rule 60
		 'anytext', 1, undef
	],
	[#Rule 61
		 'anytext', 1, undef
	],
	[#Rule 62
		 'anytext', 3,
sub
#line 221 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 63
		 'anytext', 3,
sub
#line 222 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 64
		 'anytext', 3,
sub
#line 223 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 65
		 'anytext', 3,
sub
#line 224 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 66
		 'anytext', 3,
sub
#line 225 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 67
		 'anytext', 3,
sub
#line 226 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 68
		 'anytext', 3,
sub
#line 227 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 69
		 'anytext', 3,
sub
#line 228 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 70
		 'anytext', 5,
sub
#line 229 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 71
		 'identifier', 1, undef
	],
	[#Rule 72
		 'constant', 1, undef
	],
	[#Rule 73
		 'text', 1,
sub
#line 238 "build/pidl/idl.yp"
{ "\"$_[1]\"" }
	],
	[#Rule 74
		 'optional_semicolon', 0, undef
	],
	[#Rule 75
		 'optional_semicolon', 1, undef
	]
],
                                  @_);
    bless($self,$class);
}

#line 249 "build/pidl/idl.yp"


use util;

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
			    /^(coclass|interface|const|typedef|union
			      |struct|enum|void|case|default)$/x) {
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
	my $data = `$cpp -xc $filename`;
	$/ = $saved_delim;

    $self->YYData->{INPUT} = $data;
    $self->YYData->{LINE} = 0;
    $self->YYData->{LAST_TOKEN} = "NONE";

	my $idl = $self->YYParse( yylex => \&_Lexer, yyerror => \&_Error );

	foreach my $x (@{$idl}) {
		# Add [in] ORPCTHIS *this, [out] ORPCTHAT *that
		# for 'object' interfaces
		if (defined($x->{PROPERTIES}->{object})) {
			foreach my $e (@{$x->{DATA}}) {
				if($e->{TYPE} eq "FUNCTION") {
					$e->{PROPERTIES}->{object} = 1;
					unshift(@{$e->{DATA}}, 
                        { 'NAME' => 'ORPCthis',
                          'POINTERS' => 0,
                          'PROPERTIES' => { 'in' => '1' },
                          'TYPE' => 'ORPCTHIS'
                        });
					unshift(@{$e->{DATA}},
                        { 'NAME' => 'ORPCthat',
                          'POINTERS' => 0,
                          'PROPERTIES' => { 'out' => '1' },
						  'TYPE' => 'ORPCTHAT'
                        });
				}
			}
		}
		
		# Do the inheritance
		if (defined($x->{BASE}) and $x->{BASE} ne "") {
			my $parent = util::get_interface($idl, $x->{BASE});

			if(not defined($parent)) { 
				die("No such parent interface " . $x->{BASE});
			}
			
			$x->{INHERITED_FUNCTIONS} = scalar @{$parent->{INHERITED_DATA}};
			@{$x->{INHERITED_DATA}} = (@{$parent->{INHERITED_DATA}}, @{$x->{DATA}});
		} else {
			$x->{INHERITED_FUNCTIONS} = 0;
			$x->{INHERITED_DATA} = $x->{DATA};
		}
	}

	return $idl;
}

1;
