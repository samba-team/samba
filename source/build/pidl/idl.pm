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
		DEFAULT => -44,
		GOTOS => {
			'interface' => 3,
			'property_list' => 4
		}
	},
	{#State 2
		DEFAULT => 0
	},
	{#State 3
		DEFAULT => -2
	},
	{#State 4
		ACTIONS => {
			"interface" => 6,
			"[" => 5
		}
	},
	{#State 5
		ACTIONS => {
			'IDENTIFIER' => 7
		},
		GOTOS => {
			'identifier' => 8,
			'properties' => 10,
			'property' => 9
		}
	},
	{#State 6
		ACTIONS => {
			'IDENTIFIER' => 7
		},
		GOTOS => {
			'identifier' => 11
		}
	},
	{#State 7
		DEFAULT => -65
	},
	{#State 8
		ACTIONS => {
			"(" => 12
		},
		DEFAULT => -48
	},
	{#State 9
		DEFAULT => -46
	},
	{#State 10
		ACTIONS => {
			"," => 13,
			"]" => 14
		}
	},
	{#State 11
		ACTIONS => {
			":" => 15
		},
		DEFAULT => -4,
		GOTOS => {
			'base_interface' => 16
		}
	},
	{#State 12
		ACTIONS => {
			'IDENTIFIER' => 7,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'listtext' => 21,
			'anytext' => 20,
			'text' => 19,
			'constant' => 22
		}
	},
	{#State 13
		ACTIONS => {
			'IDENTIFIER' => 7
		},
		GOTOS => {
			'identifier' => 8,
			'property' => 24
		}
	},
	{#State 14
		DEFAULT => -45
	},
	{#State 15
		ACTIONS => {
			'IDENTIFIER' => 7
		},
		GOTOS => {
			'identifier' => 25
		}
	},
	{#State 16
		ACTIONS => {
			"{" => 26
		}
	},
	{#State 17
		DEFAULT => -67
	},
	{#State 18
		DEFAULT => -53
	},
	{#State 19
		DEFAULT => -55
	},
	{#State 20
		ACTIONS => {
			"-" => 27,
			"+" => 28,
			"&" => 29,
			"/" => 30,
			"|" => 31,
			"(" => 32,
			"*" => 33,
			"." => 34,
			">" => 35
		},
		DEFAULT => -50
	},
	{#State 21
		ACTIONS => {
			"," => 36,
			")" => 37
		}
	},
	{#State 22
		DEFAULT => -54
	},
	{#State 23
		DEFAULT => -66
	},
	{#State 24
		DEFAULT => -47
	},
	{#State 25
		DEFAULT => -5
	},
	{#State 26
		ACTIONS => {
			"typedef" => 38,
			"const" => 44
		},
		DEFAULT => -44,
		GOTOS => {
			'const' => 43,
			'function' => 39,
			'typedef' => 45,
			'definitions' => 40,
			'definition' => 42,
			'property_list' => 41
		}
	},
	{#State 27
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 7
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 46,
			'constant' => 22
		}
	},
	{#State 28
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 7
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 47,
			'constant' => 22
		}
	},
	{#State 29
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 7
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 48,
			'constant' => 22
		}
	},
	{#State 30
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 7
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 49,
			'constant' => 22
		}
	},
	{#State 31
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 7
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 50,
			'constant' => 22
		}
	},
	{#State 32
		ACTIONS => {
			'IDENTIFIER' => 7,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 51,
			'constant' => 22
		}
	},
	{#State 33
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 7
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 52,
			'constant' => 22
		}
	},
	{#State 34
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 7
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 53,
			'constant' => 22
		}
	},
	{#State 35
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 7
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 54,
			'constant' => 22
		}
	},
	{#State 36
		ACTIONS => {
			'IDENTIFIER' => 7,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 55,
			'constant' => 22
		}
	},
	{#State 37
		DEFAULT => -49
	},
	{#State 38
		ACTIONS => {
			'IDENTIFIER' => 7,
			"enum" => 56,
			'void' => 57
		},
		DEFAULT => -44,
		GOTOS => {
			'identifier' => 59,
			'struct' => 60,
			'enum' => 61,
			'type' => 62,
			'union' => 63,
			'property_list' => 58
		}
	},
	{#State 39
		DEFAULT => -8
	},
	{#State 40
		ACTIONS => {
			"}" => 64,
			"typedef" => 38,
			"const" => 44
		},
		DEFAULT => -44,
		GOTOS => {
			'const' => 43,
			'function' => 39,
			'typedef' => 45,
			'definition' => 65,
			'property_list' => 41
		}
	},
	{#State 41
		ACTIONS => {
			'IDENTIFIER' => 7,
			"enum" => 56,
			"[" => 5,
			'void' => 57
		},
		DEFAULT => -44,
		GOTOS => {
			'identifier' => 59,
			'struct' => 60,
			'enum' => 61,
			'type' => 66,
			'union' => 63,
			'property_list' => 58
		}
	},
	{#State 42
		DEFAULT => -6
	},
	{#State 43
		DEFAULT => -9
	},
	{#State 44
		ACTIONS => {
			'IDENTIFIER' => 7
		},
		GOTOS => {
			'identifier' => 67
		}
	},
	{#State 45
		DEFAULT => -10
	},
	{#State 46
		DEFAULT => -56
	},
	{#State 47
		DEFAULT => -63
	},
	{#State 48
		DEFAULT => -61
	},
	{#State 49
		DEFAULT => -62
	},
	{#State 50
		DEFAULT => -60
	},
	{#State 51
		ACTIONS => {
			"-" => 27,
			"+" => 28,
			"&" => 29,
			"/" => 30,
			"(" => 32,
			"|" => 31,
			"*" => 33,
			"." => 34,
			")" => 68,
			">" => 35
		}
	},
	{#State 52
		DEFAULT => -58
	},
	{#State 53
		DEFAULT => -57
	},
	{#State 54
		DEFAULT => -59
	},
	{#State 55
		ACTIONS => {
			"-" => 27,
			"+" => 28,
			"&" => 29,
			"/" => 30,
			"(" => 32,
			"|" => 31,
			"*" => 33,
			"." => 34,
			">" => 35
		},
		DEFAULT => -51
	},
	{#State 56
		ACTIONS => {
			"{" => 69
		}
	},
	{#State 57
		DEFAULT => -18
	},
	{#State 58
		ACTIONS => {
			"union" => 70,
			"[" => 5,
			"struct" => 71
		}
	},
	{#State 59
		DEFAULT => -17
	},
	{#State 60
		DEFAULT => -14
	},
	{#State 61
		DEFAULT => -16
	},
	{#State 62
		ACTIONS => {
			'IDENTIFIER' => 7
		},
		GOTOS => {
			'identifier' => 72
		}
	},
	{#State 63
		DEFAULT => -15
	},
	{#State 64
		DEFAULT => -3
	},
	{#State 65
		DEFAULT => -7
	},
	{#State 66
		ACTIONS => {
			'IDENTIFIER' => 7
		},
		GOTOS => {
			'identifier' => 73
		}
	},
	{#State 67
		ACTIONS => {
			'IDENTIFIER' => 7
		},
		GOTOS => {
			'identifier' => 74
		}
	},
	{#State 68
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 7
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 75,
			'constant' => 22
		}
	},
	{#State 69
		ACTIONS => {
			'IDENTIFIER' => 7
		},
		GOTOS => {
			'identifier' => 76,
			'enum_element' => 77,
			'enum_elements' => 78
		}
	},
	{#State 70
		ACTIONS => {
			"{" => 79
		}
	},
	{#State 71
		ACTIONS => {
			"{" => 80
		}
	},
	{#State 72
		ACTIONS => {
			"[" => 82
		},
		DEFAULT => -41,
		GOTOS => {
			'array_len' => 81
		}
	},
	{#State 73
		ACTIONS => {
			"(" => 83
		}
	},
	{#State 74
		ACTIONS => {
			"=" => 84
		}
	},
	{#State 75
		DEFAULT => -64
	},
	{#State 76
		ACTIONS => {
			"=" => 85
		},
		DEFAULT => -22
	},
	{#State 77
		DEFAULT => -20
	},
	{#State 78
		ACTIONS => {
			"}" => 86,
			"," => 87
		}
	},
	{#State 79
		ACTIONS => {
			"[" => 90
		},
		GOTOS => {
			'union_elements' => 88,
			'union_element' => 89
		}
	},
	{#State 80
		DEFAULT => -35,
		GOTOS => {
			'element_list1' => 91
		}
	},
	{#State 81
		ACTIONS => {
			";" => 92
		}
	},
	{#State 82
		ACTIONS => {
			'IDENTIFIER' => 7,
			'CONSTANT' => 23,
			'TEXT' => 17,
			"]" => 94
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 93,
			'constant' => 22
		}
	},
	{#State 83
		ACTIONS => {
			"void" => 97,
			"," => -37,
			")" => -37
		},
		DEFAULT => -44,
		GOTOS => {
			'base_element' => 95,
			'element_list2' => 98,
			'property_list' => 96
		}
	},
	{#State 84
		ACTIONS => {
			'IDENTIFIER' => 7,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 99,
			'constant' => 22
		}
	},
	{#State 85
		ACTIONS => {
			'IDENTIFIER' => 7,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 100,
			'constant' => 22
		}
	},
	{#State 86
		DEFAULT => -19
	},
	{#State 87
		ACTIONS => {
			'IDENTIFIER' => 7
		},
		GOTOS => {
			'identifier' => 76,
			'enum_element' => 101
		}
	},
	{#State 88
		ACTIONS => {
			"}" => 102,
			"[" => 90
		},
		GOTOS => {
			'union_element' => 103
		}
	},
	{#State 89
		DEFAULT => -26
	},
	{#State 90
		ACTIONS => {
			"case" => 104,
			"default" => 105
		}
	},
	{#State 91
		ACTIONS => {
			"}" => 106
		},
		DEFAULT => -44,
		GOTOS => {
			'base_element' => 107,
			'property_list' => 96
		}
	},
	{#State 92
		DEFAULT => -13
	},
	{#State 93
		ACTIONS => {
			"-" => 27,
			"+" => 28,
			"&" => 29,
			"/" => 30,
			"(" => 32,
			"|" => 31,
			"*" => 33,
			"." => 34,
			"]" => 108,
			">" => 35
		}
	},
	{#State 94
		DEFAULT => -42
	},
	{#State 95
		DEFAULT => -39
	},
	{#State 96
		ACTIONS => {
			'IDENTIFIER' => 7,
			"enum" => 56,
			"[" => 5,
			'void' => 57
		},
		DEFAULT => -44,
		GOTOS => {
			'identifier' => 59,
			'struct' => 60,
			'enum' => 61,
			'type' => 109,
			'union' => 63,
			'property_list' => 58
		}
	},
	{#State 97
		DEFAULT => -38
	},
	{#State 98
		ACTIONS => {
			"," => 110,
			")" => 111
		}
	},
	{#State 99
		ACTIONS => {
			"-" => 27,
			"|" => 31,
			"(" => 32,
			"*" => 33,
			";" => 112,
			"+" => 28,
			"&" => 29,
			"/" => 30,
			"." => 34,
			">" => 35
		}
	},
	{#State 100
		ACTIONS => {
			"-" => 27,
			"+" => 28,
			"&" => 29,
			"/" => 30,
			"(" => 32,
			"|" => 31,
			"*" => 33,
			"." => 34,
			">" => 35
		},
		DEFAULT => -23
	},
	{#State 101
		DEFAULT => -21
	},
	{#State 102
		DEFAULT => -25
	},
	{#State 103
		DEFAULT => -27
	},
	{#State 104
		ACTIONS => {
			"(" => 113
		}
	},
	{#State 105
		ACTIONS => {
			"]" => 114
		}
	},
	{#State 106
		DEFAULT => -24
	},
	{#State 107
		ACTIONS => {
			";" => 115
		}
	},
	{#State 108
		DEFAULT => -43
	},
	{#State 109
		DEFAULT => -33,
		GOTOS => {
			'pointers' => 116
		}
	},
	{#State 110
		DEFAULT => -44,
		GOTOS => {
			'base_element' => 117,
			'property_list' => 96
		}
	},
	{#State 111
		ACTIONS => {
			";" => 118
		}
	},
	{#State 112
		DEFAULT => -11
	},
	{#State 113
		ACTIONS => {
			'IDENTIFIER' => 7,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -52,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 119,
			'constant' => 22
		}
	},
	{#State 114
		ACTIONS => {
			";" => 120
		},
		DEFAULT => -44,
		GOTOS => {
			'base_element' => 121,
			'property_list' => 96
		}
	},
	{#State 115
		DEFAULT => -36
	},
	{#State 116
		ACTIONS => {
			'IDENTIFIER' => 7,
			"*" => 123
		},
		GOTOS => {
			'identifier' => 122
		}
	},
	{#State 117
		DEFAULT => -40
	},
	{#State 118
		DEFAULT => -12
	},
	{#State 119
		ACTIONS => {
			"-" => 27,
			"+" => 28,
			"&" => 29,
			"/" => 30,
			"(" => 32,
			"|" => 31,
			"*" => 33,
			"." => 34,
			")" => 124,
			">" => 35
		}
	},
	{#State 120
		DEFAULT => -31
	},
	{#State 121
		ACTIONS => {
			";" => 125
		}
	},
	{#State 122
		ACTIONS => {
			"[" => 82
		},
		DEFAULT => -41,
		GOTOS => {
			'array_len' => 126
		}
	},
	{#State 123
		DEFAULT => -34
	},
	{#State 124
		ACTIONS => {
			"]" => 127
		}
	},
	{#State 125
		DEFAULT => -30
	},
	{#State 126
		DEFAULT => -32
	},
	{#State 127
		ACTIONS => {
			";" => 128
		},
		DEFAULT => -44,
		GOTOS => {
			'base_element' => 129,
			'property_list' => 96
		}
	},
	{#State 128
		DEFAULT => -29
	},
	{#State 129
		ACTIONS => {
			";" => 130
		}
	},
	{#State 130
		DEFAULT => -28
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
{
		push(@{$_[1]}, $_[2]); $_[1] 
	}
	],
	[#Rule 3
		 'interface', 7,
sub
#line 25 "build/pidl/idl.yp"
{$_[3] => {
               "TYPE" => "INTERFACE", 
			   "PROPERTIES" => $_[1],
		       "NAME" => $_[3],
			   "BASE" => $_[4],
		       "DATA" => $_[6],
          }}
	],
	[#Rule 4
		 'base_interface', 0, undef
	],
	[#Rule 5
		 'base_interface', 2,
sub
#line 36 "build/pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 6
		 'definitions', 1,
sub
#line 40 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 7
		 'definitions', 2,
sub
#line 41 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 8
		 'definition', 1, undef
	],
	[#Rule 9
		 'definition', 1, undef
	],
	[#Rule 10
		 'definition', 1, undef
	],
	[#Rule 11
		 'const', 6,
sub
#line 49 "build/pidl/idl.yp"
{{
                     "TYPE"  => "CONST", 
		     "DTYPE"  => $_[2],
		     "NAME"  => $_[3],
		     "VALUE" => $_[5]
        }}
	],
	[#Rule 12
		 'function', 7,
sub
#line 59 "build/pidl/idl.yp"
{{
		"TYPE" => "FUNCTION",
		"NAME" => $_[3],
		"RETURN_TYPE" => $_[2],
		"PROPERTIES" => $_[1],
		"DATA" => $_[5]
	 }}
	],
	[#Rule 13
		 'typedef', 5,
sub
#line 69 "build/pidl/idl.yp"
{{
                     "TYPE" => "TYPEDEF", 
		     "NAME" => $_[3],
		     "DATA" => $_[2],
		     "ARRAY_LEN" => $_[4]
        }}
	],
	[#Rule 14
		 'type', 1, undef
	],
	[#Rule 15
		 'type', 1, undef
	],
	[#Rule 16
		 'type', 1, undef
	],
	[#Rule 17
		 'type', 1, undef
	],
	[#Rule 18
		 'type', 1,
sub
#line 78 "build/pidl/idl.yp"
{ "void" }
	],
	[#Rule 19
		 'enum', 4,
sub
#line 83 "build/pidl/idl.yp"
{{
                     "TYPE" => "ENUM", 
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 20
		 'enum_elements', 1,
sub
#line 90 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 21
		 'enum_elements', 3,
sub
#line 91 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 22
		 'enum_element', 1, undef
	],
	[#Rule 23
		 'enum_element', 3,
sub
#line 95 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 24
		 'struct', 5,
sub
#line 99 "build/pidl/idl.yp"
{{
                     "TYPE" => "STRUCT", 
		     "PROPERTIES" => $_[1],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 25
		 'union', 5,
sub
#line 107 "build/pidl/idl.yp"
{{
		"TYPE" => "UNION",
		"PROPERTIES" => $_[1],
		"DATA" => $_[4]
	 }}
	],
	[#Rule 26
		 'union_elements', 1,
sub
#line 115 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 27
		 'union_elements', 2,
sub
#line 116 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 28
		 'union_element', 8,
sub
#line 121 "build/pidl/idl.yp"
{{
		"TYPE" => "UNION_ELEMENT",
		"CASE" => $_[4],
		"DATA" => $_[7]
	 }}
	],
	[#Rule 29
		 'union_element', 7,
sub
#line 127 "build/pidl/idl.yp"
{{
		"TYPE" => "EMPTY",
		"CASE" => $_[4],
	 }}
	],
	[#Rule 30
		 'union_element', 5,
sub
#line 132 "build/pidl/idl.yp"
{{
		"TYPE" => "UNION_ELEMENT",
		"CASE" => "default",
		"DATA" => $_[4]
	 }}
	],
	[#Rule 31
		 'union_element', 4,
sub
#line 138 "build/pidl/idl.yp"
{{
		"TYPE" => "EMPTY",
		"CASE" => "default",
	 }}
	],
	[#Rule 32
		 'base_element', 5,
sub
#line 145 "build/pidl/idl.yp"
{{
			   "NAME" => $_[4],
			   "TYPE" => $_[2],
			   "PROPERTIES" => $_[1],
			   "POINTERS" => $_[3],
			   "ARRAY_LEN" => $_[5]
              }}
	],
	[#Rule 33
		 'pointers', 0,
sub
#line 157 "build/pidl/idl.yp"
{ 0 }
	],
	[#Rule 34
		 'pointers', 2,
sub
#line 158 "build/pidl/idl.yp"
{ $_[1]+1 }
	],
	[#Rule 35
		 'element_list1', 0, undef
	],
	[#Rule 36
		 'element_list1', 3,
sub
#line 165 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 37
		 'element_list2', 0, undef
	],
	[#Rule 38
		 'element_list2', 1, undef
	],
	[#Rule 39
		 'element_list2', 1,
sub
#line 171 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 40
		 'element_list2', 3,
sub
#line 172 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 41
		 'array_len', 0, undef
	],
	[#Rule 42
		 'array_len', 2,
sub
#line 177 "build/pidl/idl.yp"
{ "*" }
	],
	[#Rule 43
		 'array_len', 3,
sub
#line 178 "build/pidl/idl.yp"
{ "$_[2]" }
	],
	[#Rule 44
		 'property_list', 0, undef
	],
	[#Rule 45
		 'property_list', 4,
sub
#line 184 "build/pidl/idl.yp"
{ util::FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 46
		 'properties', 1,
sub
#line 187 "build/pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 47
		 'properties', 3,
sub
#line 188 "build/pidl/idl.yp"
{ util::FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 48
		 'property', 1,
sub
#line 191 "build/pidl/idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 49
		 'property', 4,
sub
#line 192 "build/pidl/idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 50
		 'listtext', 1, undef
	],
	[#Rule 51
		 'listtext', 3,
sub
#line 197 "build/pidl/idl.yp"
{ "$_[1] $_[3]" }
	],
	[#Rule 52
		 'anytext', 0,
sub
#line 201 "build/pidl/idl.yp"
{ "" }
	],
	[#Rule 53
		 'anytext', 1, undef
	],
	[#Rule 54
		 'anytext', 1, undef
	],
	[#Rule 55
		 'anytext', 1, undef
	],
	[#Rule 56
		 'anytext', 3,
sub
#line 203 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 57
		 'anytext', 3,
sub
#line 204 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 58
		 'anytext', 3,
sub
#line 205 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 59
		 'anytext', 3,
sub
#line 206 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 60
		 'anytext', 3,
sub
#line 207 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 61
		 'anytext', 3,
sub
#line 208 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 62
		 'anytext', 3,
sub
#line 209 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 63
		 'anytext', 3,
sub
#line 210 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 64
		 'anytext', 5,
sub
#line 211 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 65
		 'identifier', 1, undef
	],
	[#Rule 66
		 'constant', 1, undef
	],
	[#Rule 67
		 'text', 1,
sub
#line 220 "build/pidl/idl.yp"
{ "\"$_[1]\"" }
	]
],
                                  @_);
    bless($self,$class);
}

#line 226 "build/pidl/idl.yp"


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
			    /^(interface|const|typedef|union
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
					unshift(@{$e->{DATA}}, 
                        { 'NAME' => 'ORPCthis',
                          'POINTERS' => 1,
                          'PROPERTIES' => { 'in' => '1' },
                          'TYPE' => 'ORPCTHIS'
                        });
					unshift(@{$e->{DATA}},
                        { 'NAME' => 'ORPCthat',
                          'POINTERS' => 1,
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
			
			@{$x->{INHERITED_DATA}} = (@{$parent->{INHERITED_DATA}}, @{$x->{DATA}});
		} else {
			$x->{INHERITED_DATA} = $x->{DATA};
		}
	}

	return $idl;
}

1;
