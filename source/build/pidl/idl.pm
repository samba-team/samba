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
		ACTIONS => {
			"[" => 2
		},
		GOTOS => {
			'idl_interface' => 1,
			'idl' => 3,
			'module_header' => 4
		}
	},
	{#State 1
		DEFAULT => -1
	},
	{#State 2
		ACTIONS => {
			'IDENTIFIER' => 5
		},
		DEFAULT => -5,
		GOTOS => {
			'module_params' => 7,
			'identifier' => 6,
			'module_param' => 8
		}
	},
	{#State 3
		ACTIONS => {
			'' => 9,
			"[" => 2
		},
		GOTOS => {
			'idl_interface' => 10,
			'module_header' => 4
		}
	},
	{#State 4
		ACTIONS => {
			"interface" => 12
		},
		GOTOS => {
			'interface' => 11
		}
	},
	{#State 5
		DEFAULT => -69
	},
	{#State 6
		ACTIONS => {
			"(" => 13
		}
	},
	{#State 7
		ACTIONS => {
			"," => 14,
			"]" => 15
		}
	},
	{#State 8
		DEFAULT => -6
	},
	{#State 9
		DEFAULT => 0
	},
	{#State 10
		DEFAULT => -2
	},
	{#State 11
		DEFAULT => -3
	},
	{#State 12
		ACTIONS => {
			'IDENTIFIER' => 5
		},
		GOTOS => {
			'identifier' => 16
		}
	},
	{#State 13
		ACTIONS => {
			'IDENTIFIER' => 5,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 18,
			'listtext' => 21,
			'anytext' => 20,
			'text' => 19,
			'constant' => 22
		}
	},
	{#State 14
		ACTIONS => {
			'IDENTIFIER' => 5
		},
		GOTOS => {
			'identifier' => 6,
			'module_param' => 24
		}
	},
	{#State 15
		DEFAULT => -4
	},
	{#State 16
		ACTIONS => {
			"{" => 25
		}
	},
	{#State 17
		DEFAULT => -71
	},
	{#State 18
		DEFAULT => -57
	},
	{#State 19
		DEFAULT => -59
	},
	{#State 20
		ACTIONS => {
			"-" => 26,
			"+" => 27,
			"&" => 28,
			"/" => 29,
			"|" => 30,
			"(" => 31,
			"*" => 32,
			"." => 33,
			">" => 34
		},
		DEFAULT => -54
	},
	{#State 21
		ACTIONS => {
			"," => 35,
			")" => 36
		}
	},
	{#State 22
		DEFAULT => -58
	},
	{#State 23
		DEFAULT => -70
	},
	{#State 24
		DEFAULT => -7
	},
	{#State 25
		ACTIONS => {
			"typedef" => 37,
			"const" => 43
		},
		DEFAULT => -48,
		GOTOS => {
			'const' => 42,
			'function' => 38,
			'typedef' => 44,
			'definitions' => 39,
			'definition' => 41,
			'property_list' => 40
		}
	},
	{#State 26
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 5
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 45,
			'constant' => 22
		}
	},
	{#State 27
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 5
		},
		DEFAULT => -56,
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
			'IDENTIFIER' => 5
		},
		DEFAULT => -56,
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
			'IDENTIFIER' => 5
		},
		DEFAULT => -56,
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
			'IDENTIFIER' => 5
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 49,
			'constant' => 22
		}
	},
	{#State 31
		ACTIONS => {
			'IDENTIFIER' => 5,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 50,
			'constant' => 22
		}
	},
	{#State 32
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 5
		},
		DEFAULT => -56,
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
			'IDENTIFIER' => 5
		},
		DEFAULT => -56,
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
			'IDENTIFIER' => 5
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 53,
			'constant' => 22
		}
	},
	{#State 35
		ACTIONS => {
			'IDENTIFIER' => 5,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 54,
			'constant' => 22
		}
	},
	{#State 36
		DEFAULT => -8
	},
	{#State 37
		ACTIONS => {
			'IDENTIFIER' => 5,
			"enum" => 55,
			'void' => 56
		},
		DEFAULT => -48,
		GOTOS => {
			'identifier' => 58,
			'struct' => 59,
			'enum' => 60,
			'type' => 61,
			'union' => 62,
			'property_list' => 57
		}
	},
	{#State 38
		DEFAULT => -12
	},
	{#State 39
		ACTIONS => {
			"}" => 63,
			"typedef" => 37,
			"const" => 43
		},
		DEFAULT => -48,
		GOTOS => {
			'const' => 42,
			'function' => 38,
			'typedef' => 44,
			'definition' => 64,
			'property_list' => 40
		}
	},
	{#State 40
		ACTIONS => {
			'IDENTIFIER' => 5,
			"enum" => 55,
			"[" => 65,
			'void' => 56
		},
		DEFAULT => -48,
		GOTOS => {
			'identifier' => 58,
			'struct' => 59,
			'enum' => 60,
			'type' => 66,
			'union' => 62,
			'property_list' => 57
		}
	},
	{#State 41
		DEFAULT => -10
	},
	{#State 42
		DEFAULT => -13
	},
	{#State 43
		ACTIONS => {
			'IDENTIFIER' => 5
		},
		GOTOS => {
			'identifier' => 67
		}
	},
	{#State 44
		DEFAULT => -14
	},
	{#State 45
		DEFAULT => -60
	},
	{#State 46
		DEFAULT => -67
	},
	{#State 47
		DEFAULT => -65
	},
	{#State 48
		DEFAULT => -66
	},
	{#State 49
		DEFAULT => -64
	},
	{#State 50
		ACTIONS => {
			"-" => 26,
			"+" => 27,
			"&" => 28,
			"/" => 29,
			"(" => 31,
			"|" => 30,
			"*" => 32,
			"." => 33,
			")" => 68,
			">" => 34
		}
	},
	{#State 51
		DEFAULT => -62
	},
	{#State 52
		DEFAULT => -61
	},
	{#State 53
		DEFAULT => -63
	},
	{#State 54
		ACTIONS => {
			"-" => 26,
			"+" => 27,
			"&" => 28,
			"/" => 29,
			"(" => 31,
			"|" => 30,
			"*" => 32,
			"." => 33,
			">" => 34
		},
		DEFAULT => -55
	},
	{#State 55
		ACTIONS => {
			"{" => 69
		}
	},
	{#State 56
		DEFAULT => -22
	},
	{#State 57
		ACTIONS => {
			"union" => 70,
			"[" => 65,
			"struct" => 71
		}
	},
	{#State 58
		DEFAULT => -21
	},
	{#State 59
		DEFAULT => -18
	},
	{#State 60
		DEFAULT => -20
	},
	{#State 61
		ACTIONS => {
			'IDENTIFIER' => 5
		},
		GOTOS => {
			'identifier' => 72
		}
	},
	{#State 62
		DEFAULT => -19
	},
	{#State 63
		DEFAULT => -9
	},
	{#State 64
		DEFAULT => -11
	},
	{#State 65
		ACTIONS => {
			'IDENTIFIER' => 5
		},
		GOTOS => {
			'identifier' => 74,
			'property' => 75,
			'properties' => 73
		}
	},
	{#State 66
		ACTIONS => {
			'IDENTIFIER' => 5
		},
		GOTOS => {
			'identifier' => 76
		}
	},
	{#State 67
		ACTIONS => {
			'IDENTIFIER' => 5
		},
		GOTOS => {
			'identifier' => 77
		}
	},
	{#State 68
		ACTIONS => {
			'CONSTANT' => 23,
			'TEXT' => 17,
			'IDENTIFIER' => 5
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 78,
			'constant' => 22
		}
	},
	{#State 69
		ACTIONS => {
			'IDENTIFIER' => 5
		},
		GOTOS => {
			'identifier' => 79,
			'enum_element' => 80,
			'enum_elements' => 81
		}
	},
	{#State 70
		ACTIONS => {
			"{" => 82
		}
	},
	{#State 71
		ACTIONS => {
			"{" => 83
		}
	},
	{#State 72
		ACTIONS => {
			"[" => 85
		},
		DEFAULT => -45,
		GOTOS => {
			'array_len' => 84
		}
	},
	{#State 73
		ACTIONS => {
			"," => 86,
			"]" => 87
		}
	},
	{#State 74
		ACTIONS => {
			"(" => 88
		},
		DEFAULT => -52
	},
	{#State 75
		DEFAULT => -50
	},
	{#State 76
		ACTIONS => {
			"(" => 89
		}
	},
	{#State 77
		ACTIONS => {
			"=" => 90
		}
	},
	{#State 78
		DEFAULT => -68
	},
	{#State 79
		ACTIONS => {
			"=" => 91
		},
		DEFAULT => -26
	},
	{#State 80
		DEFAULT => -24
	},
	{#State 81
		ACTIONS => {
			"}" => 92,
			"," => 93
		}
	},
	{#State 82
		ACTIONS => {
			"[" => 96
		},
		GOTOS => {
			'union_elements' => 94,
			'union_element' => 95
		}
	},
	{#State 83
		DEFAULT => -39,
		GOTOS => {
			'element_list1' => 97
		}
	},
	{#State 84
		ACTIONS => {
			";" => 98
		}
	},
	{#State 85
		ACTIONS => {
			'IDENTIFIER' => 5,
			'CONSTANT' => 23,
			'TEXT' => 17,
			"]" => 100
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 99,
			'constant' => 22
		}
	},
	{#State 86
		ACTIONS => {
			'IDENTIFIER' => 5
		},
		GOTOS => {
			'identifier' => 74,
			'property' => 101
		}
	},
	{#State 87
		DEFAULT => -49
	},
	{#State 88
		ACTIONS => {
			'IDENTIFIER' => 5,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 102,
			'constant' => 22
		}
	},
	{#State 89
		ACTIONS => {
			"void" => 105,
			"," => -41,
			")" => -41
		},
		DEFAULT => -48,
		GOTOS => {
			'base_element' => 103,
			'element_list2' => 106,
			'property_list' => 104
		}
	},
	{#State 90
		ACTIONS => {
			'IDENTIFIER' => 5,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 107,
			'constant' => 22
		}
	},
	{#State 91
		ACTIONS => {
			'IDENTIFIER' => 5,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 108,
			'constant' => 22
		}
	},
	{#State 92
		DEFAULT => -23
	},
	{#State 93
		ACTIONS => {
			'IDENTIFIER' => 5
		},
		GOTOS => {
			'identifier' => 79,
			'enum_element' => 109
		}
	},
	{#State 94
		ACTIONS => {
			"}" => 110,
			"[" => 96
		},
		GOTOS => {
			'union_element' => 111
		}
	},
	{#State 95
		DEFAULT => -30
	},
	{#State 96
		ACTIONS => {
			"case" => 112,
			"default" => 113
		}
	},
	{#State 97
		ACTIONS => {
			"}" => 114
		},
		DEFAULT => -48,
		GOTOS => {
			'base_element' => 115,
			'property_list' => 104
		}
	},
	{#State 98
		DEFAULT => -17
	},
	{#State 99
		ACTIONS => {
			"-" => 26,
			"+" => 27,
			"&" => 28,
			"/" => 29,
			"(" => 31,
			"|" => 30,
			"*" => 32,
			"." => 33,
			"]" => 116,
			">" => 34
		}
	},
	{#State 100
		DEFAULT => -46
	},
	{#State 101
		DEFAULT => -51
	},
	{#State 102
		ACTIONS => {
			"-" => 26,
			"+" => 27,
			"&" => 28,
			"/" => 29,
			"(" => 31,
			"|" => 30,
			"*" => 32,
			"." => 33,
			")" => 117,
			">" => 34
		}
	},
	{#State 103
		DEFAULT => -43
	},
	{#State 104
		ACTIONS => {
			'IDENTIFIER' => 5,
			"enum" => 55,
			"[" => 65,
			'void' => 56
		},
		DEFAULT => -48,
		GOTOS => {
			'identifier' => 58,
			'struct' => 59,
			'enum' => 60,
			'type' => 118,
			'union' => 62,
			'property_list' => 57
		}
	},
	{#State 105
		DEFAULT => -42
	},
	{#State 106
		ACTIONS => {
			"," => 119,
			")" => 120
		}
	},
	{#State 107
		ACTIONS => {
			"-" => 26,
			"|" => 30,
			"(" => 31,
			"*" => 32,
			";" => 121,
			"+" => 27,
			"&" => 28,
			"/" => 29,
			"." => 33,
			">" => 34
		}
	},
	{#State 108
		ACTIONS => {
			"-" => 26,
			"+" => 27,
			"&" => 28,
			"/" => 29,
			"(" => 31,
			"|" => 30,
			"*" => 32,
			"." => 33,
			">" => 34
		},
		DEFAULT => -27
	},
	{#State 109
		DEFAULT => -25
	},
	{#State 110
		DEFAULT => -29
	},
	{#State 111
		DEFAULT => -31
	},
	{#State 112
		ACTIONS => {
			"(" => 122
		}
	},
	{#State 113
		ACTIONS => {
			"]" => 123
		}
	},
	{#State 114
		DEFAULT => -28
	},
	{#State 115
		ACTIONS => {
			";" => 124
		}
	},
	{#State 116
		DEFAULT => -47
	},
	{#State 117
		DEFAULT => -53
	},
	{#State 118
		DEFAULT => -37,
		GOTOS => {
			'pointers' => 125
		}
	},
	{#State 119
		DEFAULT => -48,
		GOTOS => {
			'base_element' => 126,
			'property_list' => 104
		}
	},
	{#State 120
		ACTIONS => {
			";" => 127
		}
	},
	{#State 121
		DEFAULT => -15
	},
	{#State 122
		ACTIONS => {
			'IDENTIFIER' => 5,
			'CONSTANT' => 23,
			'TEXT' => 17
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 18,
			'text' => 19,
			'anytext' => 128,
			'constant' => 22
		}
	},
	{#State 123
		ACTIONS => {
			";" => 129
		},
		DEFAULT => -48,
		GOTOS => {
			'base_element' => 130,
			'property_list' => 104
		}
	},
	{#State 124
		DEFAULT => -40
	},
	{#State 125
		ACTIONS => {
			'IDENTIFIER' => 5,
			"*" => 132
		},
		GOTOS => {
			'identifier' => 131
		}
	},
	{#State 126
		DEFAULT => -44
	},
	{#State 127
		DEFAULT => -16
	},
	{#State 128
		ACTIONS => {
			"-" => 26,
			"+" => 27,
			"&" => 28,
			"/" => 29,
			"(" => 31,
			"|" => 30,
			"*" => 32,
			"." => 33,
			")" => 133,
			">" => 34
		}
	},
	{#State 129
		DEFAULT => -35
	},
	{#State 130
		ACTIONS => {
			";" => 134
		}
	},
	{#State 131
		ACTIONS => {
			"[" => 85
		},
		DEFAULT => -45,
		GOTOS => {
			'array_len' => 135
		}
	},
	{#State 132
		DEFAULT => -38
	},
	{#State 133
		ACTIONS => {
			"]" => 136
		}
	},
	{#State 134
		DEFAULT => -34
	},
	{#State 135
		DEFAULT => -36
	},
	{#State 136
		ACTIONS => {
			";" => 137
		},
		DEFAULT => -48,
		GOTOS => {
			'base_element' => 138,
			'property_list' => 104
		}
	},
	{#State 137
		DEFAULT => -33
	},
	{#State 138
		ACTIONS => {
			";" => 139
		}
	},
	{#State 139
		DEFAULT => -32
	}
],
                                  yyrules  =>
[
	[#Rule 0
		 '$start', 2, undef
	],
	[#Rule 1
		 'idl', 1, undef
	],
	[#Rule 2
		 'idl', 2,
sub
#line 18 "build/pidl/idl.yp"
{ util::FlattenArray([$_[1],$_[2]]) }
	],
	[#Rule 3
		 'idl_interface', 2,
sub
#line 21 "build/pidl/idl.yp"
{ [ $_[1], $_[2] ] }
	],
	[#Rule 4
		 'module_header', 3,
sub
#line 25 "build/pidl/idl.yp"
{{ 
              "TYPE" => "MODULEHEADER", 
              "PROPERTIES" => util::FlattenHash($_[2])
          }}
	],
	[#Rule 5
		 'module_params', 0, undef
	],
	[#Rule 6
		 'module_params', 1,
sub
#line 33 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 7
		 'module_params', 3,
sub
#line 34 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 8
		 'module_param', 4,
sub
#line 38 "build/pidl/idl.yp"
{ { "$_[1]" => "$_[3]" } }
	],
	[#Rule 9
		 'interface', 5,
sub
#line 42 "build/pidl/idl.yp"
{{
                       "TYPE" => "INTERFACE", 
		       "NAME" => $_[2],
		       "DATA" => $_[4]
          }}
	],
	[#Rule 10
		 'definitions', 1,
sub
#line 50 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 11
		 'definitions', 2,
sub
#line 51 "build/pidl/idl.yp"
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
#line 59 "build/pidl/idl.yp"
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
#line 69 "build/pidl/idl.yp"
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
#line 79 "build/pidl/idl.yp"
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
#line 88 "build/pidl/idl.yp"
{ "void" }
	],
	[#Rule 23
		 'enum', 4,
sub
#line 93 "build/pidl/idl.yp"
{{
                     "TYPE" => "ENUM", 
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 24
		 'enum_elements', 1,
sub
#line 100 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 25
		 'enum_elements', 3,
sub
#line 101 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 26
		 'enum_element', 1, undef
	],
	[#Rule 27
		 'enum_element', 3,
sub
#line 105 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 28
		 'struct', 5,
sub
#line 109 "build/pidl/idl.yp"
{{
                     "TYPE" => "STRUCT", 
		     "PROPERTIES" => $_[1],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 29
		 'union', 5,
sub
#line 117 "build/pidl/idl.yp"
{{
		"TYPE" => "UNION",
		"PROPERTIES" => $_[1],
		"DATA" => $_[4]
	 }}
	],
	[#Rule 30
		 'union_elements', 1,
sub
#line 125 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 31
		 'union_elements', 2,
sub
#line 126 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 32
		 'union_element', 8,
sub
#line 131 "build/pidl/idl.yp"
{{
		"TYPE" => "UNION_ELEMENT",
		"CASE" => $_[4],
		"DATA" => $_[7]
	 }}
	],
	[#Rule 33
		 'union_element', 7,
sub
#line 137 "build/pidl/idl.yp"
{{
		"TYPE" => "EMPTY",
		"CASE" => $_[4],
	 }}
	],
	[#Rule 34
		 'union_element', 5,
sub
#line 142 "build/pidl/idl.yp"
{{
		"TYPE" => "UNION_ELEMENT",
		"CASE" => "default",
		"DATA" => $_[4]
	 }}
	],
	[#Rule 35
		 'union_element', 4,
sub
#line 148 "build/pidl/idl.yp"
{{
		"TYPE" => "EMPTY",
		"CASE" => "default",
	 }}
	],
	[#Rule 36
		 'base_element', 5,
sub
#line 155 "build/pidl/idl.yp"
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
#line 167 "build/pidl/idl.yp"
{ 0 }
	],
	[#Rule 38
		 'pointers', 2,
sub
#line 168 "build/pidl/idl.yp"
{ $_[1]+1 }
	],
	[#Rule 39
		 'element_list1', 0, undef
	],
	[#Rule 40
		 'element_list1', 3,
sub
#line 175 "build/pidl/idl.yp"
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
#line 181 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 44
		 'element_list2', 3,
sub
#line 182 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 45
		 'array_len', 0, undef
	],
	[#Rule 46
		 'array_len', 2,
sub
#line 187 "build/pidl/idl.yp"
{ "*" }
	],
	[#Rule 47
		 'array_len', 3,
sub
#line 188 "build/pidl/idl.yp"
{ "$_[2]" }
	],
	[#Rule 48
		 'property_list', 0, undef
	],
	[#Rule 49
		 'property_list', 4,
sub
#line 194 "build/pidl/idl.yp"
{ util::FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 50
		 'properties', 1,
sub
#line 197 "build/pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 51
		 'properties', 3,
sub
#line 198 "build/pidl/idl.yp"
{ util::FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 52
		 'property', 1,
sub
#line 201 "build/pidl/idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 53
		 'property', 4,
sub
#line 202 "build/pidl/idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 54
		 'listtext', 1, undef
	],
	[#Rule 55
		 'listtext', 3,
sub
#line 207 "build/pidl/idl.yp"
{ "$_[1] $_[3]" }
	],
	[#Rule 56
		 'anytext', 0,
sub
#line 211 "build/pidl/idl.yp"
{ "" }
	],
	[#Rule 57
		 'anytext', 1, undef
	],
	[#Rule 58
		 'anytext', 1, undef
	],
	[#Rule 59
		 'anytext', 1, undef
	],
	[#Rule 60
		 'anytext', 3,
sub
#line 213 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 61
		 'anytext', 3,
sub
#line 214 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 62
		 'anytext', 3,
sub
#line 215 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 63
		 'anytext', 3,
sub
#line 216 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 64
		 'anytext', 3,
sub
#line 217 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 65
		 'anytext', 3,
sub
#line 218 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 66
		 'anytext', 3,
sub
#line 219 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 67
		 'anytext', 3,
sub
#line 220 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 68
		 'anytext', 5,
sub
#line 221 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 69
		 'identifier', 1, undef
	],
	[#Rule 70
		 'constant', 1, undef
	],
	[#Rule 71
		 'text', 1,
sub
#line 230 "build/pidl/idl.yp"
{ "\"$_[1]\"" }
	]
],
                                  @_);
    bless($self,$class);
}

#line 236 "build/pidl/idl.yp"


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
	return $self->YYParse( yylex => \&_Lexer, yyerror => \&_Error );
}

1;
