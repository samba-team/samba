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
		DEFAULT => -60,
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
		DEFAULT => -86
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
		DEFAULT => -64
	},
	{#State 12
		DEFAULT => -62
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
		DEFAULT => -70,
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
		DEFAULT => -61
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
		DEFAULT => -88
	},
	{#State 23
		DEFAULT => -71
	},
	{#State 24
		DEFAULT => -73
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
		DEFAULT => -66
	},
	{#State 26
		ACTIONS => {
			"," => 46,
			")" => 47
		}
	},
	{#State 27
		DEFAULT => -72
	},
	{#State 28
		DEFAULT => -87
	},
	{#State 29
		DEFAULT => -63
	},
	{#State 30
		DEFAULT => -9
	},
	{#State 31
		ACTIONS => {
			"typedef" => 48,
			"declare" => 53,
			"const" => 56
		},
		DEFAULT => -60,
		GOTOS => {
			'const' => 55,
			'declare' => 54,
			'function' => 49,
			'typedef' => 57,
			'definitions' => 50,
			'definition' => 52,
			'property_list' => 51
		}
	},
	{#State 32
		ACTIONS => {
			";" => 59
		},
		DEFAULT => -89,
		GOTOS => {
			'optional_semicolon' => 58
		}
	},
	{#State 33
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 60
		}
	},
	{#State 34
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 61,
			'constant' => 27
		}
	},
	{#State 35
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 62,
			'constant' => 27
		}
	},
	{#State 36
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 63,
			'constant' => 27
		}
	},
	{#State 37
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 64,
			'constant' => 27
		}
	},
	{#State 38
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 65,
			'constant' => 27,
			'commalisttext' => 66
		}
	},
	{#State 39
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 67,
			'constant' => 27
		}
	},
	{#State 40
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 68,
			'constant' => 27
		}
	},
	{#State 41
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 65,
			'constant' => 27,
			'commalisttext' => 69
		}
	},
	{#State 42
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 70,
			'constant' => 27
		}
	},
	{#State 43
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 71,
			'constant' => 27
		}
	},
	{#State 44
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 72,
			'constant' => 27
		}
	},
	{#State 45
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 73,
			'constant' => 27
		}
	},
	{#State 46
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 74,
			'constant' => 27
		}
	},
	{#State 47
		DEFAULT => -65
	},
	{#State 48
		DEFAULT => -60,
		GOTOS => {
			'property_list' => 75
		}
	},
	{#State 49
		DEFAULT => -12
	},
	{#State 50
		ACTIONS => {
			"}" => 76,
			"typedef" => 48,
			"declare" => 53,
			"const" => 56
		},
		DEFAULT => -60,
		GOTOS => {
			'const' => 55,
			'declare' => 54,
			'function' => 49,
			'typedef' => 57,
			'definition' => 77,
			'property_list' => 51
		}
	},
	{#State 51
		ACTIONS => {
			'IDENTIFIER' => 9,
			"union" => 78,
			"enum" => 79,
			"[" => 7,
			'void' => 81,
			"bitmap" => 80,
			"struct" => 88
		},
		GOTOS => {
			'identifier' => 83,
			'struct' => 84,
			'enum' => 85,
			'type' => 86,
			'union' => 87,
			'bitmap' => 82
		}
	},
	{#State 52
		DEFAULT => -10
	},
	{#State 53
		DEFAULT => -60,
		GOTOS => {
			'property_list' => 89
		}
	},
	{#State 54
		DEFAULT => -15
	},
	{#State 55
		DEFAULT => -13
	},
	{#State 56
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 90
		}
	},
	{#State 57
		DEFAULT => -14
	},
	{#State 58
		DEFAULT => -4
	},
	{#State 59
		DEFAULT => -90
	},
	{#State 60
		ACTIONS => {
			";" => 91
		}
	},
	{#State 61
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -74
	},
	{#State 62
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"*" => 43,
			"{" => 38,
			"&" => 39,
			"/" => 40,
			"|" => 42,
			"(" => 41,
			"." => 44,
			">" => 45
		},
		DEFAULT => -78
	},
	{#State 63
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"*" => 43,
			"{" => 38,
			"&" => 39,
			"/" => 40,
			"|" => 42,
			"(" => 41,
			"." => 44,
			">" => 45
		},
		DEFAULT => -83
	},
	{#State 64
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -82
	},
	{#State 65
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"*" => 43,
			"{" => 38,
			"&" => 39,
			"/" => 40,
			"|" => 42,
			"(" => 41,
			"." => 44,
			">" => 45
		},
		DEFAULT => -68
	},
	{#State 66
		ACTIONS => {
			"}" => 92,
			"," => 93
		}
	},
	{#State 67
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -80
	},
	{#State 68
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -81
	},
	{#State 69
		ACTIONS => {
			"," => 93,
			")" => 94
		}
	},
	{#State 70
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -79
	},
	{#State 71
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -76
	},
	{#State 72
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -75
	},
	{#State 73
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -77
	},
	{#State 74
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
		DEFAULT => -67
	},
	{#State 75
		ACTIONS => {
			'IDENTIFIER' => 9,
			"union" => 78,
			"enum" => 79,
			"[" => 7,
			'void' => 81,
			"bitmap" => 80,
			"struct" => 88
		},
		GOTOS => {
			'identifier' => 83,
			'struct' => 84,
			'enum' => 85,
			'type' => 95,
			'union' => 87,
			'bitmap' => 82
		}
	},
	{#State 76
		ACTIONS => {
			";" => 59
		},
		DEFAULT => -89,
		GOTOS => {
			'optional_semicolon' => 96
		}
	},
	{#State 77
		DEFAULT => -11
	},
	{#State 78
		ACTIONS => {
			"{" => 97
		}
	},
	{#State 79
		ACTIONS => {
			"{" => 98
		}
	},
	{#State 80
		ACTIONS => {
			"{" => 99
		}
	},
	{#State 81
		DEFAULT => -30
	},
	{#State 82
		DEFAULT => -28
	},
	{#State 83
		DEFAULT => -29
	},
	{#State 84
		DEFAULT => -25
	},
	{#State 85
		DEFAULT => -27
	},
	{#State 86
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 100
		}
	},
	{#State 87
		DEFAULT => -26
	},
	{#State 88
		ACTIONS => {
			"{" => 101
		}
	},
	{#State 89
		ACTIONS => {
			"enum" => 102,
			"[" => 7,
			"bitmap" => 103
		},
		GOTOS => {
			'decl_enum' => 104,
			'decl_bitmap' => 105,
			'decl_type' => 106
		}
	},
	{#State 90
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 107
		}
	},
	{#State 91
		DEFAULT => -6
	},
	{#State 92
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 108,
			'constant' => 27
		}
	},
	{#State 93
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 109,
			'constant' => 27
		}
	},
	{#State 94
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 110,
			'constant' => 27
		}
	},
	{#State 95
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 111
		}
	},
	{#State 96
		DEFAULT => -7
	},
	{#State 97
		DEFAULT => -45,
		GOTOS => {
			'union_elements' => 112
		}
	},
	{#State 98
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 113,
			'enum_element' => 114,
			'enum_elements' => 115
		}
	},
	{#State 99
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 118,
			'bitmap_elements' => 117,
			'bitmap_element' => 116
		}
	},
	{#State 100
		ACTIONS => {
			"(" => 119
		}
	},
	{#State 101
		DEFAULT => -51,
		GOTOS => {
			'element_list1' => 120
		}
	},
	{#State 102
		DEFAULT => -22
	},
	{#State 103
		DEFAULT => -23
	},
	{#State 104
		DEFAULT => -20
	},
	{#State 105
		DEFAULT => -21
	},
	{#State 106
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 121
		}
	},
	{#State 107
		ACTIONS => {
			"[" => 124,
			"=" => 123
		},
		GOTOS => {
			'array_len' => 122
		}
	},
	{#State 108
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"*" => 43,
			"{" => 38,
			"&" => 39,
			"/" => 40,
			"|" => 42,
			"(" => 41,
			"." => 44,
			">" => 45
		},
		DEFAULT => -85
	},
	{#State 109
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			"+" => 37,
			"~" => 36,
			"*" => 43,
			"{" => 38,
			"&" => 39,
			"/" => 40,
			"|" => 42,
			"(" => 41,
			"." => 44,
			">" => 45
		},
		DEFAULT => -69
	},
	{#State 110
		ACTIONS => {
			"<" => 35,
			"~" => 36,
			"{" => 38
		},
		DEFAULT => -84
	},
	{#State 111
		ACTIONS => {
			"[" => 124
		},
		DEFAULT => -57,
		GOTOS => {
			'array_len' => 125
		}
	},
	{#State 112
		ACTIONS => {
			"}" => 126
		},
		DEFAULT => -60,
		GOTOS => {
			'optional_base_element' => 128,
			'property_list' => 127
		}
	},
	{#State 113
		ACTIONS => {
			"=" => 129
		},
		DEFAULT => -34
	},
	{#State 114
		DEFAULT => -32
	},
	{#State 115
		ACTIONS => {
			"}" => 130,
			"," => 131
		}
	},
	{#State 116
		DEFAULT => -37
	},
	{#State 117
		ACTIONS => {
			"}" => 132,
			"," => 133
		}
	},
	{#State 118
		ACTIONS => {
			"=" => 134
		}
	},
	{#State 119
		ACTIONS => {
			"," => -53,
			"void" => 137,
			")" => -53
		},
		DEFAULT => -60,
		GOTOS => {
			'base_element' => 135,
			'element_list2' => 138,
			'property_list' => 136
		}
	},
	{#State 120
		ACTIONS => {
			"}" => 139
		},
		DEFAULT => -60,
		GOTOS => {
			'base_element' => 140,
			'property_list' => 136
		}
	},
	{#State 121
		ACTIONS => {
			";" => 141
		}
	},
	{#State 122
		ACTIONS => {
			"=" => 142
		}
	},
	{#State 123
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 143,
			'constant' => 27
		}
	},
	{#State 124
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			"]" => 145,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 144,
			'constant' => 27
		}
	},
	{#State 125
		ACTIONS => {
			";" => 146
		}
	},
	{#State 126
		DEFAULT => -47
	},
	{#State 127
		ACTIONS => {
			"[" => 7
		},
		DEFAULT => -60,
		GOTOS => {
			'base_or_empty' => 147,
			'base_element' => 148,
			'empty_element' => 149,
			'property_list' => 150
		}
	},
	{#State 128
		DEFAULT => -46
	},
	{#State 129
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 151,
			'constant' => 27
		}
	},
	{#State 130
		DEFAULT => -31
	},
	{#State 131
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 113,
			'enum_element' => 152
		}
	},
	{#State 132
		DEFAULT => -36
	},
	{#State 133
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 118,
			'bitmap_element' => 153
		}
	},
	{#State 134
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 154,
			'constant' => 27
		}
	},
	{#State 135
		DEFAULT => -55
	},
	{#State 136
		ACTIONS => {
			'IDENTIFIER' => 9,
			"union" => 78,
			"enum" => 79,
			"[" => 7,
			'void' => 81,
			"bitmap" => 80,
			"struct" => 88
		},
		GOTOS => {
			'identifier' => 83,
			'struct' => 84,
			'enum' => 85,
			'type' => 155,
			'union' => 87,
			'bitmap' => 82
		}
	},
	{#State 137
		DEFAULT => -54
	},
	{#State 138
		ACTIONS => {
			"," => 156,
			")" => 157
		}
	},
	{#State 139
		DEFAULT => -40
	},
	{#State 140
		ACTIONS => {
			";" => 158
		}
	},
	{#State 141
		DEFAULT => -19
	},
	{#State 142
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -70,
		GOTOS => {
			'identifier' => 23,
			'text' => 24,
			'anytext' => 159,
			'constant' => 27
		}
	},
	{#State 143
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			";" => 160,
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
			"(" => 41,
			"|" => 42,
			"*" => 43,
			"]" => 161,
			"." => 44,
			">" => 45
		}
	},
	{#State 145
		ACTIONS => {
			"[" => 124
		},
		DEFAULT => -57,
		GOTOS => {
			'array_len' => 162
		}
	},
	{#State 146
		DEFAULT => -24
	},
	{#State 147
		DEFAULT => -44
	},
	{#State 148
		ACTIONS => {
			";" => 163
		}
	},
	{#State 149
		DEFAULT => -43
	},
	{#State 150
		ACTIONS => {
			'IDENTIFIER' => 9,
			"union" => 78,
			";" => 164,
			"enum" => 79,
			"[" => 7,
			'void' => 81,
			"bitmap" => 80,
			"struct" => 88
		},
		GOTOS => {
			'identifier' => 83,
			'struct' => 84,
			'enum' => 85,
			'type' => 155,
			'union' => 87,
			'bitmap' => 82
		}
	},
	{#State 151
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
		DEFAULT => -35
	},
	{#State 152
		DEFAULT => -33
	},
	{#State 153
		DEFAULT => -38
	},
	{#State 154
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
		DEFAULT => -39
	},
	{#State 155
		DEFAULT => -49,
		GOTOS => {
			'pointers' => 165
		}
	},
	{#State 156
		DEFAULT => -60,
		GOTOS => {
			'base_element' => 166,
			'property_list' => 136
		}
	},
	{#State 157
		ACTIONS => {
			";" => 167
		}
	},
	{#State 158
		DEFAULT => -52
	},
	{#State 159
		ACTIONS => {
			"-" => 34,
			"<" => 35,
			";" => 168,
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
		}
	},
	{#State 160
		DEFAULT => -16
	},
	{#State 161
		ACTIONS => {
			"[" => 124
		},
		DEFAULT => -57,
		GOTOS => {
			'array_len' => 169
		}
	},
	{#State 162
		DEFAULT => -58
	},
	{#State 163
		DEFAULT => -42
	},
	{#State 164
		DEFAULT => -41
	},
	{#State 165
		ACTIONS => {
			'IDENTIFIER' => 9,
			"*" => 171
		},
		GOTOS => {
			'identifier' => 170
		}
	},
	{#State 166
		DEFAULT => -56
	},
	{#State 167
		DEFAULT => -18
	},
	{#State 168
		DEFAULT => -17
	},
	{#State 169
		DEFAULT => -59
	},
	{#State 170
		ACTIONS => {
			"[" => 124
		},
		DEFAULT => -57,
		GOTOS => {
			'array_len' => 172
		}
	},
	{#State 171
		DEFAULT => -50
	},
	{#State 172
		DEFAULT => -48
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
	[#Rule 17
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
	[#Rule 18
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
	[#Rule 19
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
	[#Rule 20
		 'decl_type', 1, undef
	],
	[#Rule 21
		 'decl_type', 1, undef
	],
	[#Rule 22
		 'decl_enum', 1,
sub
#line 114 "build/pidl/idl.yp"
{{
                     "TYPE" => "ENUM"
        }}
	],
	[#Rule 23
		 'decl_bitmap', 1,
sub
#line 120 "build/pidl/idl.yp"
{{
                     "TYPE" => "BITMAP"
        }}
	],
	[#Rule 24
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
	[#Rule 25
		 'type', 1, undef
	],
	[#Rule 26
		 'type', 1, undef
	],
	[#Rule 27
		 'type', 1, undef
	],
	[#Rule 28
		 'type', 1, undef
	],
	[#Rule 29
		 'type', 1, undef
	],
	[#Rule 30
		 'type', 1,
sub
#line 138 "build/pidl/idl.yp"
{ "void" }
	],
	[#Rule 31
		 'enum', 4,
sub
#line 143 "build/pidl/idl.yp"
{{
             "TYPE" => "ENUM", 
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 32
		 'enum_elements', 1,
sub
#line 150 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 33
		 'enum_elements', 3,
sub
#line 151 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 34
		 'enum_element', 1, undef
	],
	[#Rule 35
		 'enum_element', 3,
sub
#line 155 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 36
		 'bitmap', 4,
sub
#line 159 "build/pidl/idl.yp"
{{
                     "TYPE" => "BITMAP", 
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 37
		 'bitmap_elements', 1,
sub
#line 166 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 38
		 'bitmap_elements', 3,
sub
#line 167 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 39
		 'bitmap_element', 3,
sub
#line 170 "build/pidl/idl.yp"
{ "$_[1] ( $_[3] )" }
	],
	[#Rule 40
		 'struct', 4,
sub
#line 174 "build/pidl/idl.yp"
{{
                     "TYPE" => "STRUCT", 
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 41
		 'empty_element', 2,
sub
#line 181 "build/pidl/idl.yp"
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
	[#Rule 42
		 'base_or_empty', 2, undef
	],
	[#Rule 43
		 'base_or_empty', 1, undef
	],
	[#Rule 44
		 'optional_base_element', 2,
sub
#line 195 "build/pidl/idl.yp"
{ $_[2]->{PROPERTIES} = util::FlattenHash([$_[1],$_[2]->{PROPERTIES}]); $_[2] }
	],
	[#Rule 45
		 'union_elements', 0, undef
	],
	[#Rule 46
		 'union_elements', 2,
sub
#line 200 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 47
		 'union', 4,
sub
#line 204 "build/pidl/idl.yp"
{{
                     "TYPE" => "UNION", 
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 48
		 'base_element', 5,
sub
#line 211 "build/pidl/idl.yp"
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
	[#Rule 49
		 'pointers', 0,
sub
#line 225 "build/pidl/idl.yp"
{ 0 }
	],
	[#Rule 50
		 'pointers', 2,
sub
#line 226 "build/pidl/idl.yp"
{ $_[1]+1 }
	],
	[#Rule 51
		 'element_list1', 0, undef
	],
	[#Rule 52
		 'element_list1', 3,
sub
#line 231 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 53
		 'element_list2', 0, undef
	],
	[#Rule 54
		 'element_list2', 1, undef
	],
	[#Rule 55
		 'element_list2', 1,
sub
#line 237 "build/pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 56
		 'element_list2', 3,
sub
#line 238 "build/pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 57
		 'array_len', 0, undef
	],
	[#Rule 58
		 'array_len', 3,
sub
#line 243 "build/pidl/idl.yp"
{ push(@{$_[3]}, "*"); $_[3] }
	],
	[#Rule 59
		 'array_len', 4,
sub
#line 244 "build/pidl/idl.yp"
{ push(@{$_[4]}, "$_[2]"); $_[4] }
	],
	[#Rule 60
		 'property_list', 0, undef
	],
	[#Rule 61
		 'property_list', 4,
sub
#line 250 "build/pidl/idl.yp"
{ util::FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 62
		 'properties', 1,
sub
#line 253 "build/pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 63
		 'properties', 3,
sub
#line 254 "build/pidl/idl.yp"
{ util::FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 64
		 'property', 1,
sub
#line 257 "build/pidl/idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 65
		 'property', 4,
sub
#line 258 "build/pidl/idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 66
		 'listtext', 1, undef
	],
	[#Rule 67
		 'listtext', 3,
sub
#line 263 "build/pidl/idl.yp"
{ "$_[1] $_[3]" }
	],
	[#Rule 68
		 'commalisttext', 1, undef
	],
	[#Rule 69
		 'commalisttext', 3,
sub
#line 268 "build/pidl/idl.yp"
{ "$_[1],$_[3]" }
	],
	[#Rule 70
		 'anytext', 0,
sub
#line 272 "build/pidl/idl.yp"
{ "" }
	],
	[#Rule 71
		 'anytext', 1, undef
	],
	[#Rule 72
		 'anytext', 1, undef
	],
	[#Rule 73
		 'anytext', 1, undef
	],
	[#Rule 74
		 'anytext', 3,
sub
#line 274 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 75
		 'anytext', 3,
sub
#line 275 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 76
		 'anytext', 3,
sub
#line 276 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 77
		 'anytext', 3,
sub
#line 277 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 78
		 'anytext', 3,
sub
#line 278 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 79
		 'anytext', 3,
sub
#line 279 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 80
		 'anytext', 3,
sub
#line 280 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 81
		 'anytext', 3,
sub
#line 281 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 82
		 'anytext', 3,
sub
#line 282 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 83
		 'anytext', 3,
sub
#line 283 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 84
		 'anytext', 5,
sub
#line 284 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 85
		 'anytext', 5,
sub
#line 285 "build/pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 86
		 'identifier', 1, undef
	],
	[#Rule 87
		 'constant', 1, undef
	],
	[#Rule 88
		 'text', 1,
sub
#line 294 "build/pidl/idl.yp"
{ "\"$_[1]\"" }
	],
	[#Rule 89
		 'optional_semicolon', 0, undef
	],
	[#Rule 90
		 'optional_semicolon', 1, undef
	]
],
                                  @_);
    bless($self,$class);
}

#line 305 "build/pidl/idl.yp"


use pidl::util;

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

	return util::CleanData($idl);
}

1;
