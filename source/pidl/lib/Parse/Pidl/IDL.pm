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
			'' => 2,
			"importlib" => 3,
			"import" => 6
		},
		DEFAULT => -90,
		GOTOS => {
			'importlib' => 9,
			'interface' => 8,
			'include' => 4,
			'coclass' => 10,
			'import' => 7,
			'property_list' => 5
		}
	},
	{#State 2
		DEFAULT => 0
	},
	{#State 3
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 12,
			'constant' => 13,
			'commalisttext' => 15
		}
	},
	{#State 4
		DEFAULT => -5
	},
	{#State 5
		ACTIONS => {
			"coclass" => 19,
			"[" => 21,
			"interface" => 20
		}
	},
	{#State 6
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 12,
			'constant' => 13,
			'commalisttext' => 22
		}
	},
	{#State 7
		DEFAULT => -4
	},
	{#State 8
		DEFAULT => -2
	},
	{#State 9
		DEFAULT => -6
	},
	{#State 10
		DEFAULT => -3
	},
	{#State 11
		DEFAULT => -119
	},
	{#State 12
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"*" => 35,
			"?" => 25,
			"{" => 29,
			"&" => 30,
			"/" => 31,
			"=" => 32,
			"(" => 33,
			"|" => 34,
			"." => 36,
			">" => 37
		},
		DEFAULT => -98
	},
	{#State 13
		DEFAULT => -102
	},
	{#State 14
		DEFAULT => -122
	},
	{#State 15
		ACTIONS => {
			";" => 38,
			"," => 39
		}
	},
	{#State 16
		DEFAULT => -123
	},
	{#State 17
		DEFAULT => -101
	},
	{#State 18
		DEFAULT => -103
	},
	{#State 19
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 40
		}
	},
	{#State 20
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 41
		}
	},
	{#State 21
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 43,
			'property' => 44,
			'properties' => 42
		}
	},
	{#State 22
		ACTIONS => {
			";" => 45,
			"," => 39
		}
	},
	{#State 23
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 46,
			'constant' => 13
		}
	},
	{#State 24
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 47,
			'constant' => 13
		}
	},
	{#State 25
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 48,
			'constant' => 13
		}
	},
	{#State 26
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 49,
			'constant' => 13
		}
	},
	{#State 27
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 50,
			'constant' => 13
		}
	},
	{#State 28
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 51,
			'constant' => 13
		}
	},
	{#State 29
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 12,
			'constant' => 13,
			'commalisttext' => 52
		}
	},
	{#State 30
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 53,
			'constant' => 13
		}
	},
	{#State 31
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 54,
			'constant' => 13
		}
	},
	{#State 32
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 55,
			'constant' => 13
		}
	},
	{#State 33
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 12,
			'constant' => 13,
			'commalisttext' => 56
		}
	},
	{#State 34
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 57,
			'constant' => 13
		}
	},
	{#State 35
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 58,
			'constant' => 13
		}
	},
	{#State 36
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 59,
			'constant' => 13
		}
	},
	{#State 37
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 60,
			'constant' => 13
		}
	},
	{#State 38
		DEFAULT => -9
	},
	{#State 39
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 61,
			'constant' => 13
		}
	},
	{#State 40
		ACTIONS => {
			"{" => 62
		}
	},
	{#State 41
		ACTIONS => {
			":" => 63
		},
		DEFAULT => -14,
		GOTOS => {
			'base_interface' => 64
		}
	},
	{#State 42
		ACTIONS => {
			"," => 65,
			"]" => 66
		}
	},
	{#State 43
		ACTIONS => {
			"(" => 67
		},
		DEFAULT => -94
	},
	{#State 44
		DEFAULT => -92
	},
	{#State 45
		DEFAULT => -7
	},
	{#State 46
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"*" => 35,
			"?" => 25,
			"{" => 29,
			"&" => 30,
			"/" => 31,
			"=" => 32,
			"(" => 33,
			"|" => 34,
			"." => 36,
			">" => 37
		},
		DEFAULT => -113
	},
	{#State 47
		ACTIONS => {
			":" => 23,
			"<" => 26,
			"~" => 27,
			"?" => 25,
			"{" => 29,
			"=" => 32
		},
		DEFAULT => -104
	},
	{#State 48
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"*" => 35,
			"?" => 25,
			"{" => 29,
			"&" => 30,
			"/" => 31,
			"=" => 32,
			"(" => 33,
			"|" => 34,
			"." => 36,
			">" => 37
		},
		DEFAULT => -112
	},
	{#State 49
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"*" => 35,
			"?" => 25,
			"{" => 29,
			"&" => 30,
			"/" => 31,
			"=" => 32,
			"(" => 33,
			"|" => 34,
			"." => 36,
			">" => 37
		},
		DEFAULT => -108
	},
	{#State 50
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"*" => 35,
			"?" => 25,
			"{" => 29,
			"&" => 30,
			"/" => 31,
			"=" => 32,
			"(" => 33,
			"|" => 34,
			"." => 36,
			">" => 37
		},
		DEFAULT => -116
	},
	{#State 51
		ACTIONS => {
			":" => 23,
			"<" => 26,
			"~" => 27,
			"?" => 25,
			"{" => 29,
			"=" => 32
		},
		DEFAULT => -115
	},
	{#State 52
		ACTIONS => {
			"}" => 68,
			"," => 39
		}
	},
	{#State 53
		ACTIONS => {
			":" => 23,
			"<" => 26,
			"~" => 27,
			"?" => 25,
			"{" => 29,
			"=" => 32
		},
		DEFAULT => -110
	},
	{#State 54
		ACTIONS => {
			":" => 23,
			"<" => 26,
			"~" => 27,
			"?" => 25,
			"{" => 29,
			"=" => 32
		},
		DEFAULT => -111
	},
	{#State 55
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"*" => 35,
			"?" => 25,
			"{" => 29,
			"&" => 30,
			"/" => 31,
			"=" => 32,
			"(" => 33,
			"|" => 34,
			"." => 36,
			">" => 37
		},
		DEFAULT => -114
	},
	{#State 56
		ACTIONS => {
			"," => 39,
			")" => 69
		}
	},
	{#State 57
		ACTIONS => {
			":" => 23,
			"<" => 26,
			"~" => 27,
			"?" => 25,
			"{" => 29,
			"=" => 32
		},
		DEFAULT => -109
	},
	{#State 58
		ACTIONS => {
			":" => 23,
			"<" => 26,
			"~" => 27,
			"?" => 25,
			"{" => 29,
			"=" => 32
		},
		DEFAULT => -106
	},
	{#State 59
		ACTIONS => {
			":" => 23,
			"<" => 26,
			"~" => 27,
			"?" => 25,
			"{" => 29,
			"=" => 32
		},
		DEFAULT => -105
	},
	{#State 60
		ACTIONS => {
			":" => 23,
			"<" => 26,
			"~" => 27,
			"?" => 25,
			"{" => 29,
			"=" => 32
		},
		DEFAULT => -107
	},
	{#State 61
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"*" => 35,
			"?" => 25,
			"{" => 29,
			"&" => 30,
			"/" => 31,
			"=" => 32,
			"(" => 33,
			"|" => 34,
			"." => 36,
			">" => 37
		},
		DEFAULT => -99
	},
	{#State 62
		DEFAULT => -11,
		GOTOS => {
			'interface_names' => 70
		}
	},
	{#State 63
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 71
		}
	},
	{#State 64
		ACTIONS => {
			"{" => 72
		}
	},
	{#State 65
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 43,
			'property' => 73
		}
	},
	{#State 66
		DEFAULT => -91
	},
	{#State 67
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'listtext' => 75,
			'anytext' => 74,
			'constant' => 13
		}
	},
	{#State 68
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 76,
			'constant' => 13
		}
	},
	{#State 69
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'text' => 18,
			'anytext' => 77,
			'constant' => 13
		}
	},
	{#State 70
		ACTIONS => {
			"}" => 78,
			"interface" => 79
		}
	},
	{#State 71
		DEFAULT => -15
	},
	{#State 72
		ACTIONS => {
			"typedef" => 80,
			"union" => 81,
			"enum" => 94,
			"bitmap" => 95,
			"declare" => 87,
			"const" => 89,
			"struct" => 92
		},
		DEFAULT => -90,
		GOTOS => {
			'typedecl' => 93,
			'function' => 82,
			'bitmap' => 96,
			'definitions' => 83,
			'definition' => 86,
			'property_list' => 85,
			'usertype' => 84,
			'declare' => 98,
			'const' => 97,
			'struct' => 88,
			'enum' => 90,
			'typedef' => 91,
			'union' => 99
		}
	},
	{#State 73
		DEFAULT => -93
	},
	{#State 74
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"*" => 35,
			"?" => 25,
			"{" => 29,
			"&" => 30,
			"/" => 31,
			"=" => 32,
			"(" => 33,
			"|" => 34,
			"." => 36,
			">" => 37
		},
		DEFAULT => -96
	},
	{#State 75
		ACTIONS => {
			"," => 100,
			")" => 101
		}
	},
	{#State 76
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"*" => 35,
			"?" => 25,
			"{" => 29,
			"&" => 30,
			"/" => 31,
			"=" => 32,
			"(" => 33,
			"|" => 34,
			"." => 36,
			">" => 37
		},
		DEFAULT => -118
	},
	{#State 77
		ACTIONS => {
			":" => 23,
			"<" => 26,
			"~" => 27,
			"?" => 25,
			"{" => 29,
			"=" => 32
		},
		DEFAULT => -117
	},
	{#State 78
		ACTIONS => {
			";" => 102
		},
		DEFAULT => -124,
		GOTOS => {
			'optional_semicolon' => 103
		}
	},
	{#State 79
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 104
		}
	},
	{#State 80
		DEFAULT => -90,
		GOTOS => {
			'property_list' => 105
		}
	},
	{#State 81
		ACTIONS => {
			'IDENTIFIER' => 106
		},
		DEFAULT => -121,
		GOTOS => {
			'optional_identifier' => 107
		}
	},
	{#State 82
		DEFAULT => -18
	},
	{#State 83
		ACTIONS => {
			"}" => 108,
			"typedef" => 80,
			"union" => 81,
			"enum" => 94,
			"bitmap" => 95,
			"declare" => 87,
			"const" => 89,
			"struct" => 92
		},
		DEFAULT => -90,
		GOTOS => {
			'typedecl' => 93,
			'function' => 82,
			'bitmap' => 96,
			'definition' => 109,
			'property_list' => 85,
			'usertype' => 84,
			'const' => 97,
			'struct' => 88,
			'declare' => 98,
			'enum' => 90,
			'typedef' => 91,
			'union' => 99
		}
	},
	{#State 84
		ACTIONS => {
			";" => 110
		}
	},
	{#State 85
		ACTIONS => {
			'IDENTIFIER' => 11,
			"signed" => 116,
			"union" => 81,
			"enum" => 94,
			"bitmap" => 95,
			'void' => 111,
			"unsigned" => 117,
			"[" => 21,
			"struct" => 92
		},
		GOTOS => {
			'existingtype' => 115,
			'bitmap' => 96,
			'usertype' => 112,
			'identifier' => 113,
			'struct' => 88,
			'enum' => 90,
			'type' => 118,
			'union' => 99,
			'sign' => 114
		}
	},
	{#State 86
		DEFAULT => -16
	},
	{#State 87
		DEFAULT => -90,
		GOTOS => {
			'property_list' => 119
		}
	},
	{#State 88
		DEFAULT => -34
	},
	{#State 89
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 120
		}
	},
	{#State 90
		DEFAULT => -36
	},
	{#State 91
		DEFAULT => -20
	},
	{#State 92
		ACTIONS => {
			'IDENTIFIER' => 106
		},
		DEFAULT => -121,
		GOTOS => {
			'optional_identifier' => 121
		}
	},
	{#State 93
		DEFAULT => -22
	},
	{#State 94
		ACTIONS => {
			'IDENTIFIER' => 106
		},
		DEFAULT => -121,
		GOTOS => {
			'optional_identifier' => 122
		}
	},
	{#State 95
		ACTIONS => {
			'IDENTIFIER' => 106
		},
		DEFAULT => -121,
		GOTOS => {
			'optional_identifier' => 123
		}
	},
	{#State 96
		DEFAULT => -37
	},
	{#State 97
		DEFAULT => -19
	},
	{#State 98
		DEFAULT => -21
	},
	{#State 99
		DEFAULT => -35
	},
	{#State 100
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'anytext' => 124,
			'text' => 18,
			'constant' => 13
		}
	},
	{#State 101
		DEFAULT => -95
	},
	{#State 102
		DEFAULT => -125
	},
	{#State 103
		DEFAULT => -10
	},
	{#State 104
		ACTIONS => {
			";" => 125
		}
	},
	{#State 105
		ACTIONS => {
			'IDENTIFIER' => 11,
			"signed" => 116,
			"union" => 81,
			"enum" => 94,
			"bitmap" => 95,
			'void' => 111,
			"unsigned" => 117,
			"[" => 21,
			"struct" => 92
		},
		GOTOS => {
			'existingtype' => 115,
			'bitmap' => 96,
			'usertype' => 112,
			'identifier' => 113,
			'struct' => 88,
			'enum' => 90,
			'type' => 126,
			'union' => 99,
			'sign' => 114
		}
	},
	{#State 106
		DEFAULT => -120
	},
	{#State 107
		ACTIONS => {
			"{" => 128
		},
		DEFAULT => -75,
		GOTOS => {
			'union_body' => 129,
			'opt_union_body' => 127
		}
	},
	{#State 108
		ACTIONS => {
			";" => 102
		},
		DEFAULT => -124,
		GOTOS => {
			'optional_semicolon' => 130
		}
	},
	{#State 109
		DEFAULT => -17
	},
	{#State 110
		DEFAULT => -38
	},
	{#State 111
		DEFAULT => -46
	},
	{#State 112
		DEFAULT => -44
	},
	{#State 113
		DEFAULT => -43
	},
	{#State 114
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 131
		}
	},
	{#State 115
		DEFAULT => -45
	},
	{#State 116
		DEFAULT => -39
	},
	{#State 117
		DEFAULT => -40
	},
	{#State 118
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 132
		}
	},
	{#State 119
		ACTIONS => {
			"union" => 133,
			"enum" => 138,
			"bitmap" => 139,
			"[" => 21
		},
		GOTOS => {
			'decl_enum' => 134,
			'decl_bitmap' => 135,
			'decl_type' => 137,
			'decl_union' => 136
		}
	},
	{#State 120
		DEFAULT => -79,
		GOTOS => {
			'pointers' => 140
		}
	},
	{#State 121
		ACTIONS => {
			"{" => 142
		},
		DEFAULT => -65,
		GOTOS => {
			'struct_body' => 141,
			'opt_struct_body' => 143
		}
	},
	{#State 122
		ACTIONS => {
			"{" => 144
		},
		DEFAULT => -48,
		GOTOS => {
			'opt_enum_body' => 146,
			'enum_body' => 145
		}
	},
	{#State 123
		ACTIONS => {
			"{" => 148
		},
		DEFAULT => -56,
		GOTOS => {
			'bitmap_body' => 149,
			'opt_bitmap_body' => 147
		}
	},
	{#State 124
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"*" => 35,
			"?" => 25,
			"{" => 29,
			"&" => 30,
			"/" => 31,
			"=" => 32,
			"(" => 33,
			"|" => 34,
			"." => 36,
			">" => 37
		},
		DEFAULT => -97
	},
	{#State 125
		DEFAULT => -12
	},
	{#State 126
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 150
		}
	},
	{#State 127
		DEFAULT => -77
	},
	{#State 128
		DEFAULT => -72,
		GOTOS => {
			'union_elements' => 151
		}
	},
	{#State 129
		DEFAULT => -76
	},
	{#State 130
		DEFAULT => -13
	},
	{#State 131
		DEFAULT => -42
	},
	{#State 132
		ACTIONS => {
			"(" => 152
		}
	},
	{#State 133
		DEFAULT => -32
	},
	{#State 134
		DEFAULT => -27
	},
	{#State 135
		DEFAULT => -28
	},
	{#State 136
		DEFAULT => -29
	},
	{#State 137
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 153
		}
	},
	{#State 138
		DEFAULT => -30
	},
	{#State 139
		DEFAULT => -31
	},
	{#State 140
		ACTIONS => {
			'IDENTIFIER' => 11,
			"*" => 155
		},
		GOTOS => {
			'identifier' => 154
		}
	},
	{#State 141
		DEFAULT => -66
	},
	{#State 142
		DEFAULT => -81,
		GOTOS => {
			'element_list1' => 156
		}
	},
	{#State 143
		DEFAULT => -67
	},
	{#State 144
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 157,
			'enum_element' => 158,
			'enum_elements' => 159
		}
	},
	{#State 145
		DEFAULT => -49
	},
	{#State 146
		DEFAULT => -50
	},
	{#State 147
		DEFAULT => -58
	},
	{#State 148
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		DEFAULT => -61,
		GOTOS => {
			'identifier' => 162,
			'bitmap_element' => 161,
			'bitmap_elements' => 160,
			'opt_bitmap_elements' => 163
		}
	},
	{#State 149
		DEFAULT => -57
	},
	{#State 150
		ACTIONS => {
			"[" => 164
		},
		DEFAULT => -87,
		GOTOS => {
			'array_len' => 165
		}
	},
	{#State 151
		ACTIONS => {
			"}" => 166
		},
		DEFAULT => -90,
		GOTOS => {
			'optional_base_element' => 168,
			'property_list' => 167
		}
	},
	{#State 152
		ACTIONS => {
			"," => -83,
			"void" => 172,
			")" => -83
		},
		DEFAULT => -90,
		GOTOS => {
			'base_element' => 169,
			'element_list2' => 171,
			'property_list' => 170
		}
	},
	{#State 153
		ACTIONS => {
			";" => 173
		}
	},
	{#State 154
		ACTIONS => {
			"[" => 164,
			"=" => 175
		},
		GOTOS => {
			'array_len' => 174
		}
	},
	{#State 155
		DEFAULT => -80
	},
	{#State 156
		ACTIONS => {
			"}" => 176
		},
		DEFAULT => -90,
		GOTOS => {
			'base_element' => 177,
			'property_list' => 170
		}
	},
	{#State 157
		ACTIONS => {
			"=" => 178
		},
		DEFAULT => -53
	},
	{#State 158
		DEFAULT => -51
	},
	{#State 159
		ACTIONS => {
			"}" => 179,
			"," => 180
		}
	},
	{#State 160
		ACTIONS => {
			"," => 181
		},
		DEFAULT => -62
	},
	{#State 161
		DEFAULT => -59
	},
	{#State 162
		ACTIONS => {
			"=" => 182
		}
	},
	{#State 163
		ACTIONS => {
			"}" => 183
		}
	},
	{#State 164
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			"]" => 184,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'anytext' => 185,
			'text' => 18,
			'constant' => 13
		}
	},
	{#State 165
		ACTIONS => {
			";" => 186
		}
	},
	{#State 166
		DEFAULT => -74
	},
	{#State 167
		ACTIONS => {
			"[" => 21
		},
		DEFAULT => -90,
		GOTOS => {
			'base_or_empty' => 187,
			'base_element' => 188,
			'empty_element' => 189,
			'property_list' => 190
		}
	},
	{#State 168
		DEFAULT => -73
	},
	{#State 169
		DEFAULT => -85
	},
	{#State 170
		ACTIONS => {
			'IDENTIFIER' => 11,
			"signed" => 116,
			"union" => 81,
			"enum" => 94,
			"bitmap" => 95,
			'void' => 111,
			"unsigned" => 117,
			"[" => 21,
			"struct" => 92
		},
		DEFAULT => -41,
		GOTOS => {
			'existingtype' => 115,
			'bitmap' => 96,
			'usertype' => 112,
			'identifier' => 113,
			'struct' => 88,
			'enum' => 90,
			'type' => 191,
			'union' => 99,
			'sign' => 114
		}
	},
	{#State 171
		ACTIONS => {
			"," => 192,
			")" => 193
		}
	},
	{#State 172
		DEFAULT => -84
	},
	{#State 173
		DEFAULT => -26
	},
	{#State 174
		ACTIONS => {
			"=" => 194
		}
	},
	{#State 175
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'anytext' => 195,
			'text' => 18,
			'constant' => 13
		}
	},
	{#State 176
		DEFAULT => -64
	},
	{#State 177
		ACTIONS => {
			";" => 196
		}
	},
	{#State 178
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'anytext' => 197,
			'text' => 18,
			'constant' => 13
		}
	},
	{#State 179
		DEFAULT => -47
	},
	{#State 180
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 157,
			'enum_element' => 198
		}
	},
	{#State 181
		ACTIONS => {
			'IDENTIFIER' => 11
		},
		GOTOS => {
			'identifier' => 162,
			'bitmap_element' => 199
		}
	},
	{#State 182
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'anytext' => 200,
			'text' => 18,
			'constant' => 13
		}
	},
	{#State 183
		DEFAULT => -55
	},
	{#State 184
		ACTIONS => {
			"[" => 164
		},
		DEFAULT => -87,
		GOTOS => {
			'array_len' => 201
		}
	},
	{#State 185
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"?" => 25,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"&" => 30,
			"{" => 29,
			"/" => 31,
			"=" => 32,
			"|" => 34,
			"(" => 33,
			"*" => 35,
			"." => 36,
			"]" => 202,
			">" => 37
		}
	},
	{#State 186
		DEFAULT => -33
	},
	{#State 187
		DEFAULT => -71
	},
	{#State 188
		ACTIONS => {
			";" => 203
		}
	},
	{#State 189
		DEFAULT => -70
	},
	{#State 190
		ACTIONS => {
			'IDENTIFIER' => 11,
			"signed" => 116,
			"union" => 81,
			";" => 204,
			"enum" => 94,
			"bitmap" => 95,
			'void' => 111,
			"unsigned" => 117,
			"[" => 21,
			"struct" => 92
		},
		DEFAULT => -41,
		GOTOS => {
			'existingtype' => 115,
			'bitmap' => 96,
			'usertype' => 112,
			'identifier' => 113,
			'struct' => 88,
			'enum' => 90,
			'type' => 191,
			'union' => 99,
			'sign' => 114
		}
	},
	{#State 191
		DEFAULT => -79,
		GOTOS => {
			'pointers' => 205
		}
	},
	{#State 192
		DEFAULT => -90,
		GOTOS => {
			'base_element' => 206,
			'property_list' => 170
		}
	},
	{#State 193
		ACTIONS => {
			";" => 207
		}
	},
	{#State 194
		ACTIONS => {
			'CONSTANT' => 14,
			'TEXT' => 16,
			'IDENTIFIER' => 11
		},
		DEFAULT => -100,
		GOTOS => {
			'identifier' => 17,
			'anytext' => 208,
			'text' => 18,
			'constant' => 13
		}
	},
	{#State 195
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"?" => 25,
			"<" => 26,
			";" => 209,
			"+" => 28,
			"~" => 27,
			"&" => 30,
			"{" => 29,
			"/" => 31,
			"=" => 32,
			"|" => 34,
			"(" => 33,
			"*" => 35,
			"." => 36,
			">" => 37
		}
	},
	{#State 196
		DEFAULT => -82
	},
	{#State 197
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"*" => 35,
			"?" => 25,
			"{" => 29,
			"&" => 30,
			"/" => 31,
			"=" => 32,
			"(" => 33,
			"|" => 34,
			"." => 36,
			">" => 37
		},
		DEFAULT => -54
	},
	{#State 198
		DEFAULT => -52
	},
	{#State 199
		DEFAULT => -60
	},
	{#State 200
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"<" => 26,
			"+" => 28,
			"~" => 27,
			"*" => 35,
			"?" => 25,
			"{" => 29,
			"&" => 30,
			"/" => 31,
			"=" => 32,
			"(" => 33,
			"|" => 34,
			"." => 36,
			">" => 37
		},
		DEFAULT => -63
	},
	{#State 201
		DEFAULT => -88
	},
	{#State 202
		ACTIONS => {
			"[" => 164
		},
		DEFAULT => -87,
		GOTOS => {
			'array_len' => 210
		}
	},
	{#State 203
		DEFAULT => -69
	},
	{#State 204
		DEFAULT => -68
	},
	{#State 205
		ACTIONS => {
			'IDENTIFIER' => 11,
			"*" => 155
		},
		GOTOS => {
			'identifier' => 211
		}
	},
	{#State 206
		DEFAULT => -86
	},
	{#State 207
		DEFAULT => -25
	},
	{#State 208
		ACTIONS => {
			"-" => 24,
			":" => 23,
			"?" => 25,
			"<" => 26,
			";" => 212,
			"+" => 28,
			"~" => 27,
			"&" => 30,
			"{" => 29,
			"/" => 31,
			"=" => 32,
			"|" => 34,
			"(" => 33,
			"*" => 35,
			"." => 36,
			">" => 37
		}
	},
	{#State 209
		DEFAULT => -23
	},
	{#State 210
		DEFAULT => -89
	},
	{#State 211
		ACTIONS => {
			"[" => 164
		},
		DEFAULT => -87,
		GOTOS => {
			'array_len' => 213
		}
	},
	{#State 212
		DEFAULT => -24
	},
	{#State 213
		DEFAULT => -78
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
#line 19 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 3
		 'idl', 2,
sub
#line 20 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 4
		 'idl', 2,
sub
#line 21 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 5
		 'idl', 2,
sub
#line 22 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 6
		 'idl', 2,
sub
#line 23 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 7
		 'import', 3,
sub
#line 26 "pidl/idl.yp"
{{
			"TYPE" => "IMPORT", 
			"PATHS" => [ $_[2] ],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 8
		 'include', 3,
sub
#line 33 "pidl/idl.yp"
{{ 
			"TYPE" => "INCLUDE", 
			"PATHS" => [ $_[2] ],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 9
		 'importlib', 3,
sub
#line 40 "pidl/idl.yp"
{{ 
			"TYPE" => "IMPORTLIB", 
			"PATHS" => [ $_[2] ],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 10
		 'coclass', 7,
sub
#line 49 "pidl/idl.yp"
{{
               "TYPE" => "COCLASS", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "DATA" => $_[5],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 11
		 'interface_names', 0, undef
	],
	[#Rule 12
		 'interface_names', 4,
sub
#line 61 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 13
		 'interface', 8,
sub
#line 65 "pidl/idl.yp"
{{
               "TYPE" => "INTERFACE", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "BASE" => $_[4],
	       "DATA" => $_[6],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 14
		 'base_interface', 0, undef
	],
	[#Rule 15
		 'base_interface', 2,
sub
#line 78 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 16
		 'definitions', 1,
sub
#line 82 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 17
		 'definitions', 2,
sub
#line 83 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 18
		 'definition', 1, undef
	],
	[#Rule 19
		 'definition', 1, undef
	],
	[#Rule 20
		 'definition', 1, undef
	],
	[#Rule 21
		 'definition', 1, undef
	],
	[#Rule 22
		 'definition', 1, undef
	],
	[#Rule 23
		 'const', 7,
sub
#line 91 "pidl/idl.yp"
{{
                     "TYPE"  => "CONST", 
		     "DTYPE"  => $_[2],
			 "POINTERS" => $_[3],
		     "NAME"  => $_[4],
		     "VALUE" => $_[6],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 24
		 'const', 8,
sub
#line 101 "pidl/idl.yp"
{{
                     "TYPE"  => "CONST", 
		     "DTYPE"  => $_[2],
			 "POINTERS" => $_[3],
		     "NAME"  => $_[4],
		     "ARRAY_LEN" => $_[5],
		     "VALUE" => $_[7],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 25
		 'function', 7,
sub
#line 115 "pidl/idl.yp"
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
	[#Rule 26
		 'declare', 5,
sub
#line 127 "pidl/idl.yp"
{{
	             "TYPE" => "DECLARE", 
                     "PROPERTIES" => $_[2],
		     "NAME" => $_[4],
		     "DATA" => $_[3],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 27
		 'decl_type', 1, undef
	],
	[#Rule 28
		 'decl_type', 1, undef
	],
	[#Rule 29
		 'decl_type', 1, undef
	],
	[#Rule 30
		 'decl_enum', 1,
sub
#line 141 "pidl/idl.yp"
{{
                     "TYPE" => "ENUM"
        }}
	],
	[#Rule 31
		 'decl_bitmap', 1,
sub
#line 147 "pidl/idl.yp"
{{
                     "TYPE" => "BITMAP"
        }}
	],
	[#Rule 32
		 'decl_union', 1,
sub
#line 153 "pidl/idl.yp"
{{
                     "TYPE" => "UNION"
        }}
	],
	[#Rule 33
		 'typedef', 6,
sub
#line 159 "pidl/idl.yp"
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
	[#Rule 34
		 'usertype', 1, undef
	],
	[#Rule 35
		 'usertype', 1, undef
	],
	[#Rule 36
		 'usertype', 1, undef
	],
	[#Rule 37
		 'usertype', 1, undef
	],
	[#Rule 38
		 'typedecl', 2,
sub
#line 172 "pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 39
		 'sign', 1, undef
	],
	[#Rule 40
		 'sign', 1, undef
	],
	[#Rule 41
		 'existingtype', 0, undef
	],
	[#Rule 42
		 'existingtype', 2,
sub
#line 177 "pidl/idl.yp"
{ "$_[1] $_[2]" }
	],
	[#Rule 43
		 'existingtype', 1, undef
	],
	[#Rule 44
		 'type', 1, undef
	],
	[#Rule 45
		 'type', 1, undef
	],
	[#Rule 46
		 'type', 1,
sub
#line 181 "pidl/idl.yp"
{ "void" }
	],
	[#Rule 47
		 'enum_body', 3,
sub
#line 183 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 48
		 'opt_enum_body', 0, undef
	],
	[#Rule 49
		 'opt_enum_body', 1, undef
	],
	[#Rule 50
		 'enum', 3,
sub
#line 186 "pidl/idl.yp"
{{
             "TYPE" => "ENUM", 
			 "NAME" => $_[2],
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 51
		 'enum_elements', 1,
sub
#line 194 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 52
		 'enum_elements', 3,
sub
#line 195 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 53
		 'enum_element', 1, undef
	],
	[#Rule 54
		 'enum_element', 3,
sub
#line 199 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 55
		 'bitmap_body', 3,
sub
#line 202 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 56
		 'opt_bitmap_body', 0, undef
	],
	[#Rule 57
		 'opt_bitmap_body', 1, undef
	],
	[#Rule 58
		 'bitmap', 3,
sub
#line 205 "pidl/idl.yp"
{{
             "TYPE" => "BITMAP", 
			 "NAME" => $_[2],
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 59
		 'bitmap_elements', 1,
sub
#line 213 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 60
		 'bitmap_elements', 3,
sub
#line 214 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 61
		 'opt_bitmap_elements', 0, undef
	],
	[#Rule 62
		 'opt_bitmap_elements', 1, undef
	],
	[#Rule 63
		 'bitmap_element', 3,
sub
#line 219 "pidl/idl.yp"
{ "$_[1] ( $_[3] )" }
	],
	[#Rule 64
		 'struct_body', 3,
sub
#line 222 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 65
		 'opt_struct_body', 0, undef
	],
	[#Rule 66
		 'opt_struct_body', 1, undef
	],
	[#Rule 67
		 'struct', 3,
sub
#line 226 "pidl/idl.yp"
{{
             "TYPE" => "STRUCT", 
			 "NAME" => $_[2],
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 68
		 'empty_element', 2,
sub
#line 234 "pidl/idl.yp"
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
	[#Rule 69
		 'base_or_empty', 2, undef
	],
	[#Rule 70
		 'base_or_empty', 1, undef
	],
	[#Rule 71
		 'optional_base_element', 2,
sub
#line 248 "pidl/idl.yp"
{ $_[2]->{PROPERTIES} = FlattenHash([$_[1],$_[2]->{PROPERTIES}]); $_[2] }
	],
	[#Rule 72
		 'union_elements', 0, undef
	],
	[#Rule 73
		 'union_elements', 2,
sub
#line 253 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 74
		 'union_body', 3,
sub
#line 256 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 75
		 'opt_union_body', 0, undef
	],
	[#Rule 76
		 'opt_union_body', 1, undef
	],
	[#Rule 77
		 'union', 3,
sub
#line 260 "pidl/idl.yp"
{{
             "TYPE" => "UNION", 
		     "NAME" => $_[2],
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 78
		 'base_element', 5,
sub
#line 268 "pidl/idl.yp"
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
	[#Rule 79
		 'pointers', 0,
sub
#line 282 "pidl/idl.yp"
{ 0 }
	],
	[#Rule 80
		 'pointers', 2,
sub
#line 283 "pidl/idl.yp"
{ $_[1]+1 }
	],
	[#Rule 81
		 'element_list1', 0, undef
	],
	[#Rule 82
		 'element_list1', 3,
sub
#line 288 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 83
		 'element_list2', 0, undef
	],
	[#Rule 84
		 'element_list2', 1, undef
	],
	[#Rule 85
		 'element_list2', 1,
sub
#line 294 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 86
		 'element_list2', 3,
sub
#line 295 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 87
		 'array_len', 0, undef
	],
	[#Rule 88
		 'array_len', 3,
sub
#line 300 "pidl/idl.yp"
{ push(@{$_[3]}, "*"); $_[3] }
	],
	[#Rule 89
		 'array_len', 4,
sub
#line 301 "pidl/idl.yp"
{ push(@{$_[4]}, "$_[2]"); $_[4] }
	],
	[#Rule 90
		 'property_list', 0, undef
	],
	[#Rule 91
		 'property_list', 4,
sub
#line 307 "pidl/idl.yp"
{ FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 92
		 'properties', 1,
sub
#line 310 "pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 93
		 'properties', 3,
sub
#line 311 "pidl/idl.yp"
{ FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 94
		 'property', 1,
sub
#line 314 "pidl/idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 95
		 'property', 4,
sub
#line 315 "pidl/idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 96
		 'listtext', 1, undef
	],
	[#Rule 97
		 'listtext', 3,
sub
#line 320 "pidl/idl.yp"
{ "$_[1] $_[3]" }
	],
	[#Rule 98
		 'commalisttext', 1, undef
	],
	[#Rule 99
		 'commalisttext', 3,
sub
#line 325 "pidl/idl.yp"
{ "$_[1],$_[3]" }
	],
	[#Rule 100
		 'anytext', 0,
sub
#line 329 "pidl/idl.yp"
{ "" }
	],
	[#Rule 101
		 'anytext', 1, undef
	],
	[#Rule 102
		 'anytext', 1, undef
	],
	[#Rule 103
		 'anytext', 1, undef
	],
	[#Rule 104
		 'anytext', 3,
sub
#line 331 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 105
		 'anytext', 3,
sub
#line 332 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 106
		 'anytext', 3,
sub
#line 333 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 107
		 'anytext', 3,
sub
#line 334 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 108
		 'anytext', 3,
sub
#line 335 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 109
		 'anytext', 3,
sub
#line 336 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 110
		 'anytext', 3,
sub
#line 337 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 111
		 'anytext', 3,
sub
#line 338 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 112
		 'anytext', 3,
sub
#line 339 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 113
		 'anytext', 3,
sub
#line 340 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 114
		 'anytext', 3,
sub
#line 341 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 115
		 'anytext', 3,
sub
#line 342 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 116
		 'anytext', 3,
sub
#line 343 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 117
		 'anytext', 5,
sub
#line 344 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 118
		 'anytext', 5,
sub
#line 345 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 119
		 'identifier', 1, undef
	],
	[#Rule 120
		 'optional_identifier', 1, undef
	],
	[#Rule 121
		 'optional_identifier', 0, undef
	],
	[#Rule 122
		 'constant', 1, undef
	],
	[#Rule 123
		 'text', 1,
sub
#line 359 "pidl/idl.yp"
{ "\"$_[1]\"" }
	],
	[#Rule 124
		 'optional_semicolon', 0, undef
	],
	[#Rule 125
		 'optional_semicolon', 1, undef
	]
],
                                  @_);
    bless($self,$class);
}

#line 370 "pidl/idl.yp"


#####################################################################
# flatten an array of hashes into a single hash
sub FlattenHash($) 
{ 
    my $a = shift;
    my %b;
    for my $d (@{$a}) {
	for my $k (keys %{$d}) {
	    $b{$k} = $d->{$k};
	}
    }
    return \%b;
}



#####################################################################
# traverse a perl data structure removing any empty arrays or
# hashes and any hash elements that map to undef
sub CleanData($)
{
    sub CleanData($);
    my($v) = shift;
	return undef if (not defined($v));
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

    $parser->YYData->{INPUT} or return('',undef);

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
			      |struct|enum|bitmap|void|unsigned|signed|import|include
				  |importlib)$/x) {
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

sub parse_string
{
	my ($data,$filename) = @_;

	my $self = new Parse::Pidl::IDL;

    $self->YYData->{INPUT_FILENAME} = $filename;
    $self->YYData->{INPUT} = $data;
    $self->YYData->{LINE} = 0;
    $self->YYData->{LAST_TOKEN} = "NONE";

	my $idl = $self->YYParse( yylex => \&_Lexer, yyerror => \&_Error );

	return CleanData($idl);
}

sub parse_file($$)
{
	my ($filename,$incdirs) = @_;

	my $saved_delim = $/;
	undef $/;
	my $cpp = $ENV{CPP};
	if (! defined $cpp) {
		$cpp = "cpp";
	}
	my $includes = map { " -I$_" } @$incdirs;
	my $data = `$cpp -D__PIDL__$includes -xc $filename`;
	$/ = $saved_delim;

	return parse_string($data, $filename);
}

1;
