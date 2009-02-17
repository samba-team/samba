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
use Parse::Yapp::Driver;



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
			"cpp_quote" => 3,
			"importlib" => 4,
			"import" => 7,
			"include" => 13
		},
		DEFAULT => -83,
		GOTOS => {
			'cpp_quote' => 11,
			'importlib' => 10,
			'interface' => 9,
			'include' => 5,
			'coclass' => 12,
			'import' => 8,
			'property_list' => 6
		}
	},
	{#State 2
		DEFAULT => 0
	},
	{#State 3
		ACTIONS => {
			"(" => 14
		}
	},
	{#State 4
		ACTIONS => {
			'TEXT' => 16
		},
		GOTOS => {
			'commalist' => 15,
			'text' => 17
		}
	},
	{#State 5
		DEFAULT => -5
	},
	{#State 6
		ACTIONS => {
			"coclass" => 18,
			"[" => 20,
			"interface" => 19
		}
	},
	{#State 7
		ACTIONS => {
			'TEXT' => 16
		},
		GOTOS => {
			'commalist' => 21,
			'text' => 17
		}
	},
	{#State 8
		DEFAULT => -4
	},
	{#State 9
		DEFAULT => -2
	},
	{#State 10
		DEFAULT => -6
	},
	{#State 11
		DEFAULT => -7
	},
	{#State 12
		DEFAULT => -3
	},
	{#State 13
		ACTIONS => {
			'TEXT' => 16
		},
		GOTOS => {
			'commalist' => 22,
			'text' => 17
		}
	},
	{#State 14
		ACTIONS => {
			'TEXT' => 16
		},
		GOTOS => {
			'text' => 23
		}
	},
	{#State 15
		ACTIONS => {
			";" => 24,
			"," => 25
		}
	},
	{#State 16
		DEFAULT => -114
	},
	{#State 17
		DEFAULT => -11
	},
	{#State 18
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 27
		}
	},
	{#State 19
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 28
		}
	},
	{#State 20
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 30,
			'property' => 31,
			'properties' => 29
		}
	},
	{#State 21
		ACTIONS => {
			";" => 32,
			"," => 25
		}
	},
	{#State 22
		ACTIONS => {
			";" => 33,
			"," => 25
		}
	},
	{#State 23
		ACTIONS => {
			")" => 34
		}
	},
	{#State 24
		DEFAULT => -10
	},
	{#State 25
		ACTIONS => {
			'TEXT' => 16
		},
		GOTOS => {
			'text' => 35
		}
	},
	{#State 26
		DEFAULT => -110
	},
	{#State 27
		ACTIONS => {
			"{" => 36
		}
	},
	{#State 28
		ACTIONS => {
			"{" => 37
		}
	},
	{#State 29
		ACTIONS => {
			"," => 38,
			"]" => 39
		}
	},
	{#State 30
		ACTIONS => {
			"(" => 40
		},
		DEFAULT => -87
	},
	{#State 31
		DEFAULT => -85
	},
	{#State 32
		DEFAULT => -8
	},
	{#State 33
		DEFAULT => -9
	},
	{#State 34
		DEFAULT => -17
	},
	{#State 35
		DEFAULT => -12
	},
	{#State 36
		DEFAULT => -14,
		GOTOS => {
			'interface_names' => 41
		}
	},
	{#State 37
		ACTIONS => {
			"const" => 51
		},
		DEFAULT => -83,
		GOTOS => {
			'typedecl' => 42,
			'function' => 43,
			'definitions' => 45,
			'bitmap' => 44,
			'definition' => 48,
			'property_list' => 47,
			'usertype' => 46,
			'const' => 50,
			'struct' => 49,
			'typedef' => 53,
			'enum' => 52,
			'union' => 54
		}
	},
	{#State 38
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 30,
			'property' => 55
		}
	},
	{#State 39
		DEFAULT => -84
	},
	{#State 40
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'text' => 61,
			'anytext' => 56,
			'constant' => 57,
			'commalisttext' => 59
		}
	},
	{#State 41
		ACTIONS => {
			"}" => 62,
			"interface" => 63
		}
	},
	{#State 42
		DEFAULT => -23
	},
	{#State 43
		DEFAULT => -20
	},
	{#State 44
		DEFAULT => -31
	},
	{#State 45
		ACTIONS => {
			"}" => 64,
			"const" => 51
		},
		DEFAULT => -83,
		GOTOS => {
			'typedecl' => 42,
			'function' => 43,
			'bitmap' => 44,
			'definition' => 65,
			'property_list' => 47,
			'usertype' => 46,
			'struct' => 49,
			'const' => 50,
			'typedef' => 53,
			'enum' => 52,
			'union' => 54
		}
	},
	{#State 46
		ACTIONS => {
			";" => 66
		}
	},
	{#State 47
		ACTIONS => {
			"typedef" => 67,
			'IDENTIFIER' => 26,
			"signed" => 75,
			"union" => 68,
			"enum" => 77,
			"bitmap" => 78,
			'void' => 69,
			"unsigned" => 79,
			"[" => 20,
			"struct" => 74
		},
		GOTOS => {
			'existingtype' => 76,
			'bitmap' => 44,
			'usertype' => 71,
			'property_list' => 70,
			'identifier' => 72,
			'struct' => 49,
			'enum' => 52,
			'type' => 80,
			'union' => 54,
			'sign' => 73
		}
	},
	{#State 48
		DEFAULT => -18
	},
	{#State 49
		DEFAULT => -28
	},
	{#State 50
		DEFAULT => -21
	},
	{#State 51
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 81
		}
	},
	{#State 52
		DEFAULT => -30
	},
	{#State 53
		DEFAULT => -22
	},
	{#State 54
		DEFAULT => -29
	},
	{#State 55
		DEFAULT => -86
	},
	{#State 56
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"<" => 84,
			"+" => 86,
			"~" => 85,
			"*" => 87,
			"?" => 88,
			"{" => 89,
			"&" => 90,
			"/" => 91,
			"=" => 92,
			"(" => 93,
			"|" => 94,
			"." => 95,
			">" => 96
		},
		DEFAULT => -89
	},
	{#State 57
		DEFAULT => -93
	},
	{#State 58
		DEFAULT => -113
	},
	{#State 59
		ACTIONS => {
			"," => 97,
			")" => 98
		}
	},
	{#State 60
		DEFAULT => -92
	},
	{#State 61
		DEFAULT => -94
	},
	{#State 62
		ACTIONS => {
			";" => 99
		},
		DEFAULT => -115,
		GOTOS => {
			'optional_semicolon' => 100
		}
	},
	{#State 63
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 101
		}
	},
	{#State 64
		ACTIONS => {
			";" => 99
		},
		DEFAULT => -115,
		GOTOS => {
			'optional_semicolon' => 102
		}
	},
	{#State 65
		DEFAULT => -19
	},
	{#State 66
		DEFAULT => -32
	},
	{#State 67
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 75,
			'void' => 69,
			"unsigned" => 79
		},
		DEFAULT => -83,
		GOTOS => {
			'existingtype' => 76,
			'bitmap' => 44,
			'usertype' => 71,
			'property_list' => 70,
			'identifier' => 72,
			'struct' => 49,
			'enum' => 52,
			'type' => 103,
			'union' => 54,
			'sign' => 73
		}
	},
	{#State 68
		ACTIONS => {
			'IDENTIFIER' => 104
		},
		DEFAULT => -112,
		GOTOS => {
			'optional_identifier' => 105
		}
	},
	{#State 69
		DEFAULT => -39
	},
	{#State 70
		ACTIONS => {
			"union" => 68,
			"enum" => 77,
			"bitmap" => 78,
			"[" => 20,
			"struct" => 74
		}
	},
	{#State 71
		DEFAULT => -37
	},
	{#State 72
		DEFAULT => -36
	},
	{#State 73
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 106
		}
	},
	{#State 74
		ACTIONS => {
			'IDENTIFIER' => 104
		},
		DEFAULT => -112,
		GOTOS => {
			'optional_identifier' => 107
		}
	},
	{#State 75
		DEFAULT => -33
	},
	{#State 76
		DEFAULT => -38
	},
	{#State 77
		ACTIONS => {
			'IDENTIFIER' => 104
		},
		DEFAULT => -112,
		GOTOS => {
			'optional_identifier' => 108
		}
	},
	{#State 78
		ACTIONS => {
			'IDENTIFIER' => 104
		},
		DEFAULT => -112,
		GOTOS => {
			'optional_identifier' => 109
		}
	},
	{#State 79
		DEFAULT => -34
	},
	{#State 80
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 110
		}
	},
	{#State 81
		DEFAULT => -72,
		GOTOS => {
			'pointers' => 111
		}
	},
	{#State 82
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 112,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 83
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 113,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 84
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 114,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 85
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 115,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 86
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 116,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 87
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 117,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 88
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 118,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 89
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 56,
			'text' => 61,
			'constant' => 57,
			'commalisttext' => 119
		}
	},
	{#State 90
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 120,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 91
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 121,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 92
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 122,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 93
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 56,
			'text' => 61,
			'constant' => 57,
			'commalisttext' => 123
		}
	},
	{#State 94
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 124,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 95
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 125,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 96
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 126,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 97
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 127,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 98
		DEFAULT => -88
	},
	{#State 99
		DEFAULT => -116
	},
	{#State 100
		DEFAULT => -13
	},
	{#State 101
		ACTIONS => {
			";" => 128
		}
	},
	{#State 102
		DEFAULT => -16
	},
	{#State 103
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 129
		}
	},
	{#State 104
		DEFAULT => -111
	},
	{#State 105
		ACTIONS => {
			"{" => 131
		},
		DEFAULT => -68,
		GOTOS => {
			'union_body' => 132,
			'opt_union_body' => 130
		}
	},
	{#State 106
		DEFAULT => -35
	},
	{#State 107
		ACTIONS => {
			"{" => 134
		},
		DEFAULT => -58,
		GOTOS => {
			'struct_body' => 133,
			'opt_struct_body' => 135
		}
	},
	{#State 108
		ACTIONS => {
			"{" => 136
		},
		DEFAULT => -41,
		GOTOS => {
			'opt_enum_body' => 138,
			'enum_body' => 137
		}
	},
	{#State 109
		ACTIONS => {
			"{" => 140
		},
		DEFAULT => -49,
		GOTOS => {
			'bitmap_body' => 141,
			'opt_bitmap_body' => 139
		}
	},
	{#State 110
		ACTIONS => {
			"(" => 142
		}
	},
	{#State 111
		ACTIONS => {
			'IDENTIFIER' => 26,
			"*" => 144
		},
		GOTOS => {
			'identifier' => 143
		}
	},
	{#State 112
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"<" => 84,
			"+" => 86,
			"~" => 85,
			"*" => 87,
			"?" => 88,
			"{" => 89,
			"&" => 90,
			"/" => 91,
			"=" => 92,
			"(" => 93,
			"|" => 94,
			"." => 95,
			">" => 96
		},
		DEFAULT => -104
	},
	{#State 113
		ACTIONS => {
			":" => 82,
			"<" => 84,
			"~" => 85,
			"?" => 88,
			"{" => 89,
			"=" => 92
		},
		DEFAULT => -95
	},
	{#State 114
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"<" => 84,
			"+" => 86,
			"~" => 85,
			"*" => 87,
			"?" => 88,
			"{" => 89,
			"&" => 90,
			"/" => 91,
			"=" => 92,
			"(" => 93,
			"|" => 94,
			"." => 95,
			">" => 96
		},
		DEFAULT => -99
	},
	{#State 115
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"<" => 84,
			"+" => 86,
			"~" => 85,
			"*" => 87,
			"?" => 88,
			"{" => 89,
			"&" => 90,
			"/" => 91,
			"=" => 92,
			"(" => 93,
			"|" => 94,
			"." => 95,
			">" => 96
		},
		DEFAULT => -107
	},
	{#State 116
		ACTIONS => {
			":" => 82,
			"<" => 84,
			"~" => 85,
			"?" => 88,
			"{" => 89,
			"=" => 92
		},
		DEFAULT => -106
	},
	{#State 117
		ACTIONS => {
			":" => 82,
			"<" => 84,
			"~" => 85,
			"?" => 88,
			"{" => 89,
			"=" => 92
		},
		DEFAULT => -97
	},
	{#State 118
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"<" => 84,
			"+" => 86,
			"~" => 85,
			"*" => 87,
			"?" => 88,
			"{" => 89,
			"&" => 90,
			"/" => 91,
			"=" => 92,
			"(" => 93,
			"|" => 94,
			"." => 95,
			">" => 96
		},
		DEFAULT => -103
	},
	{#State 119
		ACTIONS => {
			"}" => 145,
			"," => 97
		}
	},
	{#State 120
		ACTIONS => {
			":" => 82,
			"<" => 84,
			"~" => 85,
			"?" => 88,
			"{" => 89,
			"=" => 92
		},
		DEFAULT => -101
	},
	{#State 121
		ACTIONS => {
			":" => 82,
			"<" => 84,
			"~" => 85,
			"?" => 88,
			"{" => 89,
			"=" => 92
		},
		DEFAULT => -102
	},
	{#State 122
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"<" => 84,
			"+" => 86,
			"~" => 85,
			"*" => 87,
			"?" => 88,
			"{" => 89,
			"&" => 90,
			"/" => 91,
			"=" => 92,
			"(" => 93,
			"|" => 94,
			"." => 95,
			">" => 96
		},
		DEFAULT => -105
	},
	{#State 123
		ACTIONS => {
			"," => 97,
			")" => 146
		}
	},
	{#State 124
		ACTIONS => {
			":" => 82,
			"<" => 84,
			"~" => 85,
			"?" => 88,
			"{" => 89,
			"=" => 92
		},
		DEFAULT => -100
	},
	{#State 125
		ACTIONS => {
			":" => 82,
			"<" => 84,
			"~" => 85,
			"?" => 88,
			"{" => 89,
			"=" => 92
		},
		DEFAULT => -96
	},
	{#State 126
		ACTIONS => {
			":" => 82,
			"<" => 84,
			"~" => 85,
			"?" => 88,
			"{" => 89,
			"=" => 92
		},
		DEFAULT => -98
	},
	{#State 127
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"<" => 84,
			"+" => 86,
			"~" => 85,
			"*" => 87,
			"?" => 88,
			"{" => 89,
			"&" => 90,
			"/" => 91,
			"=" => 92,
			"(" => 93,
			"|" => 94,
			"." => 95,
			">" => 96
		},
		DEFAULT => -90
	},
	{#State 128
		DEFAULT => -15
	},
	{#State 129
		ACTIONS => {
			"[" => 147
		},
		DEFAULT => -80,
		GOTOS => {
			'array_len' => 148
		}
	},
	{#State 130
		DEFAULT => -70
	},
	{#State 131
		DEFAULT => -65,
		GOTOS => {
			'union_elements' => 149
		}
	},
	{#State 132
		DEFAULT => -69
	},
	{#State 133
		DEFAULT => -59
	},
	{#State 134
		DEFAULT => -74,
		GOTOS => {
			'element_list1' => 150
		}
	},
	{#State 135
		DEFAULT => -60
	},
	{#State 136
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 151,
			'enum_element' => 152,
			'enum_elements' => 153
		}
	},
	{#State 137
		DEFAULT => -42
	},
	{#State 138
		DEFAULT => -43
	},
	{#State 139
		DEFAULT => -51
	},
	{#State 140
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		DEFAULT => -54,
		GOTOS => {
			'identifier' => 156,
			'bitmap_element' => 155,
			'bitmap_elements' => 154,
			'opt_bitmap_elements' => 157
		}
	},
	{#State 141
		DEFAULT => -50
	},
	{#State 142
		ACTIONS => {
			"," => -76,
			"void" => 161,
			")" => -76
		},
		DEFAULT => -83,
		GOTOS => {
			'base_element' => 158,
			'element_list2' => 160,
			'property_list' => 159
		}
	},
	{#State 143
		ACTIONS => {
			"[" => 147,
			"=" => 163
		},
		GOTOS => {
			'array_len' => 162
		}
	},
	{#State 144
		DEFAULT => -73
	},
	{#State 145
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 164,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 146
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 165,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 147
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			"]" => 166,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 167,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 148
		ACTIONS => {
			";" => 168
		}
	},
	{#State 149
		ACTIONS => {
			"}" => 169
		},
		DEFAULT => -83,
		GOTOS => {
			'optional_base_element' => 171,
			'property_list' => 170
		}
	},
	{#State 150
		ACTIONS => {
			"}" => 172
		},
		DEFAULT => -83,
		GOTOS => {
			'base_element' => 173,
			'property_list' => 159
		}
	},
	{#State 151
		ACTIONS => {
			"=" => 174
		},
		DEFAULT => -46
	},
	{#State 152
		DEFAULT => -44
	},
	{#State 153
		ACTIONS => {
			"}" => 175,
			"," => 176
		}
	},
	{#State 154
		ACTIONS => {
			"," => 177
		},
		DEFAULT => -55
	},
	{#State 155
		DEFAULT => -52
	},
	{#State 156
		ACTIONS => {
			"=" => 178
		}
	},
	{#State 157
		ACTIONS => {
			"}" => 179
		}
	},
	{#State 158
		DEFAULT => -78
	},
	{#State 159
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 75,
			'void' => 69,
			"unsigned" => 79,
			"[" => 20
		},
		DEFAULT => -83,
		GOTOS => {
			'existingtype' => 76,
			'bitmap' => 44,
			'usertype' => 71,
			'property_list' => 70,
			'identifier' => 72,
			'struct' => 49,
			'enum' => 52,
			'type' => 180,
			'union' => 54,
			'sign' => 73
		}
	},
	{#State 160
		ACTIONS => {
			"," => 181,
			")" => 182
		}
	},
	{#State 161
		DEFAULT => -77
	},
	{#State 162
		ACTIONS => {
			"=" => 183
		}
	},
	{#State 163
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 184,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 164
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"<" => 84,
			"+" => 86,
			"~" => 85,
			"*" => 87,
			"?" => 88,
			"{" => 89,
			"&" => 90,
			"/" => 91,
			"=" => 92,
			"(" => 93,
			"|" => 94,
			"." => 95,
			">" => 96
		},
		DEFAULT => -109
	},
	{#State 165
		ACTIONS => {
			":" => 82,
			"<" => 84,
			"~" => 85,
			"?" => 88,
			"{" => 89,
			"=" => 92
		},
		DEFAULT => -108
	},
	{#State 166
		ACTIONS => {
			"[" => 147
		},
		DEFAULT => -80,
		GOTOS => {
			'array_len' => 185
		}
	},
	{#State 167
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"?" => 88,
			"<" => 84,
			"+" => 86,
			"~" => 85,
			"&" => 90,
			"{" => 89,
			"/" => 91,
			"=" => 92,
			"|" => 94,
			"(" => 93,
			"*" => 87,
			"." => 95,
			"]" => 186,
			">" => 96
		}
	},
	{#State 168
		DEFAULT => -27
	},
	{#State 169
		DEFAULT => -67
	},
	{#State 170
		ACTIONS => {
			"[" => 20
		},
		DEFAULT => -83,
		GOTOS => {
			'base_or_empty' => 187,
			'base_element' => 188,
			'empty_element' => 189,
			'property_list' => 190
		}
	},
	{#State 171
		DEFAULT => -66
	},
	{#State 172
		DEFAULT => -57
	},
	{#State 173
		ACTIONS => {
			";" => 191
		}
	},
	{#State 174
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 192,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 175
		DEFAULT => -40
	},
	{#State 176
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 151,
			'enum_element' => 193
		}
	},
	{#State 177
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 156,
			'bitmap_element' => 194
		}
	},
	{#State 178
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 195,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 179
		DEFAULT => -48
	},
	{#State 180
		DEFAULT => -72,
		GOTOS => {
			'pointers' => 196
		}
	},
	{#State 181
		DEFAULT => -83,
		GOTOS => {
			'base_element' => 197,
			'property_list' => 159
		}
	},
	{#State 182
		ACTIONS => {
			";" => 198
		}
	},
	{#State 183
		ACTIONS => {
			'CONSTANT' => 58,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -91,
		GOTOS => {
			'identifier' => 60,
			'anytext' => 199,
			'text' => 61,
			'constant' => 57
		}
	},
	{#State 184
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"?" => 88,
			"<" => 84,
			";" => 200,
			"+" => 86,
			"~" => 85,
			"&" => 90,
			"{" => 89,
			"/" => 91,
			"=" => 92,
			"|" => 94,
			"(" => 93,
			"*" => 87,
			"." => 95,
			">" => 96
		}
	},
	{#State 185
		DEFAULT => -81
	},
	{#State 186
		ACTIONS => {
			"[" => 147
		},
		DEFAULT => -80,
		GOTOS => {
			'array_len' => 201
		}
	},
	{#State 187
		DEFAULT => -64
	},
	{#State 188
		ACTIONS => {
			";" => 202
		}
	},
	{#State 189
		DEFAULT => -63
	},
	{#State 190
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 75,
			";" => 203,
			'void' => 69,
			"unsigned" => 79,
			"[" => 20
		},
		DEFAULT => -83,
		GOTOS => {
			'existingtype' => 76,
			'bitmap' => 44,
			'usertype' => 71,
			'property_list' => 70,
			'identifier' => 72,
			'struct' => 49,
			'enum' => 52,
			'type' => 180,
			'union' => 54,
			'sign' => 73
		}
	},
	{#State 191
		DEFAULT => -75
	},
	{#State 192
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"<" => 84,
			"+" => 86,
			"~" => 85,
			"*" => 87,
			"?" => 88,
			"{" => 89,
			"&" => 90,
			"/" => 91,
			"=" => 92,
			"(" => 93,
			"|" => 94,
			"." => 95,
			">" => 96
		},
		DEFAULT => -47
	},
	{#State 193
		DEFAULT => -45
	},
	{#State 194
		DEFAULT => -53
	},
	{#State 195
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"<" => 84,
			"+" => 86,
			"~" => 85,
			"*" => 87,
			"?" => 88,
			"{" => 89,
			"&" => 90,
			"/" => 91,
			"=" => 92,
			"(" => 93,
			"|" => 94,
			"." => 95,
			">" => 96
		},
		DEFAULT => -56
	},
	{#State 196
		ACTIONS => {
			'IDENTIFIER' => 26,
			"*" => 144
		},
		GOTOS => {
			'identifier' => 204
		}
	},
	{#State 197
		DEFAULT => -79
	},
	{#State 198
		DEFAULT => -26
	},
	{#State 199
		ACTIONS => {
			"-" => 83,
			":" => 82,
			"?" => 88,
			"<" => 84,
			";" => 205,
			"+" => 86,
			"~" => 85,
			"&" => 90,
			"{" => 89,
			"/" => 91,
			"=" => 92,
			"|" => 94,
			"(" => 93,
			"*" => 87,
			"." => 95,
			">" => 96
		}
	},
	{#State 200
		DEFAULT => -24
	},
	{#State 201
		DEFAULT => -82
	},
	{#State 202
		DEFAULT => -62
	},
	{#State 203
		DEFAULT => -61
	},
	{#State 204
		ACTIONS => {
			"[" => 147
		},
		DEFAULT => -80,
		GOTOS => {
			'array_len' => 206
		}
	},
	{#State 205
		DEFAULT => -25
	},
	{#State 206
		DEFAULT => -71
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
		 'idl', 2,
sub
#line 24 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 8
		 'import', 3,
sub
#line 27 "pidl/idl.yp"
{{
			"TYPE" => "IMPORT",
			"PATHS" => $_[2],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 9
		 'include', 3,
sub
#line 34 "pidl/idl.yp"
{{
			"TYPE" => "INCLUDE",
			"PATHS" => $_[2],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 10
		 'importlib', 3,
sub
#line 41 "pidl/idl.yp"
{{
			"TYPE" => "IMPORTLIB",
			"PATHS" => $_[2],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 11
		 'commalist', 1,
sub
#line 50 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 12
		 'commalist', 3,
sub
#line 51 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 13
		 'coclass', 7,
sub
#line 55 "pidl/idl.yp"
{{
               "TYPE" => "COCLASS",
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "DATA" => $_[5],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 14
		 'interface_names', 0, undef
	],
	[#Rule 15
		 'interface_names', 4,
sub
#line 67 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 16
		 'interface', 7,
sub
#line 71 "pidl/idl.yp"
{{
               "TYPE" => "INTERFACE",
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "DATA" => $_[5],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 17
		 'cpp_quote', 4,
sub
#line 82 "pidl/idl.yp"
{{
		 "TYPE" => "CPP_QUOTE",
		 "FILE" => $_[0]->YYData->{FILE},
		 "LINE" => $_[0]->YYData->{LINE},
		 "DATA" => $_[3]
	}}
	],
	[#Rule 18
		 'definitions', 1,
sub
#line 91 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 19
		 'definitions', 2,
sub
#line 92 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
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
		 'definition', 1, undef
	],
	[#Rule 24
		 'const', 7,
sub
#line 100 "pidl/idl.yp"
{{
                     "TYPE"  => "CONST",
		     "DTYPE"  => $_[2],
			 "POINTERS" => $_[3],
		     "NAME"  => $_[4],
		     "VALUE" => $_[6],
		     "FILE" => $_[0]->YYData->{FILE},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 25
		 'const', 8,
sub
#line 110 "pidl/idl.yp"
{{
                     "TYPE"  => "CONST",
		     "DTYPE"  => $_[2],
			 "POINTERS" => $_[3],
		     "NAME"  => $_[4],
		     "ARRAY_LEN" => $_[5],
		     "VALUE" => $_[7],
		     "FILE" => $_[0]->YYData->{FILE},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 26
		 'function', 7,
sub
#line 124 "pidl/idl.yp"
{{
		"TYPE" => "FUNCTION",
		"NAME" => $_[3],
		"RETURN_TYPE" => $_[2],
		"PROPERTIES" => $_[1],
		"ELEMENTS" => $_[5],
		"FILE" => $_[0]->YYData->{FILE},
		"LINE" => $_[0]->YYData->{LINE},
	  }}
	],
	[#Rule 27
		 'typedef', 6,
sub
#line 136 "pidl/idl.yp"
{{
	             "TYPE" => "TYPEDEF",
                     "PROPERTIES" => $_[1],
		     "NAME" => $_[4],
		     "DATA" => $_[3],
		     "ARRAY_LEN" => $_[5],
		     "FILE" => $_[0]->YYData->{FILE},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 28
		 'usertype', 1, undef
	],
	[#Rule 29
		 'usertype', 1, undef
	],
	[#Rule 30
		 'usertype', 1, undef
	],
	[#Rule 31
		 'usertype', 1, undef
	],
	[#Rule 32
		 'typedecl', 2,
sub
#line 149 "pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 33
		 'sign', 1, undef
	],
	[#Rule 34
		 'sign', 1, undef
	],
	[#Rule 35
		 'existingtype', 2,
sub
#line 154 "pidl/idl.yp"
{ ($_[1]?$_[1]:"signed") ." $_[2]" }
	],
	[#Rule 36
		 'existingtype', 1, undef
	],
	[#Rule 37
		 'type', 1, undef
	],
	[#Rule 38
		 'type', 1, undef
	],
	[#Rule 39
		 'type', 1,
sub
#line 158 "pidl/idl.yp"
{ "void" }
	],
	[#Rule 40
		 'enum_body', 3,
sub
#line 160 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 41
		 'opt_enum_body', 0, undef
	],
	[#Rule 42
		 'opt_enum_body', 1, undef
	],
	[#Rule 43
		 'enum', 4,
sub
#line 163 "pidl/idl.yp"
{{
             "TYPE" => "ENUM",
			 "PROPERTIES" => $_[1],
			 "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 44
		 'enum_elements', 1,
sub
#line 172 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 45
		 'enum_elements', 3,
sub
#line 173 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 46
		 'enum_element', 1, undef
	],
	[#Rule 47
		 'enum_element', 3,
sub
#line 177 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 48
		 'bitmap_body', 3,
sub
#line 180 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 49
		 'opt_bitmap_body', 0, undef
	],
	[#Rule 50
		 'opt_bitmap_body', 1, undef
	],
	[#Rule 51
		 'bitmap', 4,
sub
#line 183 "pidl/idl.yp"
{{
             "TYPE" => "BITMAP",
		     "PROPERTIES" => $_[1],
			 "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 52
		 'bitmap_elements', 1,
sub
#line 192 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 53
		 'bitmap_elements', 3,
sub
#line 193 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 54
		 'opt_bitmap_elements', 0, undef
	],
	[#Rule 55
		 'opt_bitmap_elements', 1, undef
	],
	[#Rule 56
		 'bitmap_element', 3,
sub
#line 198 "pidl/idl.yp"
{ "$_[1] ( $_[3] )" }
	],
	[#Rule 57
		 'struct_body', 3,
sub
#line 201 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 58
		 'opt_struct_body', 0, undef
	],
	[#Rule 59
		 'opt_struct_body', 1, undef
	],
	[#Rule 60
		 'struct', 4,
sub
#line 205 "pidl/idl.yp"
{{
             "TYPE" => "STRUCT",
			 "PROPERTIES" => $_[1],
			 "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 61
		 'empty_element', 2,
sub
#line 214 "pidl/idl.yp"
{{
		 "NAME" => "",
		 "TYPE" => "EMPTY",
		 "PROPERTIES" => $_[1],
		 "POINTERS" => 0,
		 "ARRAY_LEN" => [],
		 "FILE" => $_[0]->YYData->{FILE},
		 "LINE" => $_[0]->YYData->{LINE},
	 }}
	],
	[#Rule 62
		 'base_or_empty', 2, undef
	],
	[#Rule 63
		 'base_or_empty', 1, undef
	],
	[#Rule 64
		 'optional_base_element', 2,
sub
#line 228 "pidl/idl.yp"
{ $_[2]->{PROPERTIES} = FlattenHash([$_[1],$_[2]->{PROPERTIES}]); $_[2] }
	],
	[#Rule 65
		 'union_elements', 0, undef
	],
	[#Rule 66
		 'union_elements', 2,
sub
#line 233 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 67
		 'union_body', 3,
sub
#line 236 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 68
		 'opt_union_body', 0, undef
	],
	[#Rule 69
		 'opt_union_body', 1, undef
	],
	[#Rule 70
		 'union', 4,
sub
#line 240 "pidl/idl.yp"
{{
             "TYPE" => "UNION",
			 "PROPERTIES" => $_[1],
		     "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 71
		 'base_element', 5,
sub
#line 249 "pidl/idl.yp"
{{
			   "NAME" => $_[4],
			   "TYPE" => $_[2],
			   "PROPERTIES" => $_[1],
			   "POINTERS" => $_[3],
			   "ARRAY_LEN" => $_[5],
		       "FILE" => $_[0]->YYData->{FILE},
		       "LINE" => $_[0]->YYData->{LINE},
              }}
	],
	[#Rule 72
		 'pointers', 0,
sub
#line 263 "pidl/idl.yp"
{ 0 }
	],
	[#Rule 73
		 'pointers', 2,
sub
#line 264 "pidl/idl.yp"
{ $_[1]+1 }
	],
	[#Rule 74
		 'element_list1', 0,
sub
#line 268 "pidl/idl.yp"
{ [] }
	],
	[#Rule 75
		 'element_list1', 3,
sub
#line 269 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 76
		 'element_list2', 0, undef
	],
	[#Rule 77
		 'element_list2', 1, undef
	],
	[#Rule 78
		 'element_list2', 1,
sub
#line 275 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 79
		 'element_list2', 3,
sub
#line 276 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 80
		 'array_len', 0, undef
	],
	[#Rule 81
		 'array_len', 3,
sub
#line 281 "pidl/idl.yp"
{ push(@{$_[3]}, "*"); $_[3] }
	],
	[#Rule 82
		 'array_len', 4,
sub
#line 282 "pidl/idl.yp"
{ push(@{$_[4]}, "$_[2]"); $_[4] }
	],
	[#Rule 83
		 'property_list', 0, undef
	],
	[#Rule 84
		 'property_list', 4,
sub
#line 288 "pidl/idl.yp"
{ FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 85
		 'properties', 1,
sub
#line 291 "pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 86
		 'properties', 3,
sub
#line 292 "pidl/idl.yp"
{ FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 87
		 'property', 1,
sub
#line 295 "pidl/idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 88
		 'property', 4,
sub
#line 296 "pidl/idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 89
		 'commalisttext', 1, undef
	],
	[#Rule 90
		 'commalisttext', 3,
sub
#line 301 "pidl/idl.yp"
{ "$_[1],$_[3]" }
	],
	[#Rule 91
		 'anytext', 0,
sub
#line 305 "pidl/idl.yp"
{ "" }
	],
	[#Rule 92
		 'anytext', 1, undef
	],
	[#Rule 93
		 'anytext', 1, undef
	],
	[#Rule 94
		 'anytext', 1, undef
	],
	[#Rule 95
		 'anytext', 3,
sub
#line 307 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 96
		 'anytext', 3,
sub
#line 308 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 97
		 'anytext', 3,
sub
#line 309 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 98
		 'anytext', 3,
sub
#line 310 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 99
		 'anytext', 3,
sub
#line 311 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 100
		 'anytext', 3,
sub
#line 312 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 101
		 'anytext', 3,
sub
#line 313 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 102
		 'anytext', 3,
sub
#line 314 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 103
		 'anytext', 3,
sub
#line 315 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 104
		 'anytext', 3,
sub
#line 316 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 105
		 'anytext', 3,
sub
#line 317 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 106
		 'anytext', 3,
sub
#line 318 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 107
		 'anytext', 3,
sub
#line 319 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 108
		 'anytext', 5,
sub
#line 320 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 109
		 'anytext', 5,
sub
#line 321 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 110
		 'identifier', 1, undef
	],
	[#Rule 111
		 'optional_identifier', 1, undef
	],
	[#Rule 112
		 'optional_identifier', 0, undef
	],
	[#Rule 113
		 'constant', 1, undef
	],
	[#Rule 114
		 'text', 1,
sub
#line 335 "pidl/idl.yp"
{ "\"$_[1]\"" }
	],
	[#Rule 115
		 'optional_semicolon', 0, undef
	],
	[#Rule 116
		 'optional_semicolon', 1, undef
	]
],
                                  @_);
    bless($self,$class);
}

#line 346 "pidl/idl.yp"


use Parse::Pidl qw(error);

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
	}
	# this removes any undefined elements from the array
	@{$v} = grep { defined $_ } @{$v};
    } elsif (ref($v) eq "HASH") {
	foreach my $x (keys %{$v}) {
	    CleanData($v->{$x});
	    if (!defined $v->{$x}) { delete($v->{$x}); next; }
	}
    }
	return $v;
}

sub _Error {
    if (exists $_[0]->YYData->{ERRMSG}) {
		error($_[0]->YYData, $_[0]->YYData->{ERRMSG});
		delete $_[0]->YYData->{ERRMSG};
		return;
	}
	my $last_token = $_[0]->YYData->{LAST_TOKEN};

	error($_[0]->YYData, "Syntax error near '$last_token'");
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
				$parser->YYData->{FILE} = $2;
				goto again;
			}
			if (s/^\#line (\d+) \"(.*?)\"( \d+|)//) {
				$parser->YYData->{LINE} = $1-1;
				$parser->YYData->{FILE} = $2;
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
			    /^(coclass|interface|const|typedef|union|cpp_quote
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

    $self->YYData->{FILE} = $filename;
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
	my $includes = join('',map { " -I$_" } @$incdirs);
	my $data = `$cpp -D__PIDL__$includes -xc $filename`;
	$/ = $saved_delim;

	return parse_string($data, $filename);
}

1;
