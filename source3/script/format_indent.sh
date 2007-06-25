#!/bin/sh

# -npro	Do no read the '.indent.pro' files.
# -l80	Set maximum line length for non-comment lines to 80.
# -bad 	Force blank lines after the declarations.
# -bap	Force blank lines after procedure bodies.
# -bbb	Force blank lines before block comments.
# -br	Put braces on line with if, etc.
# -ce	Cuddle else and preceeding ‘}’.
# -ut	Use tabs.
# -ts8	Set tab size to 8 spaces
# -i8	Set indentation level to 8 spaces.
# -di1	Put variables in column 1.
# -brs	Put braces on struct declaration line.
# -npsl	Put the type of a procedure on the same line as its name.
# -npcs	Do not put space after the function in function calls.
# -nprs	Do not put a space after every ’(’ and before every ’)’.
# -bbo	Prefer to break long lines before boolean operators.
# -hnl	Prefer to break long lines at the position of newlines in the input.

indent -npro -l80 -bad -bap -bbb -br -ce -ut -ts8 -i8 -di1 -brs -npsl -npcs -nprs -bbo -hnl "$@"
