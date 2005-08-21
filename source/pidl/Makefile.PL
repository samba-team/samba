use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'	=> 'Parse::Pidl',
    'VERSION_FROM' => 'Parse/Pidl.pm',
	'EXE_FILES' => [ 'pidl' ],
	'PMLIBDIRS' => [ 'Parse' ],
	'C' => [],
	'test' => { 'TESTS' => 'tests/*.pl' }
);

sub MY::postamble {
<<'EOT';
Parse/Pidl/IDL.pm :: idl.yp
	yapp -s -m 'Parse::Pidl::IDL' -o 'Parse/Pidl/IDL.pm' idl.yp
EOT
}
