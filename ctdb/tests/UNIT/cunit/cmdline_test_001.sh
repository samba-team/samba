#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

ok_null
unit_test cmdline_test 1

ok <<EOF
Command 'nofunc' has no implementation function
Command 'nohelp' has no help msg
Command 'really really long command with lots of words' is too long (85)
Command 'longhelp' help too long (90)
EOF
unit_test cmdline_test 2

ok <<EOF
Option has no long name
Option 'debug' has unsupported type
Option 'debug' has invalid arg
EOF
unit_test cmdline_test 3

ok <<EOF
Usage: test4 [<options>] <command> [<args>]

Help Options:
  -h, --help                              Show this help message

Options:
  -c, --count=INT                         Option help of length thirty.
  -v, --value=Value help of length 23     Short description

Commands:
  A really really long command <a long arguments message>     This is a really long help message
  short command <short arg msg>                               short msg for short command
Usage: test4 [-h] [-h|--help] [-c|--count=INT]
        [-v|--value=Value help of length 23] <command> [<args>]

  short command <short arg msg>     short msg for short command
EOF
unit_test cmdline_test 4

ok <<EOF
Usage: test5 [<options>] <command> [<args>]

Help Options:
  -h, --help     Show this help message

Action Commands:
  action one      action one help
  action two      action two help
Usage: test5 [<options>] <command> [<args>]

Help Options:
  -h, --help     Show this help message

Action Commands:
  action one      action one help
  action two      action two help
Usage: test5 [<options>] <command> [<args>]

Help Options:
  -h, --help     Show this help message

Action Commands:
  action one      action one help
  action two      action two help
EOF
unit_test cmdline_test 5

ok <<EOF
arg1
EOF
unit_test cmdline_test 6

ok <<EOF
Usage: test7 [<options>] <command> [<args>]

Help Options:
  -h, --help     Show this help message

Basic Commands:
  cmd1      command one help
  cmd2      command two help

Advanced Commands:
  cmd3      command three help
  cmd4      command four help

Ultimate Commands:
  cmd5      command five help
  cmd6      command six help

one
three
six
EOF
unit_test cmdline_test 7
