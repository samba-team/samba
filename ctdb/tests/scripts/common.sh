# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Common variables and functions for all CTDB tests.

# Print a message and exit.
die ()
{
    echo "$1" >&2 ; exit ${2:-1}
}
