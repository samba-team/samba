# This file can be sourced using
#
# source buildtools/devel_env.sh

# Setup python path for lsp server
PYTHONPATH="$(pwd)/third_party/waf:$(pwd)/python:$(pwd)/bin/python:$(pwd)/selftest:${PYTHONPATH}"
export PYTHONPATH
