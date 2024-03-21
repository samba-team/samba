# This file can be sourced using
#
# source buildtools/devel_env.sh

# Setup python path for lsp server
echo "Old PYTHONPATH: ${PYTHONPATH}"
PYTHONPATH="$(pwd)/third_party/waf:$(pwd)/bin/python:$(pwd)/python:$(pwd)/selftest:${PYTHONPATH}"
export PYTHONPATH
echo "New PYTHONPATH: ${PYTHONPATH}"
