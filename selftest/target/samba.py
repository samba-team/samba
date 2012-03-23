#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2012 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

import os
import sys
import warnings

from selftest.target import Target

def bindir_path(binary_mapping, bindir, path):
    """Find the executable to use.

    :param binary_mapping: Dictionary mapping binary names
    :param bindir: Directory with binaries
    :param path: Name of the executable to run
    :return: Full path to the executable to run
    """
    path = binary_mapping.get(path, path)
    valpath = os.path.join(bindir, path)
    if os.path.isfile(valpath):
        return valpath
    return path
