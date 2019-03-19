#!/usr/bin/env python3

# Copyright (C) Catalyst.Net Ltd 2019
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Manage dependencies and bootstrap environments for Samba.

CLI script to render bootstrap.sh/Dockerfile/Vagrantfile.

Author: Joe Guo <joeg@catalyst.net.nz>
"""

import io
import os
import hashlib
import logging
import argparse
from config import DISTS, VAGRANTFILE, OUT

HERE = os.path.abspath(os.path.dirname(__file__))
SHA1SUM_FILE_PATH = os.path.join(HERE, 'sha1sum.txt')
README_FILE_PATH = os.path.join(HERE, 'READMD.md')

logging.basicConfig(level='INFO')
log = logging.getLogger(__file__)


def get_files(path):
    """Get all files recursively in path as a list"""
    filepaths = []
    for root, dirnames, filenames in os.walk(path):
        for filename in filenames:
            filepath = os.path.join(root, filename)
            filepaths.append(filepath)
    return filepaths


def get_sha1sum(debug=False):
    """Get sha1sum for dists + .gitlab-ci.yml"""
    filepaths = get_files(HERE)
    m = hashlib.sha1()
    i = 0
    for filepath in sorted(list(filepaths)):
        _filepath = os.path.relpath(filepath)
        i += 1
        if filepath == SHA1SUM_FILE_PATH:
            d = "skip                                    "
            if debug:
                print("%s: %s: %s" % (i, d, _filepath))
            continue
        if filepath == README_FILE_PATH:
            d = "skip                                    "
            if debug:
                print("%s: %s: %s" % (i, d, _filepath))
            continue
        if filepath.endswith('.pyc'):
            d = "skip                                    "
            if debug:
                print("%s: %s: %s" % (i, d, _filepath))
            continue
        with io.open(filepath, mode='rb') as _file:
            _bytes = _file.read()

            m1 = hashlib.sha1()
            m1.update(_bytes)
            d = m1.hexdigest()
            if debug:
                print("%s: %s: %s" % (i, d, _filepath))

            m.update(_bytes)
    return m.hexdigest()


def render(dists):
    """Render files for all dists"""
    for dist, config in dists.items():
        home = config['home']
        os.makedirs(home, exist_ok=True)
        for key in ['bootstrap.sh', 'locale.sh', 'packages.yml', 'Dockerfile']:
            path = os.path.join(home, key)
            log.info('%s: render "%s" to %s', dist, key, path)
            with io.open(path, mode='wt', encoding='utf8') as fp:
                fp.write(config[key])
            if path.endswith('.sh'):
                os.chmod(path, 0o755)

    key = 'Vagrantfile'
    path = os.path.join(OUT, key)
    log.info('%s: render "%s" to %s', dist, key, path)
    with io.open(path, mode='wt', encoding='utf8') as fp:
        fp.write(VAGRANTFILE)

    # always calc sha1sum after render
    sha1sum = get_sha1sum()
    log.info('write sha1sum to %s: %s', SHA1SUM_FILE_PATH, sha1sum)
    with io.open(SHA1SUM_FILE_PATH, mode='wt', encoding='utf8') as fp:
        fp.write(sha1sum + "\n")


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=('Render templates with samba dependencies '
                     'to bootstrap multiple distributions.'))

    parser.add_argument(
        '-r', '--render', action='store_true', help='Render templates')

    parser.add_argument(
        '-s', '--sha1sum', action='store_true', help='Print sha1sum')
    parser.add_argument(
        '-d', '--debug', action='store_true', help='Debug sha1sum')

    args = parser.parse_args()
    need_help = True

    if args.render:
        render(DISTS)
        need_help = False
    if args.sha1sum:
        # we will use the output to check sha1sum in ci
        print(get_sha1sum(args.debug))
        need_help = False
    if need_help:
        parser.print_help()


if __name__ == '__main__':
    main()
