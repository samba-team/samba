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
import logging
import argparse
from config import DISTS, VAGRANTFILE, OUT

logging.basicConfig(level='INFO')
log = logging.getLogger(__file__)


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


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=('Render templates with samba dependencies '
                     'to bootstrap multiple distributions.'))

    parser.add_argument(
        '-r', '--render', action='store_true', help='Render templates')

    args = parser.parse_args()

    if args.render:
        render(DISTS)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
