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

CLI script to build/tag/push docker images.

Author: Joe Guo <joeg@catalyst.net.nz>
"""

import io
import os
import argparse
import logging
from os import environ
from datetime import date
from multiprocessing import Pool
from subprocess import check_call
from config import DISTS

logging.basicConfig(level='INFO')
log = logging.getLogger(__file__)

PREFIX_DEFAULT = environ.get('SAMBA_DOCKER_IMAGE_NAME_PREFIX', '')


def run(cmd, cwd=None):
    # check_call will print to stdout while check_output will not
    log.info('run cmd: %s', cmd)
    check_call(cmd.split(), cwd=cwd)


def docker_image_name(prefix='', dist='ubuntu1604', tag='latest'):
    """
    Format docker image name.

    Example output:
    latest: samba-ubuntu1604:latest
    date: samba-ubuntu1604:20190210
    docker hub: samba-team/samba-ubuntu:latest
    gitlab: registry.gitlab.com/samba-team/samba/samba-ubuntu1604:20190401
    """
    assert dist, 'dist name is required'
    if prefix:
        prefix = prefix + '/'

    name = 'samba-' + dist

    # if empty, use date as tag
    if not tag:
        tag = date.today().strftime('%Y%m%d')
    tag = ':' + tag

    return prefix + name + tag


def docker_build(dist_config):
    cmd = 'docker build --rm -t {} {}'.format(
        docker_image_name(dist=dist_config['name']),
        dist_config['home'])
    run(cmd)


class Docker(object):

    def __init__(self, dists):
        self.dists = dists

    def build(self):
        """Build images in process pool"""
        with Pool(len(self.dists)) as pool:
            pool.map(docker_build, self.dists.values())
        run('docker image prune --force')

    def tag(self, prefix):
        """Tag images with prefixed and both a latest and date tag"""
        for dist in self.dists:
            name = docker_image_name(dist=dist)
            # wil use date for empty tag
            for tag in ['', 'latest']:
                prefixed = docker_image_name(prefix=prefix,
                                             dist=dist,
                                             tag=tag)
                cmd = 'docker tag {} {}'.format(name, prefixed)
                run(cmd)
        run('docker image prune --force')

    def push(self, prefix):
        """Push prefixed docker images to registry with latest and date tag"""
        for dist in self.dists:
            # wil use date for empty tag
            for tag in ['', 'latest']:
                prefixed = docker_image_name(prefix=prefix,
                                             dist=dist,
                                             tag=tag)
                cmd = 'docker push {}'.format(prefixed)
                run(cmd)


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='Render samba docker images for multiple distributions.')

    parser.add_argument(
        '-b', '--build', action='store_true',
        help='Build docker images')

    parser.add_argument(
        '-t', '--tag', action='store_true',
        help='Tag docker images with --prefix')

    parser.add_argument(
        '-p', '--push', action='store_true',
        help='Push docker images with --prefix, requires docker login')

    parser.add_argument(
        '--prefix', default=PREFIX_DEFAULT,
        help=('Docker image name prefix, used with --tag and --push. '
              'defaults to $SAMBA_DOCKER_IMAGE_NAME_PREFIX when defined. '
              'Example: registry.gitlab.com/samba-team/samba'))

    args = parser.parse_args()
    if args.tag or args.push:
        if not args.prefix:
            parser.error('--prefix must be provided with --tag and --push')

    docker = Docker(DISTS)

    need_help = True

    if args.build:
        need_help = False
        docker.build()

    if args.tag or args.push:
        need_help = False
        docker.tag(args.prefix)

    if args.push:
        need_help = False
        docker.push(args.prefix)

    if need_help:
        parser.print_help()


if __name__ == '__main__':
    main()
