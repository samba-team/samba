#
# samba-gpupdate enhanced logging
#
# Copyright (C) 2019-2020 BaseALT Ltd.
# Copyright (C) David Mulder <dmulder@samba.org> 2022
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

import json
import datetime
import logging
import gettext
import random
import sys

logger = logging.getLogger()
def logger_init(name, log_level):
    logger = logging.getLogger(name)
    logger.addHandler(logging.StreamHandler(sys.stdout))
    logger.setLevel(logging.CRITICAL)
    if log_level == 1:
        logger.setLevel(logging.ERROR)
    elif log_level == 2:
        logger.setLevel(logging.WARNING)
    elif log_level == 3:
        logger.setLevel(logging.INFO)
    elif log_level >= 4:
        logger.setLevel(logging.DEBUG)

class slogm(object):
    '''
    Structured log message class
    '''
    def __init__(self, message, kwargs=None):
        if kwargs is None:
            kwargs = {}
        self.message = message
        self.kwargs = kwargs
        if not isinstance(self.kwargs, dict):
            self.kwargs = { 'val': self.kwargs }

    def __str__(self):
        now = str(datetime.datetime.now().isoformat(sep=' ', timespec='milliseconds'))
        args = dict()
        args.update(self.kwargs)
        result = '{}|{} | {}'.format(now, self.message, args)

        return result

def message_with_code(mtype, message):
    random.seed(message)
    code = random.randint(0, 99999)
    return '[' + mtype + str(code).rjust(5, '0') + ']| ' + \
           gettext.gettext(message)

class log(object):
    @staticmethod
    def info(message, data=None):
        if data is None:
            data = {}
        msg = message_with_code('I', message)
        logger.info(slogm(msg, data))
        return msg

    @staticmethod
    def warning(message, data=None):
        if data is None:
            data = {}
        msg = message_with_code('W', message)
        logger.warning(slogm(msg, data))
        return msg

    @staticmethod
    def warn(message, data=None):
        if data is None:
            data = {}
        return log.warning(message, data)

    @staticmethod
    def error(message, data=None):
        if data is None:
            data = {}
        msg = message_with_code('E', message)
        logger.error(slogm(msg, data))
        return msg

    @staticmethod
    def fatal(message, data=None):
        if data is None:
            data = {}
        msg = message_with_code('F', message)
        logger.fatal(slogm(msg, data))
        return msg

    @staticmethod
    def debug(message, data=None):
        if data is None:
            data = {}
        msg = message_with_code('D', message)
        logger.debug(slogm(msg, data))
        return msg
