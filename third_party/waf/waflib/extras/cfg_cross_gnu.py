#!/usr/bin/python
# -*- coding: utf-8 vi:ts=4:noexpandtab
# Tool to provide dedicated variables for cross-compilation

__author__ = __maintainer__ = "Jérôme Carretero <cJ-waf@zougloub.eu>"
__copyright__ = "Jérôme Carretero, 2014"

"""

This tool allows to use environment variables to define cross-compilation things,
mostly used when you use build variants.

The variables are obtained from the environment in 3 ways:

1. By defining CHOST, they can be derived as ${CHOST}-${TOOL}
2. By defining HOST_x
3. By defining ${CHOST//-/_}_x

Usage:

- In your build script::

    def configure(cfg):
      ...
      conf.load('c_cross_gnu')
      for variant in x_variants:
        conf.xcheck_host()
        conf.xcheck_host_var('POUET')
        ...

      ...

- Then::

    CHOST=arm-hardfloat-linux-gnueabi waf configure

    env arm-hardfloat-linux-gnueabi-CC="clang -..." waf configure

    CFLAGS=... CHOST=arm-hardfloat-linux-gnueabi HOST_CFLAGS=-g waf configure

    HOST_CC="clang -..." waf configure

"""

import os
from waflib import Utils, Configure

try:
	from shlex import quote
except ImportError:
	from pipes import quote

def get_chost_stuff(conf):
	"""
	Get the CHOST environment variable contents
	"""
	chost = None
	chost_envar = None
	if conf.env.CHOST:
		chost = conf.env.CHOST[0]
		chost_envar = chost.replace('-', '_')
	return chost, chost_envar


@Configure.conf
def xcheck_envar(conf, name, wafname=None, cross=False):
	wafname = wafname or name
	envar = os.environ.get(name, None)

	if envar is None:
		return

	value = Utils.to_list(envar) if envar != '' else [envar]

	conf.env[wafname] = value
	if cross:
		pretty = 'cross-compilation %s' % wafname
	else:
		pretty = wafname
	conf.msg('Will use %s' % pretty,
	 " ".join(quote(x) for x in value))

@Configure.conf
def xcheck_host_prog(conf, name, tool, wafname=None):
	wafname = wafname or name

	chost, chost_envar = get_chost_stuff(conf)

	specific = None
	if chost:
		specific = os.environ.get('%s_%s' % (chost_envar, name), None)

	if specific:
		value = Utils.to_list(specific)
		conf.env[wafname] += value
		conf.msg('Will use cross-compilation %s from %s_%s' \
		 % (name, chost_envar, name),
		 " ".join(quote(x) for x in value))
		return
	else:
		envar = os.environ.get('HOST_%s' % name, None)
		if envar is not None:
			value = Utils.to_list(envar)
			conf.env[wafname] = value
			conf.msg('Will use cross-compilation %s from HOST_%s' \
			 % (name, name),
			 " ".join(quote(x) for x in value))
			return

	if conf.env[wafname]:
		return

	value = None
	if chost:
		value = '%s-%s' % (chost, tool)

	if value:
		conf.env[wafname] = value
		conf.msg('Will use cross-compilation %s from CHOST' \
		 % wafname, value)

@Configure.conf
def xcheck_host_envar(conf, name, wafname=None):
	wafname = wafname or name

	chost, chost_envar = get_chost_stuff(conf)

	specific = None
	if chost:
		specific = os.environ.get('%s_%s' % (chost_envar, name), None)

	if specific:
		value = Utils.to_list(specific)
		conf.env[wafname] += value
		conf.msg('Will use cross-compilation %s from %s_%s' \
		 % (name, chost_envar, name),
		 " ".join(quote(x) for x in value))
		return


	envar = os.environ.get('HOST_%s' % name, None)
	if envar is None:
		return

	value = Utils.to_list(envar) if envar != '' else [envar]

	conf.env[wafname] = value
	conf.msg('Will use cross-compilation %s from HOST_%s' \
	 % (name, name),
	 " ".join(quote(x) for x in value))


@Configure.conf
def xcheck_host(conf):
	conf.xcheck_envar('CHOST', cross=True)
	conf.xcheck_host_prog('CC', 'gcc')
	conf.xcheck_host_prog('CXX', 'g++')
	conf.xcheck_host_prog('LINK_CC', 'gcc')
	conf.xcheck_host_prog('LINK_CXX', 'g++')
	conf.xcheck_host_prog('AR', 'ar')
	conf.xcheck_host_prog('AS', 'as')
	conf.xcheck_host_prog('LD', 'ld')
	conf.xcheck_host_envar('CFLAGS')
	conf.xcheck_host_envar('CXXFLAGS')
	conf.xcheck_host_envar('LDFLAGS', 'LINKFLAGS')
	conf.xcheck_host_envar('LIB')
	conf.xcheck_host_envar('PKG_CONFIG_LIBDIR')
	conf.xcheck_host_envar('PKG_CONFIG_PATH')

	if not conf.env.env:
		conf.env.env = {}
		conf.env.env.update(os.environ)
	if conf.env.PKG_CONFIG_LIBDIR:
		conf.env.env['PKG_CONFIG_LIBDIR'] = conf.env.PKG_CONFIG_LIBDIR[0]
	if conf.env.PKG_CONFIG_PATH:
		conf.env.env['PKG_CONFIG_PATH'] = conf.env.PKG_CONFIG_PATH[0]
