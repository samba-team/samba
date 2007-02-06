#!/usr/bin/env python
################################################################################
#
#  qooxdoo - the new era of web development
#
#  http://qooxdoo.org
#
#  Copyright:
#    2006-2007 1&1 Internet AG, Germany, http://www.1and1.org
#
#  License:
#    LGPL: http://www.gnu.org/licenses/lgpl.html
#    EPL: http://www.eclipse.org/org/documents/epl-v10.php
#    See the LICENSE file in the project's top-level directory for details.
#
#  Authors:
#    * Fabian Jakobs (fjakobs)
#
################################################################################

import sys

"""
checks whether the locale string is correct.
"""

errormsg = """
****************************************************************************
  ERROR
----------------------------------------------------------------------------
  The locale '%(locale)s' is defined in APPLICATION_LOCALES, but not '%(lang)s'!

  If a locale with a territory code is set ('%(locale)s'), the corresponding
  locale without territory code must be included as well ('%(lang)s').
  
  Please add '%(lang)s' to APPLICATION_LOCALES in your Makefile.
****************************************************************************
"""

def main():
	line = sys.stdin.read()
	locales = line.split()
	for locale in locales:
		if locale.find("_") >= 0:
			lang = locale.split("_")[0]
			if not lang in locales:
				print errormsg % {"lang": lang, "locale": locale}
				sys.exit(1)
	sys.exit(0)
	
if __name__ == "__main__":
	main()