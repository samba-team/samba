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
#    * Sebastian Werner (wpbasti)
#    * Andreas Ecker (ecker)
#    * Fabian Jakobs (fjakobs)
#
################################################################################

APPLICATIONS = apiviewer feedreader sample showcase webmail

source:
	@for APPLICATION in $(APPLICATIONS); do $(MAKE) -s -C $$APPLICATION source || exit 1; done

build:
	@for APPLICATION in $(APPLICATIONS); do $(MAKE) -s -C $$APPLICATION build || exit 1; done
	
api:
	@for APPLICATION in $(APPLICATIONS); do $(MAKE) -s -C $$APPLICATION api || exit 1; done
	
all:
	@for APPLICATION in $(APPLICATIONS); do $(MAKE) -s -C $$APPLICATION all || exit 1; done

publish:
	@for APPLICATION in $(APPLICATIONS); do $(MAKE) -s -C $$APPLICATION publish || exit 1; done

fix:
	@for APPLICATION in $(APPLICATIONS); do $(MAKE) -s -C $$APPLICATION fix || exit 1; done

pretty:
	@for APPLICATION in $(APPLICATIONS); do $(MAKE) -s -C $$APPLICATION pretty || exit 1;	done	

clean:
	@for APPLICATION in $(APPLICATIONS); do $(MAKE) -s -C $$APPLICATION clean || exit 1; done

distclean:
	@for APPLICATION in $(APPLICATIONS); do $(MAKE) -s -C $$APPLICATION distclean || exit 1; done

locales:
	@for APPLICATION in $(APPLICATIONS); do $(MAKE) -s -C $$APPLICATION locales || exit 1; done
	