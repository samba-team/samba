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

warning:
	@echo
	@echo "****************************************************************************"
	@echo "  WARNING"
	@echo "----------------------------------------------------------------------------"
	@echo "  This file 'project.mk' has been renamed to 'application.mk'." 
	@echo "  between release 0.6.4 and 0.6.5. You have to migrate manually:"
	@echo "  Please replace all occurrences of 'project.mk' in your Makefiles with"
	@echo "  'application.mk'."
	@echo "****************************************************************************"



source: warning
build: warning
api: warning
all: warning

include $(QOOXDOO_PATH)/frontend/framework/tool/make/application.mk
