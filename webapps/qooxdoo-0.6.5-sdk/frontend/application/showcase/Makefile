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

################################################################################
# BASIC SETTINGS
################################################################################

#
# Location of your qooxdoo distribution
# Could be relative from this location or absolute
#
QOOXDOO_PATH = ../../..

#
# The same as above, but from the webserver point of view
# Starting point is the application HTML file of the source folder.
# In most cases just add a "/.." compared to above
#
QOOXDOO_URI = ../../../..

#
# Namespace of your application e.g. custom
#
APPLICATION_NAMESPACE = showcase

#
# Titles used in your API viewer and during the build process
#
APPLICATION_MAKE_TITLE = SHOWCASE
APPLICATION_API_TITLE = ShowCase

#
# Additional files (space separated list)
#
APPLICATION_FILES = index.html

#
# Locales to include
#
APPLICATION_LOCALES = de de_DE en en_US es es_ES fr fr_FR

#
# full locales used for the online version
#
#APPLICATION_LOCALES = ar de de_AT de_DE en en_US es es_ES fr fr_FR it ru sv tr zh



################################################################################
# ADVANCED SETTINGS
################################################################################

#
# Enable resource filtering in API viewer
#
APPLICATION_RESOURCE_FILTER = true

#
# We don't need the full source code
#
APPLICATION_COMPLETE_SOURCE = false

#
# Disable line breaks
#
APPLICATION_LINEBREAKS_BUILD = false
APPLICATION_LINEBREAKS_SOURCE = false

#
# qooxdoo.org sync
#
APPLICATION_PUBLISH_PATH = root@qooxdoo.org:/var/www/qooxdoo/demo/$(FRAMEWORK_VERSION)/$(APPLICATION_NAMESPACE)





################################################################################
# INCLUDE CORE
################################################################################

ifneq ($(QOOXDOO_PATH),PLEASE_DEFINE_QOOXDOO_PATH)
	include $(QOOXDOO_PATH)/frontend/framework/tool/make/targets.mk
	include $(QOOXDOO_PATH)/frontend/framework/tool/make/application.mk
endif

error:
	@echo "  * Please configure QOOXDOO_PATH"
