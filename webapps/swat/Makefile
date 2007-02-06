################################################################################
# REQUIRED SETTINGS
################################################################################

#
# Path to the folder of your qooxdoo distribution.
# Can either be
# a) a path relative to the location of this Makefile (preferred) or
# b) an absolute path starting at the root of your file system
# Example: If you put the skeleton folder next to the qooxdoo SDK folder,
# you can use the following relative path:
# QOOXDOO_PATH = ../qooxdoo-0.6.5-sdk
#
QOOXDOO_PATH = ../qooxdoo-0.6.5-sdk

#
# Similar to above, but from the webserver point of view.
# Starting point is now the application HTML file of the source folder
# (source/index.html by default). In most cases just prepend a "../" to
# QOOXDOO_PATH from above.
# Example: QOOXDOO_URI = ../../qooxdoo-0.6.5-sdk
#
QOOXDOO_URI = ../../qooxdoo-0.6.5-sdk






################################################################################
# BASIC SETTINGS
################################################################################

#
# Full namespace of your application
#
APPLICATION_NAMESPACE = swat

#
# Titles used in your API viewer and during the build process
#
APPLICATION_MAKE_TITLE = SWAT
APPLICATION_API_TITLE = Swat

#
# Additional static files of your application (space separated list)
#
APPLICATION_FILES = index.html

#
# Locales to build (space separated list)
# To set a specific locale like "en_US" the generic locale "en" has to be added as well
# Example: APPLICATION_LOCALES = en en_US de de_DE es
#
APPLICATION_LOCALES =






################################################################################
# ADVANCED SETTINGS
################################################################################

#
# Please take a look at $(QOOXDOO_PATH)/frontend/framework/tool/make/application.mk
# for an overview of available options
#

include $(QOOXDOO_PATH)/frontend/framework/tool/make/apiviewer.mk

APPLICATION_CLASSNAME = $(APPLICATION_NAMESPACE).main.Main
APPLICATION_LINEBREAKS_BUILD = true
APPLICATION_LINEBREAKS_SOURCE = true
APPLICATION_OPTIMIZE_STRINGS = false
APPLICATION_OPTIMIZE_VARIABLES = false
APPLICATION_ADDITIONAL_CLASS_PATH = \
  --class-path $(APIVIEWER_PATH)/source/class
APPLICATION_ADDITIONAL_RESOURCE = \
  --resource-input $(APIVIEWER_PATH)/source/resource \
  --resource-output $(APPLICATION_BUILD_PATH)/resource/apiviewer \
  --define-runtime-setting apiviewer.resourceUri:$(APPLICATION_PAGE_TO_TOPLEVEL)/resource/apiviewer
APPLICATION_RESOURCE_FILTER = true
APPLICATION_COMPLETE_SOURCE = false


################################################################################
# INCLUDE CORE
################################################################################

ifneq ($(QOOXDOO_PATH),PLEASE_DEFINE_QOOXDOO_PATH)
	include $(QOOXDOO_PATH)/frontend/framework/tool/make/targets.mk
	include $(QOOXDOO_PATH)/frontend/framework/tool/make/application.mk
endif

error:
	@echo "  * Please configure QOOXDOO_PATH"
