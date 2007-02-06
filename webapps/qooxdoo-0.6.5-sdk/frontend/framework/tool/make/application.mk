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

###################################################################################
# INCLUDE EXTERNAL MAKEFILES
###################################################################################

include $(QOOXDOO_PATH)/frontend/framework/tool/make/framework.mk
include $(QOOXDOO_PATH)/frontend/framework/tool/make/apiviewer.mk



####################################################################################
# BASIC SETTINGS
####################################################################################

#
# Location of your qooxdoo distribution
# Could be relative from this location or absolute
#
ifndef QOOXDOO_PATH
  QOOXDOO_PATH = PLEASE_DEFINE_QOOXDOO_PATH
endif

#
# The same as above, but from the webserver point of view
# Starting point is the application HTML file of the source folder.
# In most cases just add a "/.." compared to above
#
ifndef QOOXDOO_URI
  QOOXDOO_URI = $(QOOXDOO_PATH)/..
endif

#
# Namespace of your application e.g. custom
#
ifndef APPLICATION_NAMESPACE
  APPLICATION_NAMESPACE = custom
endif

#
# Titles used in your API viewer and during the build process
#
ifndef APPLICATION_MAKE_TITLE
  APPLICATION_MAKE_TITLE = CUSTOM
endif

ifndef APPLICATION_API_TITLE
  APPLICATION_API_TITLE = Custom
endif

#
# Files that will be copied into the build directory
# (space separated list) (no default)
#
# ifndef APPLICATION_FILES
#   APPLICATION_FILES = index.html
# endif

#
# Locales to use (space separated list)
#
ifndef APPLICATION_LOCALES
  APPLICATION_LOCALES = C
else
  APPLICATION_LOCALES += C
endif






####################################################################################
# ADVANCED SETTINGS
####################################################################################

#
# Define folder path
#
ifndef APPLICATION_PATH
  APPLICATION_PATH = .
endif

#
# Define deep folder paths
#
ifndef APPLICATION_SOURCE_PATH
  APPLICATION_SOURCE_PATH = $(APPLICATION_PATH)/source
endif

ifndef APPLICATION_BUILD_PATH
  APPLICATION_BUILD_PATH = $(APPLICATION_PATH)/build
endif

ifndef APPLICATION_API_PATH
  APPLICATION_API_PATH = $(APPLICATION_PATH)/api
endif

#
# Define the publishing location
# Could be any rsync compatible url/path
#
ifndef APPLICATION_PUBLISH_PATH
  APPLICATION_PUBLISH_PATH = $(APPLICATION_PATH)/publish
endif

#
# Define the debug location
# Could be any rsync compatible url/path
#
ifndef APPLICATION_DEBUG_PATH
  APPLICATION_DEBUG_PATH = $(APPLICATION_PATH)/debug
endif

#
# Relation from HTML file to the top level directory (source or build).
#
ifndef APPLICATION_PAGE_TO_TOPLEVEL
  APPLICATION_PAGE_TO_TOPLEVEL = .
endif

#
# Configure resource handling
#
ifndef APPLICATION_RESOURCE_FILTER
  APPLICATION_RESOURCE_FILTER = false
endif

#
# Customize your build
#
ifndef APPLICATION_COMPLETE_BUILD
  APPLICATION_COMPLETE_BUILD = false
endif

ifndef APPLICATION_COMPLETE_SOURCE
  APPLICATION_COMPLETE_SOURCE = true
endif

ifndef APPLICATION_COMPLETE_API
  APPLICATION_COMPLETE_API = true
endif

#
# Customize your build
#
ifndef APPLICATION_LINEBREAKS_BUILD
  APPLICATION_LINEBREAKS_BUILD = true
endif

ifndef APPLICATION_LINEBREAKS_SOURCE
  APPLICATION_LINEBREAKS_SOURCE = true
endif

#
# Configure optimizer
#
ifndef APPLICATION_OPTIMIZE_STRINGS
  APPLICATION_OPTIMIZE_STRINGS = true
endif

ifndef APPLICATION_OPTIMIZE_VARIABLES
  APPLICATION_OPTIMIZE_VARIABLES = true
endif

#
# Include support for widgets
#
ifndef APPLICATION_ENABLE_GUI
  APPLICATION_ENABLE_GUI = true
endif

#
# Redefine folder names (inside build/source)
# It is not recommended to change these fundamental settings.
#
ifndef APPLICATION_SCRIPT_FOLDERNAME
  APPLICATION_SCRIPT_FOLDERNAME = script
endif

ifndef APPLICATION_CLASS_FOLDERNAME
  APPLICATION_CLASS_FOLDERNAME = class
endif

ifndef APPLICATION_TRANSLATION_FOLDERNAME
  APPLICATION_TRANSLATION_FOLDERNAME = translation
endif

#
# Name of the generated script
#
ifndef APPLICATION_SCRIPT_FILENAME
  APPLICATION_SCRIPT_FILENAME = $(APPLICATION_NAMESPACE).js
endif

#
# Full application classname
#
ifndef APPLICATION_CLASSNAME
  APPLICATION_CLASSNAME = $(APPLICATION_NAMESPACE).Application
endif

#
# Translation path
#
ifndef APPLICATION_TRANSLATION_PATH
  APPLICATION_TRANSLATION_PATH = $(APPLICATION_SOURCE_PATH)/$(APPLICATION_TRANSLATION_FOLDERNAME)
endif

#
# Namespace of translation classes
#
ifndef APPLICATION_TRANSLATION_CLASS_NAMESPACE
  APPLICATION_TRANSLATION_CLASS_NAMESPACE = $(APPLICATION_NAMESPACE).$(APPLICATION_TRANSLATION_FOLDERNAME)
endif

#
# Directory of translation classes
#
ifndef APPLICATION_TRANSLATION_CLASS_PATH
  APPLICATION_TRANSLATION_CLASS_PATH = $(APPLICATION_SOURCE_PATH)/$(APPLICATION_CLASS_FOLDERNAME)/$(APPLICATION_NAMESPACE)/$(APPLICATION_TRANSLATION_FOLDERNAME)
endif

#
# Settings for more advanced users
#
ifndef APPLICATION_ADDITIONAL_CLASS_PATH
  APPLICATION_ADDITIONAL_CLASS_PATH =
endif

ifndef APPLICATION_ADDITIONAL_CLASS_URI
  APPLICATION_ADDITIONAL_CLASS_URI =
endif

ifndef APPLICATION_ADDITIONAL_RESOURCE
  APPLICATION_ADDITIONAL_RESOURCE =
endif

#
# Template to patch (e.g. XHTML mode)
#

# (no default)

#ifndef APPLICATION_TEMPLATE_INPUT
#  APPLICATION_TEMPLATE_INPUT =
#endif

ifndef APPLICATION_TEMPLATE_OUTPUT
  APPLICATION_TEMPLATE_OUTPUT = $(APPLICATION_TEMPLATE_INPUT).out
endif

ifndef APPLICATION_TEMPLATE_REPLACE
  APPLICATION_TEMPLATE_REPLACE = <!-- qooxdoo-script-block -->
endif






###################################################################################
# COMPUTED DEFAULTS
###################################################################################

COMPUTED_COMMON_INIT =

COMPUTED_SOURCE_INCLUDE =
COMPUTED_SOURCE_LINEBREAKS =

COMPUTED_BUILD_INCLUDE =
COMPUTED_BUILD_OPTIMIZATIONS =
COMPUTED_BUILD_LINEBREAKS =

COMPUTED_API_INCLUDE =






###################################################################################
# PROCESSING APPLICATION SETTINGS
###################################################################################

COMPUTED_CLASS_PATH = --class-path $(FRAMEWORK_SOURCE_PATH)/class \
  --class-path $(APPLICATION_SOURCE_PATH)/$(APPLICATION_CLASS_FOLDERNAME) \
  $(APPLICATION_ADDITIONAL_CLASS_PATH)

COMPUTED_CLASS_URI = --class-uri $(FRAMEWORK_SOURCE_URI)/class \
  --class-uri $(APPLICATION_PAGE_TO_TOPLEVEL)/$(APPLICATION_CLASS_FOLDERNAME) \
  $(APPLICATION_ADDITIONAL_CLASS_URI)

COMPUTED_RESOURCE = --copy-resources \
  --resource-input $(FRAMEWORK_SOURCE_PATH)/resource \
  --resource-output $(APPLICATION_BUILD_PATH)/resource/qx \
  --define-runtime-setting qx.manager.object.AliasManager.resourceUri:$(APPLICATION_PAGE_TO_TOPLEVEL)/resource/qx \
  --resource-input $(APPLICATION_SOURCE_PATH)/resource \
  --resource-output $(APPLICATION_BUILD_PATH)/resource/$(APPLICATION_NAMESPACE) \
  --define-runtime-setting $(APPLICATION_CLASSNAME).resourceUri:$(APPLICATION_PAGE_TO_TOPLEVEL)/resource/$(APPLICATION_NAMESPACE) \
  $(APPLICATION_ADDITIONAL_RESOURCE)


COMPUTED_FRAMEWORK_LOCALE_INCLUDE := $(APPLICATION_LOCALES:%= --include qx.locale.data.% )
COMPUTED_FRAMEWORK_TRANSLATION_INCLUDE := $(APPLICATION_LOCALES:%= --include $(FRAMEWORK_TRANSLATION_CLASS_NAMESPACE).% )
COMPUTED_APPLICATION_TRANSLATION_INCLUDE := $(APPLICATION_LOCALES:%= --include $(APPLICATION_TRANSLATION_CLASS_NAMESPACE).% )


ifeq ($(APPLICATION_COMPLETE_SOURCE),false)
  COMPUTED_SOURCE_INCLUDE = --include $(APPLICATION_CLASSNAME) \
    $(COMPUTED_FRAMEWORK_LOCALE_INCLUDE) \
    $(COMPUTED_FRAMEWORK_TRANSLATION_INCLUDE) \
    $(COMPUTED_APPLICATION_TRANSLATION_INCLUDE)
endif

ifneq ($(APPLICATION_COMPLETE_BUILD),true)
  COMPUTED_BUILD_INCLUDE = --include $(APPLICATION_CLASSNAME) \
    $(COMPUTED_FRAMEWORK_LOCALE_INCLUDE) \
    $(COMPUTED_FRAMEWORK_TRANSLATION_INCLUDE) \
    $(COMPUTED_APPLICATION_TRANSLATION_INCLUDE)
endif

ifeq ($(APPLICATION_COMPLETE_API),false)
  COMPUTED_API_INCLUDE = --include $(APPLICATION_CLASSNAME)
endif

ifeq ($(APPLICATION_OPTIMIZE_STRINGS),true)
  COMPUTED_BUILD_OPTIMIZATIONS += --optimize-strings
endif

ifeq ($(APPLICATION_OPTIMIZE_VARIABLES),true)
  COMPUTED_BUILD_OPTIMIZATIONS += --optimize-variables
endif

ifeq ($(APPLICATION_ENABLE_GUI),false)
  COMPUTED_COMMON_INIT = --define-runtime-setting qx.core.Init.component:qx.component.init.BasicInitComponent
endif

ifeq ($(APPLICATION_RESOURCE_FILTER),true)
  COMPUTED_RESOURCE += --enable-resource-filter
endif

ifeq ($(APPLICATION_LINEBREAKS_SOURCE),true)
  COMPUTED_SOURCE_LINEBREAKS = --add-new-lines --add-file-ids
endif

ifeq ($(APPLICATION_LINEBREAKS_BUILD),true)
  COMPUTED_BUILD_LINEBREAKS = --add-new-lines --add-file-ids
endif

ifneq ($(APPLICATION_TEMPLATE_INPUT),)
  COMPUTED_TEMPLATE = --source-template-input-file $(APPLICATION_SOURCE_PATH)/$(APPLICATION_TEMPLATE_INPUT) --source-template-output-file $(APPLICATION_SOURCE_PATH)/$(APPLICATION_TEMPLATE_OUTPUT)

  ifneq ($(APPLICATION_TEMPLATE_REPLACE),)
    COMPUTED_TEMPLATE += --source-template-replace "$(APPLICATION_TEMPLATE_REPLACE)"
  endif
endif




###################################################################################
# INCLUDE EXTERNAL MAKEFILES
###################################################################################

include $(QOOXDOO_PATH)/frontend/framework/tool/make/impl.mk
