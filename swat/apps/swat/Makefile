###################################################################################
# PUBLIC VARIABLES
###################################################################################

QOOXDOO = ../qooxdoo-0.6.3-sdk
SCRIPTNAME = swat.js
APPCLASS = swat.Application
INCLUDEALL = true
OPTIMIZESTRINGS = false
OPTIMIZEVARIABLES = false
SOURCELOADER=
NICE=10


###################################################################################
# PRIVATE VARIABLES
###################################################################################

FRONTEND = $(QOOXDOO)/frontend
FRAMEWORK = $(FRONTEND)/framework
API = $(FRONTEND)/api
CACHE = $(FRAMEWORK)/.cache
GENERATOR = $(FRAMEWORK)/tool/generator.py


ifeq ($(INCLUDEALL),false)
  INCLUDE = --include $(APPCLASS)
else
  INCLUDE =
endif

ifeq ($(OPTIMIZESTRINGS),true)
  OPTIMIZESTR = --optimize-strings
else
  OPTIMIZESTR =
endif

ifeq ($(OPTIMIZEVARIABLES),true)
  OPTIMIZEVAR = --optimize-variables
else
  OPTIMIZEVAR =
endif

ifneq ($(SOURCELOADER),)
  SOURCELDR = --source-loader-type $(SOURCELOADER)
else
  SOURCELDR =
endif


###################################################################################
# DEFAULT TARGET
###################################################################################

all: build



###################################################################################
# COMMON TARGETS
###################################################################################

source: info-source generate-script-source
build: info-build generate-script-build copy-build-files fix-build-rights

api: generate-api-build generate-api-data
	@echo
	@echo "  CREATE COPY OF HTML FILE"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Copying file..."
	@cp -f $(API)/source/index.html api/index.html

pretty: generate-pretty
fix: generate-fix



###################################################################################
# CLEANUP TARGETS
###################################################################################

clean:
	@echo
	@echo "  CLEANUP OF GENERATED FILES"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Deleting files..."
	@rm -f source/script/$(SCRIPTNAME) build/script/$(SCRIPTNAME)

realclean: clean
	@echo
	@echo "  CLEANUP OF GENERATED FILES (REAL)"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Deleting files..."
	@nice -n $(NICE) rm -rf build

distclean: realclean
	@echo
	@echo "  CLEANUP OF GENERATED FILES (DIST)"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Deleting files..."
	@nice -n $(NICE) find . -name "*~" -o -name "*.bak" -o -name "*.old" | xargs rm -rf
	@nice -n $(NICE) rm -rf $(CACHE)



###################################################################################
# GENERATOR TARGETS
###################################################################################

generate-script-source:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input $(FRAMEWORK)/source/class \
	  --source-script-path ../$(FRAMEWORK)/source/class \
	  --script-input source/class \
	  --source-script-path class \
	  --generate-source-script $(SOURCELDR) \
	  $(INCLUDE) \
	  --source-script-file source/script/$(SCRIPTNAME) \
	  --define-runtime-setting qx.manager.object.AliasManager.resourceUri:../$(FRAMEWORK)/source/resource \
	  --cache-directory $(CACHE) \
	  --add-new-lines

generate-script-build:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input $(FRAMEWORK)/source/class \
	  --script-input source/class \
	  --generate-compiled-script \
	  $(INCLUDE) $(OPTIMIZESTR) $(OPTIMIZEVAR) \
	  --compiled-script-file build/script/$(SCRIPTNAME) \
	  --copy-resources \
	  --resource-input $(FRAMEWORK)/source/resource \
	  --resource-output build/resource \
	  --define-runtime-setting qx.manager.object.AliasManager.resourceUri:./resource \
	  --cache-directory $(CACHE)

generate-api-build:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input $(FRAMEWORK)/source/class \
	  --resource-input $(FRAMEWORK)/source/resource \
	  --resource-output api/resource/qooxdoo \
	  --script-input $(API)/source/class \
	  --resource-input $(API)/source/resource \
	  --resource-output api/resource \
	  --include api \
	  $(OPTIMIZESTR) $(OPTIMIZEVAR) \
	  --generate-compiled-script \
	  --compiled-script-file api/script/api.js \
	  --define-runtime-setting qx.manager.object.AliasManager.resourceUri:resource/qooxdoo \
	  --define-runtime-setting api.Viewer.title:Sample \
	  --copy-resources \
	  --cache-directory $(CACHE)

generate-api-data:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input $(FRAMEWORK)/source/class \
	  --script-input source/class \
	  --generate-api-documentation \
	  --api-documentation-json-file api/script/data.js \
	  --cache-directory $(CACHE)

generate-pretty:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --script-input $(FRAMEWORK)/source/class \
	  --include-without-dependencies api.* \
	  --pretty-print \
	  --cache-directory $(CACHE)

generate-fix:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --script-input $(FRAMEWORK)/source/class \
	  --include-without-dependencies api.* \
	  --fix-source \
	  --cache-directory $(CACHE)



###################################################################################
# ADDITIONAL TARGETS
###################################################################################

copy-build-files:
	@echo
	@echo "  CREATE COPY OF HTML FILE"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Copying file..."
	@cp -f source/index.html build/index.html

fix-build-rights:
	@echo
	@echo "  FIX RIGHTS ON BUILD FILES"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Fixing file rights..."
	@nice -n $(NICE) find build -type d | xargs chmod a+rx
	@nice -n $(NICE) find build -type f | xargs chmod a+r





###################################################################################
# INFO TARGETS
###################################################################################

info-build:
	@echo "****************************************************************************"
	@echo "  GENERATING SAMPLE 1 BUILD"
	@echo "****************************************************************************"

info-source:
	@echo "****************************************************************************"
	@echo "  GENERATING SAMPLE 1 SOURCE"
	@echo "****************************************************************************"
