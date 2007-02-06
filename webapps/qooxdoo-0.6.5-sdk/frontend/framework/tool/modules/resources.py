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
#    * Sebastian Werner (wpbasti)
#
################################################################################

import os, shutil, re
import config, textutil




def copy(options, sortedIncludeList, fileDb):
  if options.enableResourceFilter:
    print "  * Processing embeds..."

    definedEmbeds = {}
    compiledEmbeds = {}

    for fileId in sortedIncludeList:
      fileEmbeds = fileDb[fileId]["embeds"]


      if len(fileEmbeds) > 0:
        print "    - Found %i embeds in %s" % (len(fileEmbeds), fileId)

        for fileEmbed in fileEmbeds:
          resourceNS = fileEmbed["namespace"]
          resourceId = fileEmbed["id"]
          embedEntry = fileEmbed["entry"]

          if not definedEmbeds.has_key(resourceNS):
            definedEmbeds[resourceNS] = {}

          if not definedEmbeds[resourceNS].has_key(resourceId):
            definedEmbeds[resourceNS][resourceId] = []

          if not embedEntry in definedEmbeds[resourceNS][resourceId]:
            definedEmbeds[resourceNS][resourceId].append(embedEntry)


    # We must do this in a separate step because otherwise the string compare
    # above does not work (how to compare compiled regexp?)

    print "  * Compiling embeds..."

    for resourceNS in definedEmbeds:
      for resourceId in definedEmbeds[resourceNS]:
        for embedEntry in definedEmbeds[resourceNS][resourceId]:
          if not compiledEmbeds.has_key(resourceNS):
            compiledEmbeds[resourceNS] = {}

          if not compiledEmbeds[resourceNS].has_key(resourceId):
            compiledEmbeds[resourceNS][resourceId] = []

          compiledEmbeds[resourceNS][resourceId].append(textutil.toRegExp(embedEntry))



  print "  * Syncing files..."

  for fileId in sortedIncludeList:
    filePath = fileDb[fileId]["path"]
    fileResources = fileDb[fileId]["resources"]

    if len(fileResources) > 0:
      print "    - Found %i resources in %s" % (len(fileResources), fileId)

      for fileResource in fileResources:
        resourceNS = fileResource["namespace"]
        resourceId = fileResource["id"]
        resourceEntry = fileResource["entry"]

        if options.enableResourceFilter:
          if compiledEmbeds.has_key(resourceNS) and compiledEmbeds[resourceNS].has_key(resourceId):
            resourceFilter = compiledEmbeds[resourceNS][resourceId]
          else:
            resourceFilter = []



        # Preparing source directory

        sourceDirectory = os.path.join(fileDb[fileId]["resourceInput"], resourceEntry)

        try:
          os.listdir(sourceDirectory)
        except OSError:
          print "        - Source directory isn't readable! Ignore resource!"
          continue


        # Preparing destination directory

        destinationDirectory = os.path.join(fileDb[fileId]["resourceOutput"], resourceEntry)





        print "      - Copying %s [%s.%s]" % (resourceEntry, resourceNS, resourceId)

        for root, dirs, files in os.walk(sourceDirectory):

          # Filter ignored directories
          for ignoredDir in config.DIRIGNORE:
            if ignoredDir in dirs:
              dirs.remove(ignoredDir)

          # Searching for items (resource files)
          for itemName in files:

            # Generate absolute source file path
            itemSourcePath = os.path.join(root, itemName)

            # Extract relative path and directory
            itemRelPath = itemSourcePath.replace(sourceDirectory + os.sep, "")
            itemRelDir = os.path.dirname(itemRelPath)

            # Filter items
            if options.enableResourceFilter:
              include = False

              for filterEntry in resourceFilter:
                if filterEntry.search(itemRelPath):
                  include = True
                  break

              if not include:
                continue

            # Generate destination directory and file path
            itemDestDir = os.path.join(destinationDirectory, itemRelDir)
            itemDestPath = os.path.join(itemDestDir, itemName)

            # Check/Create destination directory
            if not os.path.exists(itemDestDir):
              os.makedirs(itemDestDir)

            # Copy file
            if options.verbose:
              print "        - Copying file: %s" % itemRelPath

            shutil.copyfile(itemSourcePath, itemDestPath)
