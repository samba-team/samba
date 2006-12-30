#!/usr/bin/env python

import os, shutil
import config


def copy(options, sortedIncludeList, fileDb):
  print "  * Preparing configuration..."

  overrideList = []

  for overrideEntry in options.overrideResourceOutput:
    # Parse
    # fileId.resourceId:destinationDirectory
    targetSplit = overrideEntry.split(":")
    targetStart = targetSplit.pop(0)
    targetStartSplit = targetStart.split(".")

    # Store
    overrideData = {}
    overrideData["destinationDirectory"] = ":".join(targetSplit)
    overrideData["resourceId"] = targetStartSplit.pop()
    overrideData["fileId"] = ".".join(targetStartSplit)

    # Append
    overrideList.append(overrideData)

  print "  * Syncing..."

  for fileId in sortedIncludeList:
    filePath = fileDb[fileId]["path"]
    fileResources = fileDb[fileId]["resources"]

    if len(fileResources) > 0:
      print "    - Found %i resources in %s" % (len(fileResources), fileId)

      for fileResource in fileResources:
        fileResourceSplit = fileResource.split(":")

        resourceId = fileResourceSplit.pop(0)
        relativeDirectory = ":".join(fileResourceSplit)

        sourceDirectory = os.path.join(fileDb[fileId]["resourceInput"], relativeDirectory)
        destinationDirectory = os.path.join(fileDb[fileId]["resourceOutput"], relativeDirectory)

        # Searching for overrides
        for overrideData in overrideList:
          if overrideData["fileId"] == fileId and overrideData["resourceId"] == resourceId:
            destinationDirectory = overrideData["destinationDirectory"]

        print "      - Copy %s => %s" % (sourceDirectory, destinationDirectory)

        try:
          os.listdir(sourceDirectory)
        except OSError:
          print "        - Source directory isn't readable! Ignore resource!"
          continue

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

            # Generate destination directory and file path
            itemDestDir = os.path.join(destinationDirectory, itemRelDir)
            itemDestPath = os.path.join(itemDestDir, itemName)

            # Check/Create destination directory
            if not os.path.exists(itemDestDir):
              os.makedirs(itemDestDir)

            # Copy file
            if options.verbose:
              print "      - Copying: %s => %s" % (itemSourcePath, itemDestPath)

            shutil.copyfile(itemSourcePath, itemDestPath)
