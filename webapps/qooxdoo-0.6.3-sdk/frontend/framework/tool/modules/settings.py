#!/usr/bin/env python

import sys, re, os, optparse
import filetool




def generate(options):
  if len(options.defineRuntimeSetting) == 0:
    return ""

  typeFloat = re.compile("^([0-9\-]+\.[0-9]+)$")
  typeNumber = re.compile("^([0-9\-])$")

  settingsStr = ""

  settingsStr += 'if(!window.qx)qx={};'

  if options.addNewLines:
    settingsStr += "\n"

  settingsStr += 'if(!qx.Settings)qx.Settings={};'

  if options.addNewLines:
    settingsStr += "\n"

  settingsStr += 'if(!qx.Settings._customSettings)qx.Settings._customSettings={};'

  if options.addNewLines:
    settingsStr += "\n"

  for setting in options.defineRuntimeSetting:
    settingSplit = setting.split(":")
    settingKey = settingSplit.pop(0)
    settingValue = ":".join(settingSplit)

    settingKeySplit = settingKey.split(".")
    settingKeyName = settingKeySplit.pop()
    settingKeySpace = ".".join(settingKeySplit)

    checkStr = 'if(!qx.Settings._customSettings["%s"])qx.Settings._customSettings["%s"]={};' % (settingKeySpace, settingKeySpace)
    if not checkStr in settingsStr:
      settingsStr += checkStr

      if options.addNewLines:
        settingsStr += "\n"

    settingsStr += 'qx.Settings._customSettings["%s"]["%s"]=' % (settingKeySpace, settingKeyName)

    if settingValue == "false" or settingValue == "true" or typeFloat.match(settingValue) or typeNumber.match(settingValue):
      settingsStr += '%s' % settingValue

    else:
      settingsStr += '"%s"' % settingValue.replace("\"", "\\\"")

    settingsStr += ";"

    if options.addNewLines:
      settingsStr += "\n"

  return settingsStr




def main():
  parser = optparse.OptionParser()

  parser.add_option("-d", "--define-runtime-setting", action="append", dest="defineRuntimeSetting", metavar="NAMESPACE.KEY:VALUE", default=[], help="Define a setting.")
  parser.add_option("-s", "--settings-script-file", dest="settingsScriptFile", metavar="FILENAME", help="Name of settings script file.")
  parser.add_option("-n", "--add-new-lines", action="store_true", dest="addNewLines", default=False, help="Keep newlines in compiled files.")

  (options, args) = parser.parse_args()

  if options.settingsScriptFile == None:
    print "  * Please define the output file!"
    sys.exit(1)

  if len(options.defineRuntimeSetting) == 0:
    print "  * Please define at least one runtime setting!"
    sys.exit(1)

  print "   * Saving settings to %s" % options.settingsScriptFile
  filetool.save(options.settingsScriptFile, generate(options))




if __name__ == '__main__':
  try:
    main()

  except KeyboardInterrupt:
    print
    print "  * Keyboard Interrupt"
    sys.exit(1)
