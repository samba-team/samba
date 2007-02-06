/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************

#id(qx.Settings)
#module(core)

************************************************************************ */



/*
---------------------------------------------------------------------------
  CREATE NAMESPACE HIERARCHY
---------------------------------------------------------------------------
*/

if (!window.qx) {
  qx = {};
}

if (!qx.Settings) {
  qx.Settings = {};
}

if (!qx.Settings._customSettings) {
  qx.Settings._customSettings = {};
}

/** the default settings */
qx.Settings._defaultSettings = {};




/*
---------------------------------------------------------------------------
  ATTACH GLOBAL DATA
---------------------------------------------------------------------------
*/

qx._LOADSTART = (new Date).valueOf();






/*
---------------------------------------------------------------------------
  UTILITES METHODS
---------------------------------------------------------------------------
*/

qx.Settings.substitute = function(vTemplate)
{
  if (typeof vTemplate !== "string") {
    return vTemplate;
  }

  return vTemplate.replace(/\%\{(.+)\}/g, function(vMatch, vKey) {
    return eval(vKey);
  });
};






/*
---------------------------------------------------------------------------
  ACCESS METHODS
---------------------------------------------------------------------------
*/

qx.Settings.getValue = function(vKey) {
  return qx.Settings.getValueOfClass(qx.Class.classname, vKey);
}

qx.Settings.getValueOfClass = function(vClassName, vKey)
{
  var vCustomObject = qx.Settings._customSettings[vClassName];
  if (vCustomObject && vCustomObject[vKey] != null) {
    return vCustomObject[vKey];
  }

  var vDefaultObject = qx.Settings._defaultSettings[vClassName];
  if (vDefaultObject && vDefaultObject[vKey] != null) {
    return vDefaultObject[vKey];
  }

  return null;
}

qx.Settings.setDefault = function(vKey, vValue) {
  return qx.Settings.setDefaultOfClass(qx.Class.classname, vKey, vValue);
}

qx.Settings.setDefaultOfClass = function(vClassName, vKey, vValue)
{
  var vDefaultObject = qx.Settings._defaultSettings[vClassName];

  if (!vDefaultObject) {
    vDefaultObject = qx.Settings._defaultSettings[vClassName] = {};
  }

  // default values doesn't support substitution
  vDefaultObject[vKey] = vValue;
}

qx.Settings.setCustom = function(vKey, vValue) {
  return qx.Settings.setCustomOfClass(qx.Class.classname, vKey, vValue);
}

qx.Settings.setCustomOfClass = function(vClassName, vKey, vValue)
{
  var vCustomObject = qx.Settings._customSettings[vClassName];

  if (!vCustomObject) {
    vCustomObject = qx.Settings._customSettings[vClassName] = {};
  }

  vCustomObject[vKey] = qx.Settings.substitute(vValue);
}







/*
---------------------------------------------------------------------------
  IMPORT VARIABLES OF CUSTOM SETTINGS
---------------------------------------------------------------------------
*/

qx.Settings.init = function()
{
  for (var vClass in qx.Settings._customSettings)
  {
    var vSettings = qx.Settings._customSettings[vClass];

    for (var vKey in vSettings) {
      qx.Settings.setCustomOfClass(vClass, vKey, vSettings[vKey]);
    }
  }
}

qx.Settings.init();
