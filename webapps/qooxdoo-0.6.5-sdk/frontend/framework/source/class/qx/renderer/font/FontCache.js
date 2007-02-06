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

#module(ui_basic)

************************************************************************ */

qx.OO.defineClass("qx.renderer.font.FontCache");

qx.renderer.font.FontCache = function(propValue, propData)
{
  var propKey;
  var propKeyAsStyle = false;

  switch(typeof propValue)
  {
    case "string":
      if (propValue != "")
      {
        propValue = propKey = propValue.toLowerCase();
        break;
      }

      return propValue;

    case "number":
      propKey = propValue.toString();
      break;

    case "object":
      if (propValue == null || propValue instanceof qx.renderer.font.Font) {
        return propValue;
      }

      // Try to detect array of RGB values
      if (typeof propValue.join === "function")
      {
        propKey = propValue.join(" ").toLowerCase();
        break;
      }

    default:
      return propValue;
  }

  if (qx.renderer.font.FontCache._data[propKey]) {
    return qx.renderer.font.FontCache._data[propKey];
  }

  return qx.renderer.font.FontCache._data[propKey] = qx.renderer.font.Font.fromString(propKey);
}

qx.renderer.font.FontCache._data = {};
