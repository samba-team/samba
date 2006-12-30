/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************

#module(ui_core)

************************************************************************ */

qx.OO.defineClass("qx.renderer.color.ColorCache");

qx.renderer.color.ColorCache = function(propValue)
{
  var propKey;
  var propKeyAsStyle = false;

  switch(typeof propValue)
  {
    case "string":
      if (propValue != "") {
        propValue = propKey = propValue.toLowerCase();
        break;
      }

      return propValue;

    case "number":
      if (propValue >= 0 && propValue <= 255)
      {
        propKey = propValue.toString();
        break;
      }

      return propValue;

    case "object":
      if (propValue == null || propValue instanceof qx.renderer.color.Color) {
        return propValue;
      }

      // Try to detect array of RGB values
      if (typeof propValue.join === "function" && propValue.length == 3)
      {
        propKey = "rgb(" + propValue.join(",") + ")";
        propKeyAsStyle = true;
        break;
      }

    default:
      return propValue;
  }

  if (qx.renderer.color.ColorCache._data[propKey]) {
    return qx.renderer.color.ColorCache._data[propKey];
  }

  // this.debug("Create new color instance: " + propKey);

  var vColorObject = qx.renderer.color.ColorCache._data[propKey] = qx.renderer.color.Color.themedNames[propValue] ? new qx.renderer.color.ColorObject(propValue) : new qx.renderer.color.Color(propValue);

  if (propKeyAsStyle) {
    vColorObject._style = propKey;
  }

  return vColorObject;
}

qx.renderer.color.ColorCache._data = {};
