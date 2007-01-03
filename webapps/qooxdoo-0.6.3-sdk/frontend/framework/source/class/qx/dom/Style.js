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
#require(qx.sys.Client)

************************************************************************ */

qx.OO.defineClass("qx.dom.Style");

if (Boolean(document.defaultView) && Boolean(document.defaultView.getComputedStyle))
{
  qx.dom.Style.getStylePropertySure = function(el, prop) { return !el ? null : el.ownerDocument ? el.ownerDocument.defaultView.getComputedStyle(el, "")[prop] : el.style[prop]; }

  qx.dom.Style.getStyleProperty = function(el, prop)
  {
    try
    {
      return el.ownerDocument.defaultView.getComputedStyle(el, "")[prop];
    }
    catch(ex)
    {
      throw new Error("Could not evaluate computed style: " + el + "[" + prop + "]: " + ex);
    }
  }
}
else if (qx.sys.Client.getInstance().isMshtml())
{
  qx.dom.Style.getStyleProperty = function(el, prop)
  {
    try
    {
      return el.currentStyle[prop];
    }
    catch(ex)
    {
      throw new Error("Could not evaluate computed style: " + el + "[" + prop + "]: " + ex);
    }
  }

  qx.dom.Style.getStylePropertySure = function(el, prop)
  {
    try
    {
      if (!el) {
        return null;
      }

      if (el.parentNode && el.currentStyle)
      {
        return el.currentStyle[prop];
      }
      else
      {
        var v1 = el.runtimeStyle[prop];

        if (v1 != null && typeof v1 != "undefined" && v1 != "") {
          return v1;
        }

        return el.style[prop];
      }
    }
    catch(ex)
    {
      throw new Error("Could not evaluate computed style: " + el + "[" + prop + "]: " + ex);
    }
  }
}
else
{
  qx.dom.Style.getStylePropertySure = function(el, prop) { return !el ? null : el.style[prop]; }

  qx.dom.Style.getStyleProperty = function(el, prop)
  {
    try
    {
      return el.style[prop];
    }
    catch(ex)
    {
      throw new Error("Could not evaluate computed style: " + el + "[" + prop + "]");
    }
  }
}


qx.dom.Style.getStyleSize = function(el, prop) { return parseInt(qx.dom.Style.getStyleProperty(el, prop)) || 0; }


// Properties
qx.dom.Style.getMarginLeft    = function(el) { return qx.dom.Style.getStyleSize(el, "marginLeft"); }
qx.dom.Style.getMarginTop     = function(el) { return qx.dom.Style.getStyleSize(el, "marginTop"); }
qx.dom.Style.getMarginRight   = function(el) { return qx.dom.Style.getStyleSize(el, "marginRight"); }
qx.dom.Style.getMarginBottom  = function(el) { return qx.dom.Style.getStyleSize(el, "marginBottom"); }

qx.dom.Style.getPaddingLeft   = function(el) { return qx.dom.Style.getStyleSize(el, "paddingLeft"); }
qx.dom.Style.getPaddingTop    = function(el) { return qx.dom.Style.getStyleSize(el, "paddingTop"); }
qx.dom.Style.getPaddingRight  = function(el) { return qx.dom.Style.getStyleSize(el, "paddingRight"); }
qx.dom.Style.getPaddingBottom = function(el) { return qx.dom.Style.getStyleSize(el, "paddingBottom"); }

qx.dom.Style.getBorderLeft    = function(el) { return qx.dom.Style.getStyleProperty(el, "borderLeftStyle")   == "none" ? 0 : qx.dom.Style.getStyleSize(el, "borderLeftWidth"); }
qx.dom.Style.getBorderTop     = function(el) { return qx.dom.Style.getStyleProperty(el, "borderTopStyle")    == "none" ? 0 : qx.dom.Style.getStyleSize(el, "borderTopWidth"); }
qx.dom.Style.getBorderRight   = function(el) { return qx.dom.Style.getStyleProperty(el, "borderRightStyle")  == "none" ? 0 : qx.dom.Style.getStyleSize(el, "borderRightWidth"); }
qx.dom.Style.getBorderBottom  = function(el) { return qx.dom.Style.getStyleProperty(el, "borderBottomStyle") == "none" ? 0 : qx.dom.Style.getStyleSize(el, "borderBottomWidth"); }
