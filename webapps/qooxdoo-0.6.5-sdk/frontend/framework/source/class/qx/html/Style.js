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

#module(ui_core)
#require(qx.core.Client)

************************************************************************ */

/**
 * Methods to get CSS style properties of DOM elements.
 */
qx.OO.defineClass("qx.html.Style");

/**
 * TODO
 */
qx.html.Style.getStylePropertySure = function(vElement, propertyName) {};

/**
 * Get the (CSS) style property of a given DOM element
 *
 * @param vElement {Element} the DOM element
 * @param propertyName {String} the name of the style property. e.g. "color", "border", ...
 * @return {String} the (CSS) style property
 */
qx.html.Style.getStyleProperty = function(vElement, propertyName) {};

if (Boolean(document.defaultView) && Boolean(document.defaultView.getComputedStyle))
{
  qx.html.Style.getStylePropertySure = function(el, prop) { return !el ? null : el.ownerDocument ? el.ownerDocument.defaultView.getComputedStyle(el, "")[prop] : el.style[prop]; }

  qx.html.Style.getStyleProperty = function(el, prop)
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
else if (qx.core.Client.getInstance().isMshtml())
{
  qx.html.Style.getStyleProperty = function(el, prop)
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

  qx.html.Style.getStylePropertySure = function(el, prop)
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
  qx.html.Style.getStylePropertySure = function(el, prop) { return !el ? null : el.style[prop]; }

  qx.html.Style.getStyleProperty = function(el, prop)
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

/**
 * Get a (CSS) style property of a given DOM element and interpret the property as integer value
 *
 * @param vElement {Element} the DOM element
 * @param propertyName {String} the name of the style property. e.g. "paddingTop", "marginLeft", ...
 * @return {Integer} the (CSS) style property converted to an integer value
 */
qx.html.Style.getStyleSize = function(vElement, propertyName) { return parseInt(qx.html.Style.getStyleProperty(vElement, propertyName)) || 0; }


// Properties
/**
 * Get the element's left margin.
 *
 * @param vElement {Element} the DOM element
 * @return {Integer} the element's left margin size
 */
qx.html.Style.getMarginLeft    = function(vElement) { return qx.html.Style.getStyleSize(vElement, "marginLeft"); }

/**
 * Get the element's top margin.
 *
 * @param vElement {Element} the DOM element
 * @return {Integer} the element's top margin size
 */
qx.html.Style.getMarginTop     = function(vElement) { return qx.html.Style.getStyleSize(vElement, "marginTop"); }

/**
 * Get the element's right margin.
 *
 * @param vElement {Element} the DOM element
 * @return {Integer} the element's right margin size
 */
qx.html.Style.getMarginRight   = function(vElement) { return qx.html.Style.getStyleSize(vElement, "marginRight"); }

/**
 * Get the element's bottom margin.
 *
 * @param vElement {Element} the DOM element
 * @return {Integer} the element's bottom margin size
 */
qx.html.Style.getMarginBottom  = function(vElement) { return qx.html.Style.getStyleSize(vElement, "marginBottom"); }

/**
 * Get the element's left padding.
 *
 * @param vElement {Element} the DOM element
 * @return {Integer} the element's left padding size
 */
qx.html.Style.getPaddingLeft   = function(vElement) { return qx.html.Style.getStyleSize(vElement, "paddingLeft"); }

/**
 * Get the element's top padding.
 *
 * @param vElement {Element} the DOM element
 * @return {Integer} the element's top padding size
 */
qx.html.Style.getPaddingTop    = function(vElement) { return qx.html.Style.getStyleSize(vElement, "paddingTop"); }

/**
 * Get the element's right padding.
 *
 * @param vElement {Element} the DOM element
 * @return {Integer} the element's right padding size
 */
qx.html.Style.getPaddingRight  = function(vElement) { return qx.html.Style.getStyleSize(vElement, "paddingRight"); }

/**
 * Get the element's bottom padding.
 *
 * @param vElement {Element} the DOM element
 * @return {Integer} the element's bottom padding size
 */
qx.html.Style.getPaddingBottom = function(vElement) { return qx.html.Style.getStyleSize(vElement, "paddingBottom"); }

/**
 * Get the element's left border width.
 *
 * @param vElement {Element} the DOM element
 * @return {Integer} the element's left border width
 */
qx.html.Style.getBorderLeft    = function(vElement) { return qx.html.Style.getStyleProperty(vElement, "borderLeftStyle")   == "none" ? 0 : qx.html.Style.getStyleSize(vElement, "borderLeftWidth"); }

/**
 * Get the element's top border width.
 *
 * @param vElement {Element} the DOM element
 * @return {Integer} the element's top border width
 */
qx.html.Style.getBorderTop     = function(vElement) { return qx.html.Style.getStyleProperty(vElement, "borderTopStyle")    == "none" ? 0 : qx.html.Style.getStyleSize(vElement, "borderTopWidth"); }

/**
 * Get the element's right border width.
 *
 * @param vElement {Element} the DOM element
 * @return {Integer} the element's right border width
 */
qx.html.Style.getBorderRight   = function(vElement) { return qx.html.Style.getStyleProperty(vElement, "borderRightStyle")  == "none" ? 0 : qx.html.Style.getStyleSize(vElement, "borderRightWidth"); }

/**
 * Get the element's bottom border width.
 *
 * @param vElement {Element} the DOM element
 * @return {Integer} the element's bottom border width
 */
qx.html.Style.getBorderBottom  = function(vElement) { return qx.html.Style.getStyleProperty(vElement, "borderBottomStyle") == "none" ? 0 : qx.html.Style.getStyleSize(vElement, "borderBottomWidth"); }
