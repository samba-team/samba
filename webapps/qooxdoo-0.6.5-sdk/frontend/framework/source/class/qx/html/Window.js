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

#require(qx.core.Client)

************************************************************************ */

qx.OO.defineClass("qx.html.Window");


/**
 * Get the inner width of the given browser window
 *
 * @param window {window} browser window
 * @return {Integer} the window's inner width
 */
qx.html.Window.getInnerWidth = function(window) {};

/**
 * Get the inner height of the given browser window
 *
 * @param window {window} browser window
 * @return {Integer} the window's inner height
 */
qx.html.Window.getInnerHeight = function(window) {};

/**
 * Get the left scroll position of the given browser window
 *
 * @param window {window} browser window
 * @return {Integer} the window's left scroll position
 */
qx.html.Window.getScrollLeft = function(window) {};

/**
 * Get the top scroll position of the given browser window
 *
 * @param window {window} browser window
 * @return {Integer} the window's top scroll position
 */
qx.html.Window.getScrollTop = function(window) {};


if (qx.core.Client.getInstance().isMshtml())
{
  qx.html.Window.getInnerWidth = function(w)
  {
    if (w.document.documentElement && w.document.documentElement.clientWidth)
    {
      return w.document.documentElement.clientWidth;
    }
    else if (w.document.body)
    {
      return w.document.body.clientWidth;
    }

    return 0;
  }

  qx.html.Window.getInnerHeight = function(w)
  {
    if (w.document.documentElement && w.document.documentElement.clientHeight)
    {
      return w.document.documentElement.clientHeight;
    }
    else if (w.document.body)
    {
      return w.document.body.clientHeight;
    }

    return 0;
  }

  qx.html.Window.getScrollLeft = function(w)
  {
    if (w.document.documentElement && w.document.documentElement.scrollLeft)
    {
      return w.document.documentElement.scrollLeft;
    }
    else if (w.document.body)
    {
      return w.document.body.scrollTop;
    }

    return 0;
  }

  qx.html.Window.getScrollTop = function(w)
  {
    if (w.document.documentElement && w.document.documentElement.scrollTop)
    {
      return w.document.documentElement.scrollTop;
    }
    else if (w.document.body)
    {
      return w.document.body.scrollTop;
    }

    return 0;
  }
}
else
{
  qx.html.Window.getInnerWidth = function(w) {
    return w.innerWidth;
  }

  qx.html.Window.getInnerHeight = function(w) {
    return w.innerHeight;
  }

  qx.html.Window.getScrollLeft = function(w) {
    return w.document.body.scrollLeft;
  }

  qx.html.Window.getScrollTop = function(w) {
    return w.document.body.scrollTop;
  }
}
