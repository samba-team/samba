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

************************************************************************ */

qx.OO.defineClass("qx.html.Dimension");

/*
+-Outer----------------------------------------+
|  Margin                                      |
|  +-Box------------------------------+        |
|  |  Border (+ Scrollbar)            |        |
|  |  +-Area--------------------+     |        |
|  |  |  Padding                |     |        |
|  |  |  +-Inner----------+     |     |        |
|  |  |  |                |     |     |        |
|  |  |  +----------------+     |     |        |
|  |  +-------------------------+     |        |
|  +----------------------------------+        |
+----------------------------------------------+
*/

// Dimensions
qx.html.Dimension.getOuterWidth  = function(el) { return qx.html.Dimension.getBoxWidth(el)  + qx.html.Style.getMarginLeft(el) + qx.html.Style.getMarginRight(el); }
qx.html.Dimension.getOuterHeight = function(el) { return qx.html.Dimension.getBoxHeight(el) + qx.html.Style.getMarginTop(el)  + qx.html.Style.getMarginBottom(el); }

qx.html.Dimension.getBoxWidthForZeroHeight = function(el)
{
  var h = el.offsetHeight;
  if (h == 0) {
    var o = el.style.height;
    el.style.height = "1px";
  }

  var v = el.offsetWidth;

  if (h == 0) {
    el.style.height = o;
  }

  return v;
}

qx.html.Dimension.getBoxHeightForZeroWidth = function(el)
{
  var w = el.offsetWidth;
  if (w == 0) {
    var o = el.style.width;
    el.style.width = "1px";
  }

  var v = el.offsetHeight;

  if (w == 0) {
    el.style.width = o;
  }

  return v;
}

qx.html.Dimension.getBoxWidth = function(el) {
  return el.offsetWidth;
}

qx.html.Dimension.getBoxHeight = function(el) {
  return el.offsetHeight;
}


qx.html.Dimension.getAreaWidth = function(el) {};
qx.html.Dimension.getAreaHeight = function(el) {};

if (qx.core.Client.getInstance().isGecko())
{
  qx.html.Dimension.getAreaWidth = function(el)
  {
    // 0 in clientWidth could mean both: That it is really 0 or
    // that the element is not rendered by the browser and
    // therefore it is 0, too

    // In Gecko based browsers there is sometimes another
    // behaviour: The clientHeight is equal to the border
    // sum. This is normally not correct and so we
    // fix this value with a more complex calculation.

    // (Mozilla/5.0 (Windows; U; Windows NT 5.1; de-DE; rv:1.7.6) Gecko/20050223 Firefox/1.0.1)

    if (el.clientWidth != 0 && el.clientWidth != (qx.html.Style.getBorderLeft(el) + qx.html.Style.getBorderRight(el)))
    {
      return el.clientWidth;
    }
    else
    {
      return qx.html.Dimension.getBoxWidth(el) - qx.html.Dimension.getInsetLeft(el) - qx.html.Dimension.getInsetRight(el);
    }
  }

  qx.html.Dimension.getAreaHeight = function(el)
  {
    // 0 in clientHeight could mean both: That it is really 0 or
    // that the element is not rendered by the browser and
    // therefore it is 0, too

    // In Gecko based browsers there is sometimes another
    // behaviour: The clientHeight is equal to the border
    // sum. This is normally not correct and so we
    // fix this value with a more complex calculation.

    // (Mozilla/5.0 (Windows; U; Windows NT 5.1; de-DE; rv:1.7.6) Gecko/20050223 Firefox/1.0.1)

    if (el.clientHeight != 0 && el.clientHeight != (qx.html.Style.getBorderTop(el) + qx.html.Style.getBorderBottom(el)))
    {
      return el.clientHeight;
    }
    else
    {
      return qx.html.Dimension.getBoxHeight(el) - qx.html.Dimension.getInsetTop(el) - qx.html.Dimension.getInsetBottom(el);
    }
  }
}
else
{
  qx.html.Dimension.getAreaWidth = function(el)
  {
    // 0 in clientWidth could mean both: That it is really 0 or
    // that the element is not rendered by the browser and
    // therefore it is 0, too

    return el.clientWidth != 0 ? el.clientWidth : (qx.html.Dimension.getBoxWidth(el) - qx.html.Dimension.getInsetLeft(el) - qx.html.Dimension.getInsetRight(el));
  }

  qx.html.Dimension.getAreaHeight = function(el)
  {
    // 0 in clientHeight could mean both: That it is really 0 or
    // that the element is not rendered by the browser and
    // therefore it is 0, too

    return el.clientHeight != 0 ? el.clientHeight : (qx.html.Dimension.getBoxHeight(el) - qx.html.Dimension.getInsetTop(el) - qx.html.Dimension.getInsetBottom(el));
  }
}

qx.html.Dimension.getInnerWidth  = function(el) { return qx.html.Dimension.getAreaWidth(el) - qx.html.Style.getPaddingLeft(el) - qx.html.Style.getPaddingRight(el); }
qx.html.Dimension.getInnerHeight = function(el) { return qx.html.Dimension.getAreaHeight(el) - qx.html.Style.getPaddingTop(el)  - qx.html.Style.getPaddingBottom(el); }




// Insets
qx.html.Dimension.getInsetLeft   = function(el) {};
qx.html.Dimension.getInsetTop    = function(el) {};
qx.html.Dimension.getInsetRight  = function(el) {};
qx.html.Dimension.getInsetBottom = function(el) {};

if (qx.core.Client.getInstance().isMshtml())
{
  qx.html.Dimension.getInsetLeft   = function(el) { return el.clientLeft; }
  qx.html.Dimension.getInsetTop    = function(el) { return el.clientTop; }
  qx.html.Dimension.getInsetRight  = function(el) {
    if(qx.html.Style.getStyleProperty(el, "overflowY") == "hidden" || el.clientWidth == 0) {
      return qx.html.Style.getBorderRight(el);
    }

    return Math.max(0, el.offsetWidth - el.clientLeft - el.clientWidth);
  }

  qx.html.Dimension.getInsetBottom = function(el) {
    if(qx.html.Style.getStyleProperty(el, "overflowX") == "hidden" || el.clientHeight == 0) {
      return qx.html.Style.getBorderBottom(el);
    }

    return Math.max(0, el.offsetHeight - el.clientTop - el.clientHeight);
  }
}
else
{
  qx.html.Dimension.getInsetLeft   = function(el) { return qx.html.Style.getBorderLeft(el); }
  qx.html.Dimension.getInsetTop    = function(el) { return qx.html.Style.getBorderTop(el); }

  qx.html.Dimension.getInsetRight  = function(el) {
    // Alternative method if clientWidth is unavailable
    // clientWidth == 0 could mean both: unavailable or really 0
    if (el.clientWidth == 0) {
      var ov = qx.html.Style.getStyleProperty(el, "overflow");
      var sbv = ov == "scroll" || ov == "-moz-scrollbars-vertical" ? 16 : 0;
      return Math.max(0, qx.html.Style.getBorderRight(el) + sbv);
    }

    return Math.max(0, el.offsetWidth - el.clientWidth - qx.html.Style.getBorderLeft(el));
  }

  qx.html.Dimension.getInsetBottom = function(el) {
    // Alternative method if clientHeight is unavailable
    // clientHeight == 0 could mean both: unavailable or really 0
    if (el.clientHeight == 0) {
      var ov = qx.html.Style.getStyleProperty(el, "overflow");
      var sbv = ov == "scroll" || ov == "-moz-scrollbars-horizontal" ? 16 : 0;
      return Math.max(0, qx.html.Style.getBorderBottom(el) + sbv);
    }

    return Math.max(0, el.offsetHeight - el.clientHeight - qx.html.Style.getBorderTop(el));
  }
}


// Scrollbar
qx.html.Dimension.getScrollBarSizeLeft   = function(el) { return 0; }
qx.html.Dimension.getScrollBarSizeTop    = function(el) { return 0; }
qx.html.Dimension.getScrollBarSizeRight  = function(el) { return qx.html.Dimension.getInsetRight(el)  - qx.html.Style.getBorderRight(el); }
qx.html.Dimension.getScrollBarSizeBottom = function(el) { return qx.html.Dimension.getInsetBottom(el) - qx.html.Style.getBorderBottom(el); }

qx.html.Dimension.getScrollBarVisibleX   = function(el) { return qx.html.Dimension.getScrollBarSizeRight(el)  > 0; }
qx.html.Dimension.getScrollBarVisibleY   = function(el) { return qx.html.Dimension.getScrollBarSizeBottom(el) > 0; }
