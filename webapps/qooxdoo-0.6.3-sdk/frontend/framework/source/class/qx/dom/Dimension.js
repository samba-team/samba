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

qx.OO.defineClass("qx.dom.Dimension");

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
qx.dom.Dimension.getOuterWidth  = function(el) { return qx.dom.Dimension.getBoxWidth(el)  + qx.dom.Style.getMarginLeft(el) + qx.dom.Style.getMarginRight(el); }
qx.dom.Dimension.getOuterHeight = function(el) { return qx.dom.Dimension.getBoxHeight(el) + qx.dom.Style.getMarginTop(el)  + qx.dom.Style.getMarginBottom(el); }

qx.dom.Dimension.getBoxWidthForZeroHeight = function(el)
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

qx.dom.Dimension.getBoxHeightForZeroWidth = function(el)
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

qx.dom.Dimension.getBoxWidth = function(el) {
  return el.offsetWidth;
}

qx.dom.Dimension.getBoxHeight = function(el) {
  return el.offsetHeight;
}

if (qx.sys.Client.getInstance().isGecko())
{
  qx.dom.Dimension.getAreaWidth = function(el)
  {
    // 0 in clientWidth could mean both: That it is really 0 or
    // that the element is not rendered by the browser and
    // therefore it is 0, too

    // In Gecko based browsers there is sometimes another
    // behaviour: The clientHeight is equal to the border
    // sum. This is normally not correct and so we
    // fix this value with a more complex calculation.

    // (Mozilla/5.0 (Windows; U; Windows NT 5.1; de-DE; rv:1.7.6) Gecko/20050223 Firefox/1.0.1)

    if (el.clientWidth != 0 && el.clientWidth != (qx.dom.Style.getBorderLeft(el) + qx.dom.Style.getBorderRight(el)))
    {
      return el.clientWidth;
    }
    else
    {
      return qx.dom.Dimension.getBoxWidth(el) - qx.dom.Dimension.getInsetLeft(el) - qx.dom.Dimension.getInsetRight(el);
    }
  }

  qx.dom.Dimension.getAreaHeight = function(el)
  {
    // 0 in clientHeight could mean both: That it is really 0 or
    // that the element is not rendered by the browser and
    // therefore it is 0, too

    // In Gecko based browsers there is sometimes another
    // behaviour: The clientHeight is equal to the border
    // sum. This is normally not correct and so we
    // fix this value with a more complex calculation.

    // (Mozilla/5.0 (Windows; U; Windows NT 5.1; de-DE; rv:1.7.6) Gecko/20050223 Firefox/1.0.1)

    if (el.clientHeight != 0 && el.clientHeight != (qx.dom.Style.getBorderTop(el) + qx.dom.Style.getBorderBottom(el)))
    {
      return el.clientHeight;
    }
    else
    {
      return qx.dom.Dimension.getBoxHeight(el) - qx.dom.Dimension.getInsetTop(el) - qx.dom.Dimension.getInsetBottom(el);
    }
  }
}
else
{
  qx.dom.Dimension.getAreaWidth = function(el)
  {
    // 0 in clientWidth could mean both: That it is really 0 or
    // that the element is not rendered by the browser and
    // therefore it is 0, too

    return el.clientWidth != 0 ? el.clientWidth : (qx.dom.Dimension.getBoxWidth(el) - qx.dom.Dimension.getInsetLeft(el) - qx.dom.Dimension.getInsetRight(el));
  }

  qx.dom.Dimension.getAreaHeight = function(el)
  {
    // 0 in clientHeight could mean both: That it is really 0 or
    // that the element is not rendered by the browser and
    // therefore it is 0, too

    return el.clientHeight != 0 ? el.clientHeight : (qx.dom.Dimension.getBoxHeight(el) - qx.dom.Dimension.getInsetTop(el) - qx.dom.Dimension.getInsetBottom(el));
  }
}

qx.dom.Dimension.getInnerWidth  = function(el) { return qx.dom.Dimension.getAreaWidth(el) - qx.dom.Style.getPaddingLeft(el) - qx.dom.Style.getPaddingRight(el); }
qx.dom.Dimension.getInnerHeight = function(el) { return qx.dom.Dimension.getAreaHeight(el) - qx.dom.Style.getPaddingTop(el)  - qx.dom.Style.getPaddingBottom(el); }




// Insets
if (qx.sys.Client.getInstance().isMshtml())
{
  qx.dom.Dimension.getInsetLeft   = function(el) { return el.clientLeft; }
  qx.dom.Dimension.getInsetTop    = function(el) { return el.clientTop; }
  qx.dom.Dimension.getInsetRight  = function(el) {
    if(qx.dom.Style.getStyleProperty(el, "overflowY") == "hidden" || el.clientWidth == 0) {
      return qx.dom.Style.getBorderRight(el);
    }

    return Math.max(0, el.offsetWidth - el.clientLeft - el.clientWidth);
  }

  qx.dom.Dimension.getInsetBottom = function(el) {
    if(qx.dom.Style.getStyleProperty(el, "overflowX") == "hidden" || el.clientHeight == 0) {
      return qx.dom.Style.getBorderBottom(el);
    }

    return Math.max(0, el.offsetHeight - el.clientTop - el.clientHeight);
  }
}
else
{
  qx.dom.Dimension.getInsetLeft   = function(el) { return qx.dom.Style.getBorderLeft(el); }
  qx.dom.Dimension.getInsetTop    = function(el) { return qx.dom.Style.getBorderTop(el); }

  qx.dom.Dimension.getInsetRight  = function(el) {
    // Alternative method if clientWidth is unavailable
    // clientWidth == 0 could mean both: unavailable or really 0
    if (el.clientWidth == 0) {
      var ov = qx.dom.Style.getStyleProperty(el, "overflow");
      var sbv = ov == "scroll" || ov == "-moz-scrollbars-vertical" ? 16 : 0;
      return Math.max(0, qx.dom.Style.getBorderRight(el) + sbv);
    }

    return Math.max(0, el.offsetWidth - el.clientWidth - qx.dom.Style.getBorderLeft(el));
  }

  qx.dom.Dimension.getInsetBottom = function(el) {
    // Alternative method if clientHeight is unavailable
    // clientHeight == 0 could mean both: unavailable or really 0
    if (el.clientHeight == 0) {
      var ov = qx.dom.Style.getStyleProperty(el, "overflow");
      var sbv = ov == "scroll" || ov == "-moz-scrollbars-horizontal" ? 16 : 0;
      return Math.max(0, qx.dom.Style.getBorderBottom(el) + sbv);
    }

    return Math.max(0, el.offsetHeight - el.clientHeight - qx.dom.Style.getBorderTop(el));
  }
}


// Scrollbar
qx.dom.Dimension.getScrollBarSizeLeft   = function(el) { return 0; }
qx.dom.Dimension.getScrollBarSizeTop    = function(el) { return 0; }
qx.dom.Dimension.getScrollBarSizeRight  = function(el) { return qx.dom.Dimension.getInsetRight(el)  - qx.dom.Style.getBorderRight(el); }
qx.dom.Dimension.getScrollBarSizeBottom = function(el) { return qx.dom.Dimension.getInsetBottom(el) - qx.dom.Style.getBorderBottom(el); }

qx.dom.Dimension.getScrollBarVisibleX   = function(el) { return qx.dom.Dimension.getScrollBarSizeRight(el)  > 0; }
qx.dom.Dimension.getScrollBarVisibleY   = function(el) { return qx.dom.Dimension.getScrollBarSizeBottom(el) > 0; }
