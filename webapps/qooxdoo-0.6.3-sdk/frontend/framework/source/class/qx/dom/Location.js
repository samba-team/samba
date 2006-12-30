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

qx.OO.defineClass("qx.dom.Location");

qx.dom.Location.getPageOuterLeft     = function(el) { return qx.dom.Location.getPageBoxLeft(el)     - qx.dom.Style.getMarginLeft(el); }
qx.dom.Location.getPageOuterTop      = function(el) { return qx.dom.Location.getPageBoxTop(el)      - qx.dom.Style.getMarginTop(el); }
qx.dom.Location.getPageOuterRight    = function(el) { return qx.dom.Location.getPageBoxRight(el)    + qx.dom.Style.getMarginRight(el); }
qx.dom.Location.getPageOuterBottom   = function(el) { return qx.dom.Location.getPageBoxBottom(el)   + qx.dom.Style.getMarginBottom(el); }

qx.dom.Location.getClientOuterLeft   = function(el) { return qx.dom.Location.getClientBoxLeft(el)   - qx.dom.Style.getMarginLeft(el); }
qx.dom.Location.getClientOuterTop    = function(el) { return qx.dom.Location.getClientBoxTop(el)    - qx.dom.Style.getMarginTop(el); }
qx.dom.Location.getClientOuterRight  = function(el) { return qx.dom.Location.getClientBoxRight(el)  + qx.dom.Style.getMarginRight(el); }
qx.dom.Location.getClientOuterBottom = function(el) { return qx.dom.Location.getClientBoxBottom(el) + qx.dom.Style.getMarginBottom(el); }


if (qx.sys.Client.getInstance().isMshtml())
{
  qx.dom.Location.getClientBoxLeft   = function(el) { return el.getBoundingClientRect().left; }
  qx.dom.Location.getClientBoxTop    = function(el) { return el.getBoundingClientRect().top; }

  qx.dom.Location.getPageBoxLeft     = function(el) { return qx.dom.Location.getClientBoxLeft(el)  + qx.dom.Scroll.getLeftSum(el); }
  qx.dom.Location.getPageBoxTop      = function(el) { return qx.dom.Location.getClientBoxTop(el)   + qx.dom.Scroll.getTopSum(el); }
}
else if (qx.sys.Client.getInstance().isGecko())
{
  qx.dom.Location.getClientBoxLeft   = function(el) { return qx.dom.Location.getClientAreaLeft(el) - qx.dom.Style.getBorderLeft(el); }
  qx.dom.Location.getClientBoxTop    = function(el) { return qx.dom.Location.getClientAreaTop(el)  - qx.dom.Style.getBorderTop(el); }

  qx.dom.Location.getPageBoxLeft     = function(el) { return qx.dom.Location.getPageAreaLeft(el)   - qx.dom.Style.getBorderLeft(el); }
  qx.dom.Location.getPageBoxTop      = function(el) { return qx.dom.Location.getPageAreaTop(el)    - qx.dom.Style.getBorderTop(el); }
}
else
{
  qx.dom.Location.getPageBoxLeft = function(el)
  {
    var sum = el.offsetLeft;
    while (el.tagName.toLowerCase() != "body")
    {
      el = el.offsetParent;
      sum += el.offsetLeft;
    }

    return sum;
  }

  qx.dom.Location.getPageBoxTop = function(el)
  {
    var sum = el.offsetTop;
    while (el.tagName.toLowerCase() != "body")
    {
      el = el.offsetParent;
      sum += el.offsetTop;
    }

    return sum;
  }

  qx.dom.Location.getClientBoxLeft = function(el)
  {
    var sum = el.offsetLeft;
    while (el.tagName.toLowerCase() != "body")
    {
      el = el.offsetParent;
      sum += el.offsetLeft - el.scrollLeft;
    }

    return sum;
  }

  qx.dom.Location.getClientBoxTop = function(el)
  {
    var sum = el.offsetTop;
    while (el.tagName.toLowerCase() != "body")
    {
      el = el.offsetParent;
      sum += el.offsetTop - el.scrollTop;
    }

    return sum;
  }
}

if (qx.sys.Client.getInstance().isMshtml())
{
  qx.dom.Location.getClientBoxRight  = function(el) { return el.getBoundingClientRect().right; }
  qx.dom.Location.getClientBoxBottom = function(el) { return el.getBoundingClientRect().bottom; }

  qx.dom.Location.getPageBoxRight    = function(el) { return qx.dom.Location.getClientBoxRight(el)  + qx.dom.Scroll.getLeftSum(el); }
  qx.dom.Location.getPageBoxBottom   = function(el) { return qx.dom.Location.getClientBoxBottom(el) + qx.dom.Scroll.getTopSum(el);  }
}
else
{
  qx.dom.Location.getClientBoxRight  = function(el) { return qx.dom.Location.getClientBoxLeft(el) + qx.dom.Dimension.getBoxWidth(el); }
  qx.dom.Location.getClientBoxBottom = function(el) { return qx.dom.Location.getClientBoxTop(el)  + qx.dom.Dimension.getBoxHeight(el); }

  qx.dom.Location.getPageBoxRight    = function(el) { return qx.dom.Location.getPageBoxLeft(el)   + qx.dom.Dimension.getBoxWidth(el); }
  qx.dom.Location.getPageBoxBottom   = function(el) { return qx.dom.Location.getPageBoxTop(el)    + qx.dom.Dimension.getBoxHeight(el); }
}

if (qx.sys.Client.getInstance().isGecko())
{
  qx.dom.Location.getPageAreaLeft = function(el) {
    return el.ownerDocument.getBoxObjectFor(el).x;
  }

  qx.dom.Location.getPageAreaTop = function(el) {
    return el.ownerDocument.getBoxObjectFor(el).y;
  }

  // We need to subtract the scroll position of all parent containers (bug #186229).
  qx.dom.Location.getClientAreaLeft = function(el) {
    return qx.dom.Location.getPageAreaLeft(el) - qx.dom.Scroll.getLeftSum(el);
  }

  // We need to subtract the scroll position of all parent containers (bug #186229).
  qx.dom.Location.getClientAreaTop = function(el) {
    return qx.dom.Location.getPageAreaTop(el) - qx.dom.Scroll.getTopSum(el);
  }
}
else
{
  qx.dom.Location.getClientAreaLeft = function(el) { return qx.dom.Location.getClientBoxLeft(el) + qx.dom.Style.getBorderLeft(el); }
  qx.dom.Location.getClientAreaTop  = function(el) { return qx.dom.Location.getClientBoxTop(el)  + qx.dom.Style.getBorderTop(el); }

  qx.dom.Location.getPageAreaLeft = function(el) { return qx.dom.Location.getPageBoxLeft(el) + qx.dom.Style.getBorderLeft(el); }
  qx.dom.Location.getPageAreaTop  = function(el) { return qx.dom.Location.getPageBoxTop(el)  + qx.dom.Style.getBorderTop(el); }
}



qx.dom.Location.getClientAreaRight   = function(el) { return qx.dom.Location.getClientAreaLeft(el)  + qx.dom.Dimension.getAreaWidth(el);  }
qx.dom.Location.getClientAreaBottom  = function(el) { return qx.dom.Location.getClientAreaTop(el)   + qx.dom.Dimension.getAreaHeight(el); }

qx.dom.Location.getPageAreaRight     = function(el) { return qx.dom.Location.getPageAreaLeft(el)    + qx.dom.Dimension.getAreaWidth(el);  }
qx.dom.Location.getPageAreaBottom    = function(el) { return qx.dom.Location.getPageAreaTop(el)     + qx.dom.Dimension.getAreaHeight(el); }




qx.dom.Location.getClientInnerLeft   = function(el) { return qx.dom.Location.getClientAreaLeft(el)  + qx.dom.Style.getPaddingLeft(el); }
qx.dom.Location.getClientInnerTop    = function(el) { return qx.dom.Location.getClientAreaTop(el)   + qx.dom.Style.getPaddingTop(el);  }
qx.dom.Location.getClientInnerRight  = function(el) { return qx.dom.Location.getClientInnerLeft(el) + qx.dom.Dimension.getInnerWidth(el);  }
qx.dom.Location.getClientInnerBottom = function(el) { return qx.dom.Location.getClientInnerTop(el)  + qx.dom.Dimension.getInnerHeight(el); }

qx.dom.Location.getPageInnerLeft     = function(el) { return qx.dom.Location.getPageAreaLeft(el)    + qx.dom.Style.getPaddingLeft(el); }
qx.dom.Location.getPageInnerTop      = function(el) { return qx.dom.Location.getPageAreaTop(el)     + qx.dom.Style.getPaddingTop(el);  }
qx.dom.Location.getPageInnerRight    = function(el) { return qx.dom.Location.getPageInnerLeft(el)   + qx.dom.Dimension.getInnerWidth(el);  }
qx.dom.Location.getPageInnerBottom   = function(el) { return qx.dom.Location.getPageInnerTop(el)    + qx.dom.Dimension.getInnerHeight(el); }


// Screen
if (qx.sys.Client.getInstance().isGecko())
{
  /*
    screenX and screenY seem to return the distance to the box
    and not to the area. Confusing, especially as the x and y properties
    of the BoxObject return the distance to the area.
  */

  qx.dom.Location.getScreenBoxLeft = function(el)
  {
    // We need to subtract the scroll position of all
    // parent containers (bug #186229).
    var sum = 0;
    var p = el.parentNode;
    while (p.nodeType == 1) {
      sum += p.scrollLeft;
      p = p.parentNode;
    }

    return el.ownerDocument.getBoxObjectFor(el).screenX - sum;
  }

  qx.dom.Location.getScreenBoxTop = function(el)
  {
    // We need to subtract the scroll position of all
    // parent containers (bug #186229).
    var sum = 0;
    var p = el.parentNode;
    while (p.nodeType == 1) {
      sum += p.scrollTop;
      p = p.parentNode;
    }

    return el.ownerDocument.getBoxObjectFor(el).screenY - sum;
  }
}
else
{
  // Hope this works in khtml, too (opera 7.6p3 seems to be ok)
  qx.dom.Location.getScreenBoxLeft = function(el) { return qx.dom.Location.getScreenDocumentLeft(el) + qx.dom.Location.getPageBoxLeft(el); }
  qx.dom.Location.getScreenBoxTop  = function(el) { return qx.dom.Location.getScreenDocumentTop(el) + qx.dom.Location.getPageBoxTop(el); }
}

qx.dom.Location.getScreenBoxRight    = function(el) { return qx.dom.Location.getScreenBoxLeft(el)    + qx.dom.Dimension.getBoxWidth(el); }
qx.dom.Location.getScreenBoxBottom   = function(el) { return qx.dom.Location.getScreenBoxTop(el)     + qx.dom.Dimension.getBoxHeight(el); }

qx.dom.Location.getScreenOuterLeft   = function(el) { return qx.dom.Location.getScreenBoxLeft(el)    - qx.dom.Style.getMarginLeft(el); }
qx.dom.Location.getScreenOuterTop    = function(el) { return qx.dom.Location.getScreenBoxTop(el)     - qx.dom.Style.getMarginTop(el); }
qx.dom.Location.getScreenOuterRight  = function(el) { return qx.dom.Location.getScreenBoxRight(el)   + qx.dom.Style.getMarginRight(el); }
qx.dom.Location.getScreenOuterBottom = function(el) { return qx.dom.Location.getScreenBoxBottom(el)  + qx.dom.Style.getMarginBottom(el); }

qx.dom.Location.getScreenAreaLeft    = function(el) { return qx.dom.Location.getScreenBoxLeft(el)    + qx.dom.Dimension.getInsetLeft(el); }
qx.dom.Location.getScreenAreaTop     = function(el) { return qx.dom.Location.getScreenBoxTop(el)     + qx.dom.Dimension.getInsetTop(el); }
qx.dom.Location.getScreenAreaRight   = function(el) { return qx.dom.Location.getScreenBoxRight(el)   - qx.dom.Dimension.getInsetRight(el); }
qx.dom.Location.getScreenAreaBottom  = function(el) { return qx.dom.Location.getScreenBoxBottom(el)  - qx.dom.Dimension.getInsetBottom(el); }

qx.dom.Location.getScreenInnerLeft   = function(el) { return qx.dom.Location.getScreenAreaLeft(el)   + qx.dom.Style.getPaddingLeft(el); }
qx.dom.Location.getScreenInnerTop    = function(el) { return qx.dom.Location.getScreenAreaTop(el)    + qx.dom.Style.getPaddingTop(el); }
qx.dom.Location.getScreenInnerRight  = function(el) { return qx.dom.Location.getScreenAreaRight(el)  - qx.dom.Style.getPaddingRight(el); }
qx.dom.Location.getScreenInnerBottom = function(el) { return qx.dom.Location.getScreenAreaBottom(el) - qx.dom.Style.getPaddingBottom(el); }


if (qx.sys.Client.getInstance().isGecko())
{
  /*
    Notice:
      This doesn't work like the mshtml method:
      el.ownerDocument.defaultView.screenX;
  */

  // Tested in Gecko 1.7.5
  qx.dom.Location.getScreenDocumentLeft = function(el) { return qx.dom.Location.getScreenOuterLeft(el.ownerDocument.body); }
  qx.dom.Location.getScreenDocumentTop = function(el) { return qx.dom.Location.getScreenOuterTop(el.ownerDocument.body); }
  qx.dom.Location.getScreenDocumentRight = function(el) { return qx.dom.Location.getScreenOuterRight(el.ownerDocument.body); }
  qx.dom.Location.getScreenDocumentBottom = function(el) { return qx.dom.Location.getScreenOuterBottom(el.ownerDocument.body); }
}
else
{
  // Tested in Opera 7.6b3 and Mshtml 6.0 (XP-SP2)
  // What's up with khtml (Safari/Konq)?
  qx.dom.Location.getScreenDocumentLeft = function(el) { return el.document.parentWindow.screenLeft; }
  qx.dom.Location.getScreenDocumentTop = function(el) { return el.document.parentWindow.screenTop; }
  qx.dom.Location.getScreenDocumentRight = function(el) {}
  qx.dom.Location.getScreenDocumentBottom = function(el) {}
}
