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

qx.OO.defineClass("qx.html.Location");

qx.html.Location.getPageOuterLeft     = function(el) { return qx.html.Location.getPageBoxLeft(el)     - qx.html.Style.getMarginLeft(el); }
qx.html.Location.getPageOuterTop      = function(el) { return qx.html.Location.getPageBoxTop(el)      - qx.html.Style.getMarginTop(el); }
qx.html.Location.getPageOuterRight    = function(el) { return qx.html.Location.getPageBoxRight(el)    + qx.html.Style.getMarginRight(el); }
qx.html.Location.getPageOuterBottom   = function(el) { return qx.html.Location.getPageBoxBottom(el)   + qx.html.Style.getMarginBottom(el); }

qx.html.Location.getClientOuterLeft   = function(el) { return qx.html.Location.getClientBoxLeft(el)   - qx.html.Style.getMarginLeft(el); }
qx.html.Location.getClientOuterTop    = function(el) { return qx.html.Location.getClientBoxTop(el)    - qx.html.Style.getMarginTop(el); }
qx.html.Location.getClientOuterRight  = function(el) { return qx.html.Location.getClientBoxRight(el)  + qx.html.Style.getMarginRight(el); }
qx.html.Location.getClientOuterBottom = function(el) { return qx.html.Location.getClientBoxBottom(el) + qx.html.Style.getMarginBottom(el); }


qx.html.Location.getClientBoxLeft = function(el) {}
qx.html.Location.getClientBoxTop = function(el) {}
qx.html.Location.getClientBoxRight = function(el) {}
qx.html.Location.getClientBoxBottom = function(el) {}
qx.html.Location.getPageBoxLeft = function(el) {}
qx.html.Location.getPageBoxTop = function(el) {}
qx.html.Location.getPageBoxRight = function(el) {}
qx.html.Location.getPageBoxBottom = function(el) {}

if (qx.core.Client.getInstance().isMshtml())
{
  qx.html.Location.getClientBoxLeft   = function(el) { return el.getBoundingClientRect().left; }
  qx.html.Location.getClientBoxTop    = function(el) { return el.getBoundingClientRect().top; }

  qx.html.Location.getPageBoxLeft     = function(el) { return qx.html.Location.getClientBoxLeft(el)  + qx.html.Scroll.getLeftSum(el); }
  qx.html.Location.getPageBoxTop      = function(el) { return qx.html.Location.getClientBoxTop(el)   + qx.html.Scroll.getTopSum(el); }
}
else if (qx.core.Client.getInstance().isGecko())
{
  qx.html.Location.getClientBoxLeft   = function(el) { return qx.html.Location.getClientAreaLeft(el) - qx.html.Style.getBorderLeft(el); }
  qx.html.Location.getClientBoxTop    = function(el) { return qx.html.Location.getClientAreaTop(el)  - qx.html.Style.getBorderTop(el); }

  qx.html.Location.getPageBoxLeft     = function(el) { return qx.html.Location.getPageAreaLeft(el)   - qx.html.Style.getBorderLeft(el); }
  qx.html.Location.getPageBoxTop      = function(el) { return qx.html.Location.getPageAreaTop(el)    - qx.html.Style.getBorderTop(el); }
}
else
{
  qx.html.Location.getPageBoxLeft = function(el)
  {
    var sum = el.offsetLeft;
    while (el.tagName.toLowerCase() != "body")
    {
      el = el.offsetParent;
      sum += el.offsetLeft;
    }

    return sum;
  }

  qx.html.Location.getPageBoxTop = function(el)
  {
    var sum = el.offsetTop;
    while (el.tagName.toLowerCase() != "body")
    {
      el = el.offsetParent;
      sum += el.offsetTop;
    }

    return sum;
  }

  qx.html.Location.getClientBoxLeft = function(el)
  {
    var sum = el.offsetLeft;
    while (el.tagName.toLowerCase() != "body")
    {
      el = el.offsetParent;
      sum += el.offsetLeft - el.scrollLeft;
    }

    return sum;
  }

  qx.html.Location.getClientBoxTop = function(el)
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

if (qx.core.Client.getInstance().isMshtml())
{
  qx.html.Location.getClientBoxRight  = function(el) { return el.getBoundingClientRect().right; }
  qx.html.Location.getClientBoxBottom = function(el) { return el.getBoundingClientRect().bottom; }

  qx.html.Location.getPageBoxRight    = function(el) { return qx.html.Location.getClientBoxRight(el)  + qx.html.Scroll.getLeftSum(el); }
  qx.html.Location.getPageBoxBottom   = function(el) { return qx.html.Location.getClientBoxBottom(el) + qx.html.Scroll.getTopSum(el);  }
}
else
{
  qx.html.Location.getClientBoxRight  = function(el) { return qx.html.Location.getClientBoxLeft(el) + qx.html.Dimension.getBoxWidth(el); }
  qx.html.Location.getClientBoxBottom = function(el) { return qx.html.Location.getClientBoxTop(el)  + qx.html.Dimension.getBoxHeight(el); }

  qx.html.Location.getPageBoxRight    = function(el) { return qx.html.Location.getPageBoxLeft(el)   + qx.html.Dimension.getBoxWidth(el); }
  qx.html.Location.getPageBoxBottom   = function(el) { return qx.html.Location.getPageBoxTop(el)    + qx.html.Dimension.getBoxHeight(el); }
}


qx.html.Location.getClientAreaLeft = function(el) {};
qx.html.Location.getClientAreaTop = function(el) {};
qx.html.Location.getPageAreaLeft = function(el) {};
qx.html.Location.getPageAreaTop = function(el) {};

if (qx.core.Client.getInstance().isGecko())
{
  qx.html.Location.getPageAreaLeft = function(el) {
    return el.ownerDocument.getBoxObjectFor(el).x;
  }

  qx.html.Location.getPageAreaTop = function(el) {
    return el.ownerDocument.getBoxObjectFor(el).y;
  }

  // We need to subtract the scroll position of all parent containers (bug #186229).
  qx.html.Location.getClientAreaLeft = function(el) {
    return qx.html.Location.getPageAreaLeft(el) - qx.html.Scroll.getLeftSum(el);
  }

  // We need to subtract the scroll position of all parent containers (bug #186229).
  qx.html.Location.getClientAreaTop = function(el) {
    return qx.html.Location.getPageAreaTop(el) - qx.html.Scroll.getTopSum(el);
  }
}
else
{
  qx.html.Location.getClientAreaLeft = function(el) { return qx.html.Location.getClientBoxLeft(el) + qx.html.Style.getBorderLeft(el); }
  qx.html.Location.getClientAreaTop  = function(el) { return qx.html.Location.getClientBoxTop(el)  + qx.html.Style.getBorderTop(el); }

  qx.html.Location.getPageAreaLeft = function(el) { return qx.html.Location.getPageBoxLeft(el) + qx.html.Style.getBorderLeft(el); }
  qx.html.Location.getPageAreaTop  = function(el) { return qx.html.Location.getPageBoxTop(el)  + qx.html.Style.getBorderTop(el); }
}



qx.html.Location.getClientAreaRight   = function(el) { return qx.html.Location.getClientAreaLeft(el)  + qx.html.Dimension.getAreaWidth(el);  }
qx.html.Location.getClientAreaBottom  = function(el) { return qx.html.Location.getClientAreaTop(el)   + qx.html.Dimension.getAreaHeight(el); }

qx.html.Location.getPageAreaRight     = function(el) { return qx.html.Location.getPageAreaLeft(el)    + qx.html.Dimension.getAreaWidth(el);  }
qx.html.Location.getPageAreaBottom    = function(el) { return qx.html.Location.getPageAreaTop(el)     + qx.html.Dimension.getAreaHeight(el); }




qx.html.Location.getClientInnerLeft   = function(el) { return qx.html.Location.getClientAreaLeft(el)  + qx.html.Style.getPaddingLeft(el); }
qx.html.Location.getClientInnerTop    = function(el) { return qx.html.Location.getClientAreaTop(el)   + qx.html.Style.getPaddingTop(el);  }
qx.html.Location.getClientInnerRight  = function(el) { return qx.html.Location.getClientInnerLeft(el) + qx.html.Dimension.getInnerWidth(el);  }
qx.html.Location.getClientInnerBottom = function(el) { return qx.html.Location.getClientInnerTop(el)  + qx.html.Dimension.getInnerHeight(el); }

qx.html.Location.getPageInnerLeft     = function(el) { return qx.html.Location.getPageAreaLeft(el)    + qx.html.Style.getPaddingLeft(el); }
qx.html.Location.getPageInnerTop      = function(el) { return qx.html.Location.getPageAreaTop(el)     + qx.html.Style.getPaddingTop(el);  }
qx.html.Location.getPageInnerRight    = function(el) { return qx.html.Location.getPageInnerLeft(el)   + qx.html.Dimension.getInnerWidth(el);  }
qx.html.Location.getPageInnerBottom   = function(el) { return qx.html.Location.getPageInnerTop(el)    + qx.html.Dimension.getInnerHeight(el); }


// Screen
qx.html.Location.getScreenBoxLeft = function(el) {};
qx.html.Location.getScreenBoxTop = function(el) {};

if (qx.core.Client.getInstance().isGecko())
{
  /*
    screenX and screenY seem to return the distance to the box
    and not to the area. Confusing, especially as the x and y properties
    of the BoxObject return the distance to the area.
  */

  qx.html.Location.getScreenBoxLeft = function(el)
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

  qx.html.Location.getScreenBoxTop = function(el)
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
  qx.html.Location.getScreenBoxLeft = function(el) { return qx.html.Location.getScreenDocumentLeft(el) + qx.html.Location.getPageBoxLeft(el); }
  qx.html.Location.getScreenBoxTop  = function(el) { return qx.html.Location.getScreenDocumentTop(el) + qx.html.Location.getPageBoxTop(el); }
}

qx.html.Location.getScreenBoxRight    = function(el) { return qx.html.Location.getScreenBoxLeft(el)    + qx.html.Dimension.getBoxWidth(el); }
qx.html.Location.getScreenBoxBottom   = function(el) { return qx.html.Location.getScreenBoxTop(el)     + qx.html.Dimension.getBoxHeight(el); }

qx.html.Location.getScreenOuterLeft   = function(el) { return qx.html.Location.getScreenBoxLeft(el)    - qx.html.Style.getMarginLeft(el); }
qx.html.Location.getScreenOuterTop    = function(el) { return qx.html.Location.getScreenBoxTop(el)     - qx.html.Style.getMarginTop(el); }
qx.html.Location.getScreenOuterRight  = function(el) { return qx.html.Location.getScreenBoxRight(el)   + qx.html.Style.getMarginRight(el); }
qx.html.Location.getScreenOuterBottom = function(el) { return qx.html.Location.getScreenBoxBottom(el)  + qx.html.Style.getMarginBottom(el); }

qx.html.Location.getScreenAreaLeft    = function(el) { return qx.html.Location.getScreenBoxLeft(el)    + qx.html.Dimension.getInsetLeft(el); }
qx.html.Location.getScreenAreaTop     = function(el) { return qx.html.Location.getScreenBoxTop(el)     + qx.html.Dimension.getInsetTop(el); }
qx.html.Location.getScreenAreaRight   = function(el) { return qx.html.Location.getScreenBoxRight(el)   - qx.html.Dimension.getInsetRight(el); }
qx.html.Location.getScreenAreaBottom  = function(el) { return qx.html.Location.getScreenBoxBottom(el)  - qx.html.Dimension.getInsetBottom(el); }

qx.html.Location.getScreenInnerLeft   = function(el) { return qx.html.Location.getScreenAreaLeft(el)   + qx.html.Style.getPaddingLeft(el); }
qx.html.Location.getScreenInnerTop    = function(el) { return qx.html.Location.getScreenAreaTop(el)    + qx.html.Style.getPaddingTop(el); }
qx.html.Location.getScreenInnerRight  = function(el) { return qx.html.Location.getScreenAreaRight(el)  - qx.html.Style.getPaddingRight(el); }
qx.html.Location.getScreenInnerBottom = function(el) { return qx.html.Location.getScreenAreaBottom(el) - qx.html.Style.getPaddingBottom(el); }


qx.html.Location.getScreenDocumentLeft = function(el) {};
qx.html.Location.getScreenDocumentTop = function(el) {};
qx.html.Location.getScreenDocumentRight = function(el) {};
qx.html.Location.getScreenDocumentBottom = function(el) {};

if (qx.core.Client.getInstance().isGecko())
{
  /*
    Notice:
      This doesn't work like the mshtml method:
      el.ownerDocument.defaultView.screenX;
  */

  // Tested in Gecko 1.7.5
  qx.html.Location.getScreenDocumentLeft = function(el) { return qx.html.Location.getScreenOuterLeft(el.ownerDocument.body); }
  qx.html.Location.getScreenDocumentTop = function(el) { return qx.html.Location.getScreenOuterTop(el.ownerDocument.body); }
  qx.html.Location.getScreenDocumentRight = function(el) { return qx.html.Location.getScreenOuterRight(el.ownerDocument.body); }
  qx.html.Location.getScreenDocumentBottom = function(el) { return qx.html.Location.getScreenOuterBottom(el.ownerDocument.body); }
}
else
{
  // Tested in Opera 7.6b3 and Mshtml 6.0 (XP-SP2)
  // What's up with khtml (Safari/Konq)?
  qx.html.Location.getScreenDocumentLeft = function(el) { return el.document.parentWindow.screenLeft; }
  qx.html.Location.getScreenDocumentTop = function(el) { return el.document.parentWindow.screenTop; }
  qx.html.Location.getScreenDocumentRight = function(el) {}
  qx.html.Location.getScreenDocumentBottom = function(el) {}
}
