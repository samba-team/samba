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

qx.OO.defineClass("qx.dom.Offset");

/*
Mozilla seems to be a little buggy here.
Mozilla/5.0 (Windows; U; Windows NT 5.1; de-DE; rv:1.7.5) Gecko/20041108 Firefox/1.0

It calculates some borders and/or paddings to the offsetProperties.
*/
if (qx.sys.Client.getInstance().isGecko())
{
  qx.dom.Offset.getLeft = function(el)
  {
    var val = el.offsetLeft;
    var pa = el.parentNode;

    var pose = qx.dom.Style.getStyleProperty(el, "position");
    var posp = qx.dom.Style.getStyleProperty(pa, "position");

    // If element is positioned non-static: Substract the border of the element
    if (pose != "absolute" && pose != "fixed") {
      val -= qx.dom.Style.getBorderLeft(pa);
    }

    // If parent is positioned static: Substract the border of the first
    // parent element which is ab positioned non-static.
    if (posp != "absolute" && posp != "fixed")
    {
      while(pa)
      {
        pa = pa.parentNode;

        if (!pa || qx.util.Validation.isInvalidString(pa.tagName)) {
          break;
        }

        var posi = qx.dom.Style.getStyleProperty(pa, "position");

        if (posi == "absolute" || posi == "fixed") {
          val -= qx.dom.Style.getBorderLeft(pa) + qx.dom.Style.getPaddingLeft(pa);
          break;
        }
      }
    }

    return val;
  }

  qx.dom.Offset.getTop = function(el)
  {
    var val = el.offsetTop;
    var pa = el.parentNode;

    var pose = qx.dom.Style.getStyleProperty(el, "position");
    var posp = qx.dom.Style.getStyleProperty(pa, "position");

    // If element is positioned non-static: Substract the border of the element
    if (pose != "absolute" && pose != "fixed") {
      val -= qx.dom.Style.getBorderTop(pa);
    }

    // If parent is positioned static: Substract the border of the first
    // parent element which is ab positioned non-static.
    if (posp != "absolute" && posp != "fixed")
    {
      while(pa)
      {
        pa = pa.parentNode;

        if (!pa || qx.util.Validation.isInvalidString(pa.tagName)) {
          break;
        }

        var posi = qx.dom.Style.getStyleProperty(pa, "position");

        if (posi == "absolute" || posi == "fixed") {
          val -= qx.dom.Style.getBorderTop(pa) + qx.dom.Style.getPaddingTop(pa);
          break;
        }
      }
    }

    return val;
  }
}
else
{
  qx.dom.Offset.getLeft = function(el) {
    return el.offsetLeft;
  }

  qx.dom.Offset.getTop = function(el) {
    return el.offsetTop;
  }
}
