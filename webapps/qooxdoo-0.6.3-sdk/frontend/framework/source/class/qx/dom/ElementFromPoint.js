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


************************************************************************ */

qx.OO.defineClass("qx.dom.ElementFromPoint");

qx.dom.ElementFromPoint.getElementFromPoint = function(x, y) {
  return qx.dom.ElementFromPoint.getElementFromPointHandler(document.body, x, y);
}

qx.dom.ElementFromPoint.getElementFromPointHandler = function(node, x, y, recursive)
{
  var ch = node.childNodes;
  var chl = ch.length-1;

  if (chl < 0) {
    return null;
  }

  var chc, subres, ret;

  do
  {
    chc = ch[chl];
    ret = qx.dom.ElementFromPoint.getElementFromPointChecker(chc, x, y);

    if (ret)
    {
      if (typeof recursive === "boolean" && recursive == false)
      {
        return chc;
      }
      else
      {
        subres = qx.dom.ElementFromPoint.getElementFromPointHandler(chc, x-ret[0]-qx.dom.Style.getBorderLeft(chc), y-ret[2]-qx.dom.Style.getBorderTop(chc));
        return subres ? subres : chc;
      }
    }
  }
  while(chl--);

  return null;
}

qx.dom.ElementFromPoint.getElementFromPointChecker = function(chc, x, y)
{
  var xstart, ystart, xstop, ystop;

  if (chc.nodeType != 1) {
    return false;
  }

  xstart = qx.dom.Offset.getLeft(chc);
  if (x > xstart)
  {
    ystart = qx.dom.Offset.getTop(chc);
    if (y > ystart)
    {
      xstop = xstart + chc.offsetWidth;

      if (x < xstop)
      {
        ystop = ystart + chc.offsetHeight;
        if (y < ystop)
        {
          return [ xstart, xstop, ystart, ystop ];
        }
      }
    }
  }

  return false;
}

qx.dom.ElementFromPoint.getElementAbsolutePointChecker = function(chc, x, y)
{
  var xstart, ystart, xstop, ystop;

  if (!chc || chc.nodeType != 1) {
    return false;
  }

  xstart = qx.dom.Location.getPageBoxLeft(chc);
  if (x > xstart)
  {
    ystart = qx.dom.Location.getPageBoxTop(chc);
    if (y > ystart)
    {
      xstop = xstart + chc.offsetWidth;

      if (x < xstop)
      {
        ystop = ystart + chc.offsetHeight;
        if (y < ystop)
        {
          return [ xstart, xstop, ystart, ystop ];
        }
      }
    }
  }

  return false;
}
