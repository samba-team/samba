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

#require(qx.sys.Client)

************************************************************************ */

qx.OO.defineClass("qx.dom.Window");

if (qx.sys.Client.getInstance().isMshtml())
{
  qx.dom.Window.getInnerWidth = function(w)
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

  qx.dom.Window.getInnerHeight = function(w)
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

  qx.dom.Window.getScrollLeft = function(w)
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

  qx.dom.Window.getScrollTop = function(w)
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
  qx.dom.Window.getInnerWidth = function(w) {
    return w.innerWidth;
  }

  qx.dom.Window.getInnerHeight = function(w) {
    return w.innerHeight;
  }

  qx.dom.Window.getScrollLeft = function(w) {
    return w.document.body.scrollLeft;
  }

  qx.dom.Window.getScrollTop = function(w) {
    return w.document.body.scrollTop;
  }
}
