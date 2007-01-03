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

qx.OO.defineClass("qx.dom.Scroll");

qx.dom.Scroll.getLeftSum = function(el)
{
  var sum = 0;
  var p = el.parentNode;

  while (p.nodeType == 1)
  {
    sum += p.scrollLeft;
    p = p.parentNode;
  }

  return sum;
}

qx.dom.Scroll.getTopSum = function(el)
{
  var sum = 0;
  var p = el.parentNode;

  while (p.nodeType == 1)
  {
    sum += p.scrollTop;
    p = p.parentNode;
  }

  return sum;
}
