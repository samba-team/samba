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

qx.OO.defineClass("qx.ui.pageview.AbstractPageView", qx.ui.layout.BoxLayout,
function(vBarClass, vPaneClass)
{
  qx.ui.layout.BoxLayout.call(this);

  this._bar = new vBarClass;
  this._pane = new vPaneClass;

  this.add(this._bar, this._pane);
  this.setOrientation("vertical");
});





/*
---------------------------------------------------------------------------
  UTILITY
---------------------------------------------------------------------------
*/

qx.Proto.getPane = function() {
  return this._pane;
}

qx.Proto.getBar = function() {
  return this._bar;
}






/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return true;
  }

  if (this._bar)
  {
    this._bar.dispose();
    this._bar = null;
  }

  if (this._pane)
  {
    this._pane.dispose();
    this._pane = null;
  }

  return qx.ui.layout.BoxLayout.prototype.dispose.call(this);
}
