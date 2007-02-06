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


************************************************************************ */

qx.OO.defineClass("qx.ui.pageview.AbstractBar", qx.ui.layout.BoxLayout,
function()
{
  qx.ui.layout.BoxLayout.call(this);

  this._manager = new qx.manager.selection.RadioManager;

  this.addEventListener("mousewheel", this._onmousewheel);
});




/*
---------------------------------------------------------------------------
  UTILITY
---------------------------------------------------------------------------
*/

qx.Proto.getManager = function() {
  return this._manager;
}





/*
---------------------------------------------------------------------------
  EVENTS
---------------------------------------------------------------------------
*/

qx.Proto._lastDate = (new Date(0)).valueOf();

qx.Proto._onmousewheel = function(e)
{
  // Make it a bit lazier than it could be
  // Hopefully this is a better behaviour for fast scrolling users
  var vDate = (new Date).valueOf();

  if ((vDate - 50) < this._lastDate) {
    return;
  }

  this._lastDate = vDate;

  var vManager = this.getManager();
  var vItems = vManager.getEnabledItems();
  var vPos = vItems.indexOf(vManager.getSelected());

  if (this.getWheelDelta(e) > 0)
  {
    var vNext = vItems[vPos+1];

    if (!vNext) {
      vNext = vItems[0];
    }
  }
  else if (vPos > 0)
  {
    var vNext = vItems[vPos-1];

    if (!vNext) {
      vNext = vItems[0];
    }
  }
  else
  {
    vNext = vItems[vItems.length-1];
  }

  vManager.setSelected(vNext);
}

qx.Proto.getWheelDelta = function(e) {
  return e.getWheelDelta();
}






/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  if (this._manager)
  {
    this._manager.dispose();
    this._manager = null;
  }

  this.removeEventListener("mousewheel", this._onmousewheel);

  return qx.ui.layout.BoxLayout.prototype.dispose.call(this);
}
