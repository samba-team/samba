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

#module(ui_window)

************************************************************************ */

/*!
  This singleton manages qx.ui.window.Windows
*/
qx.OO.defineClass("qx.manager.object.WindowManager", qx.manager.object.ObjectManager,
function() {
  qx.manager.object.ObjectManager.call(this);
});

qx.OO.addProperty({ name : "activeWindow", type : "object" });






/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyActiveWindow = function(propValue, propOldValue, propData)
{
  qx.manager.object.PopupManager.getInstance().update();

  if (propOldValue) {
    propOldValue.setActive(false);
  }

  if (propValue) {
    propValue.setActive(true);
  }

  if (propOldValue && propOldValue.getModal()) {
    propOldValue.getTopLevelWidget().release(propOldValue);
  }

  if (propValue && propValue.getModal()) {
    propValue.getTopLevelWidget().block(propValue);
  }

  return true;
}






/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.update = function(oTarget)
{
  var vWindow, vHashCode;
  var vAll = this.getAll();

  for (var vHashCode in vAll)
  {
    vWindow = vAll[vHashCode];

    if(!vWindow.getAutoHide()) {
      continue;
    }

    vWindow.hide();
  }
}





/*
---------------------------------------------------------------------------
  MANAGER INTERFACE
---------------------------------------------------------------------------
*/

qx.Proto.compareWindows = function(w1, w2)
{
  switch(w1.getWindowManager().getActiveWindow())
  {
    case w1:
      return 1;

    case w2:
      return -1;
  }

  return w1.getZIndex() - w2.getZIndex();
}

qx.Proto.add = function(vWindow)
{
  qx.manager.object.ObjectManager.prototype.add.call(this, vWindow);

  // this.debug("Add: " + vWindow);
  this.setActiveWindow(vWindow);
}

qx.Proto.remove = function(vWindow)
{
  qx.manager.object.ObjectManager.prototype.remove.call(this, vWindow);

  // this.debug("Remove: " + vWindow);

  if (this.getActiveWindow() == vWindow)
  {
    var a = [];
    for (var i in this._objects) {
      a.push(this._objects[i]);
    }

    var l = a.length;

    if (l==0)
    {
      this.setActiveWindow(null);
    }
    else if (l==1)
    {
      this.setActiveWindow(a[0]);
    }
    else if (l>1)
    {
      a.sort(this.compareWindows);
      this.setActiveWindow(a[l-1]);
    }
  }
}
