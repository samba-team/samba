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

#module(ui_menu)

************************************************************************ */

/*!
  This singleton manages multiple instances of qx.ui.menu.Menu and their state.
*/
qx.OO.defineClass("qx.manager.object.MenuManager", qx.manager.object.ObjectManager,
function(){
  qx.manager.object.ObjectManager.call(this);
});





/*
---------------------------------------------------------------------------
  METHODS
---------------------------------------------------------------------------
*/

qx.Proto.update = function(vTarget, vEventName)
{
  var vMenu, vHashCode;
  var vAll = this.getAll();

  for (vHashCode in vAll)
  {
    vMenu = vAll[vHashCode];

    if(!vMenu.getAutoHide()) {
      continue;
    }

    if (vTarget && vTarget.getMenu && vTarget.getMenu()) {
      continue;
    }

    // Hide on global events (mouseup, window focus, window blur, ...)
    if (!vTarget)
    {
      vMenu.hide();
      continue;
    }

    // Hide only if the target is not a button inside this
    // or any sub menu and is not the opener
    if (vMenu.getOpener() !== vTarget && ((vTarget && !vMenu.isSubButton(vTarget)) || vEventName !== "mousedown"))
    {
      vMenu.hide();
      continue;
    }
  }
}







/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
