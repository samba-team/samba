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

#module(ui_popup)

************************************************************************ */

/*!
  This singleton is used to manager multiple instances of popups and their state.
*/
qx.OO.defineClass("qx.manager.object.PopupManager", qx.manager.object.ObjectManager,
function() {
  qx.manager.object.ObjectManager.call(this);
});



/*
---------------------------------------------------------------------------
  METHODS
---------------------------------------------------------------------------
*/

qx.Proto.update = function(vTarget)
{
  // be sure that target is correctly set (needed for contains() later)
  if (!(vTarget instanceof qx.ui.core.Widget)) {
    vTarget = null;
  }

  var vPopup, vHashCode;
  var vAll = this.getAll();

  for (vHashCode in vAll)
  {
    vPopup = vAll[vHashCode];

    if(!vPopup.getAutoHide() || vTarget == vPopup || vPopup.contains(vTarget)) {
      continue;
    }

    vPopup.hide();
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
