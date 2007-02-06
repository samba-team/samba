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

#module(ui_popup)
#optional(qx.ui.popup.ToolTip)

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

    if (qx.OO.isAvailable("qx.ui.popup.ToolTip") && vTarget instanceof qx.ui.popup.ToolTip && !(vPopup instanceof qx.ui.popup.ToolTip)) {
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
qx.Class.getInstance = qx.lang.Function.returnInstance;
