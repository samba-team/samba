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

#module(ui_buttonview)

************************************************************************ */

qx.OO.defineClass("qx.ui.pageview.buttonview.Button", qx.ui.pageview.AbstractButton,
function(vText, vIcon, vIconWidth, vIconHeight, vFlash) {
  qx.ui.pageview.AbstractButton.call(this, vText, vIcon, vIconWidth, vIconHeight, vFlash);
});

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "bar-view-button" });






/*
---------------------------------------------------------------------------
  EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onkeypress = function(e)
{
  switch(this.getView().getBarPosition())
  {
    case "top":
    case "bottom":
      switch(e.getKeyIdentifier())
      {
        case "Left":
          var vPrevious = true;
          break;

        case "Right":
          var vPrevious = false;
          break;

        default:
          return;
      }

      break;

    case "left":
    case "right":
      switch(e.getKeyIdentifier())
      {
        case "Up":
          var vPrevious = true;
          break;

        case "Down":
          var vPrevious = false;
          break;

        default:
          return;
      }

      break;

    default:
      return;
  }

  var vChild = vPrevious ? this.isFirstChild() ? this.getParent().getLastChild() : this.getPreviousSibling() : this.isLastChild() ? this.getParent().getFirstChild() : this.getNextSibling();

  // focus next/previous button
  vChild.setFocused(true);

  // and naturally also check it
  vChild.setChecked(true);
}









/*
---------------------------------------------------------------------------
  APPEARANCE ADDITIONS
---------------------------------------------------------------------------
*/

qx.Proto._applyStateAppearance = function()
{
  var vPos = this.getView().getBarPosition();

  this._states.barLeft = vPos === "left";
  this._states.barRight = vPos === "right";
  this._states.barTop = vPos === "top";
  this._states.barBottom = vPos === "bottom";

  qx.ui.pageview.AbstractButton.prototype._applyStateAppearance.call(this);
}
