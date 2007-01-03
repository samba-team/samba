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

#module(ui_basic)

************************************************************************ */

qx.OO.defineClass("qx.ui.basic.Inline", qx.ui.layout.CanvasLayout,
function(vId)
{
  qx.ui.layout.CanvasLayout.call(this);

  this.setStyleProperty("position", "relative");

  if (qx.util.Validation.isValidString(vId)) {
    this.setInlineNodeId(vId);
  }
});

qx.OO.addProperty({ name : "inlineNodeId", type : "string" });
