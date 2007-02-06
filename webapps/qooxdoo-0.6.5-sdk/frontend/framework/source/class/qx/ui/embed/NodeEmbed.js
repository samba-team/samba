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

#module(ui_basic)

************************************************************************ */

qx.OO.defineClass("qx.ui.embed.NodeEmbed", qx.ui.basic.Terminator,
function(vId)
{
  qx.ui.basic.Terminator.call(this);

  if (vId != null) {
    this.setSourceNodeId(vId);
  }
});

qx.OO.addProperty({ name : "sourceNodeId", type : "string" });

qx.Proto._createElementImpl = function()
{
  var vNode = document.getElementById(this.getSourceNodeId());

  if (!vNode) {
    throw new Error("Could not find source node with ID: " + this.getSourceNodeId());
  }

  vNode.style.display = "";

  return this.setElement(vNode);
}
