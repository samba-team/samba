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

#module(ui_tree)

************************************************************************ */

qx.OO.defineClass("qx.ui.tree.TreeFile", qx.ui.tree.AbstractTreeElement,
function(vLabel, vIcon, vIconSelected) {
  qx.ui.tree.AbstractTreeElement.call(this, vLabel, vIcon, vIconSelected);
});




/*
---------------------------------------------------------------------------
  INDENT HELPER
---------------------------------------------------------------------------
*/

qx.Proto.getIndentSymbol = function(vUseTreeLines, vIsLastColumn)
{
  if (vUseTreeLines)
  {
    if (vIsLastColumn)
    {
      return this.isLastChild() ? "end" : "cross";
    }
    else
    {
      return "line";
    }
  }

  return null;
}

qx.Proto._updateIndent = function() {
  this.addToTreeQueue();
}

qx.Proto.getItems = function() {
  return [this];
}
