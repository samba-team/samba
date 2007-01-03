/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org
     2006 by Derrell Lipman

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)
     * Derrell Lipman (derrell)

************************************************************************ */

/* ************************************************************************

#module(ui_treefullcontrol)

************************************************************************ */

/**
 * qx.ui.treefullcontrol.TreeFile objects are terminal tree rows (i.e. no
 * sub-trees)
 *
 * @param
 * treeRowStructure -
 *   An instance of qx.ui.treefullcontrol.TreeRowStructure, defining the
 *   structure  of this tree row.
 */
qx.OO.defineClass("qx.ui.treefullcontrol.TreeFile", qx.ui.treefullcontrol.AbstractTreeElement,
function(treeRowStructure)
{
  qx.ui.treefullcontrol.AbstractTreeElement.call(this, treeRowStructure);
});




/*
---------------------------------------------------------------------------
  INDENT HELPER
---------------------------------------------------------------------------
*/

qx.Proto.getIndentSymbol = function(vUseTreeLines,
                                    vColumn,
                                    vFirstColumn,
                                    vLastColumn)
{
  var vLevel = this.getLevel();
  var vExcludeList = this.getTree().getExcludeSpecificTreeLines();
  var vExclude = vExcludeList[vLastColumn - vColumn - 1];

  if (vUseTreeLines && ! (vExclude === true))
  {
    if (vColumn == vFirstColumn)
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
