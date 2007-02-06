/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2007 Derrell Lipman

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Derrell Lipman (derrell)

************************************************************************ */

/* ************************************************************************

#module(treevirtual)

************************************************************************ */



/*
 * A simple tree data model used as the table model
 *
 * The object structure of a single node of the tree is:
 *
 * {
 *   type          : qx.ui.treevirtual.Type.LEAF,
 *   parentNodeId  : 23,   // index in _nodeArr of the parent node
 *   label         : "My Documents",
 *   bSelected     : true, // true if node is selected; false otherwise
 *   opened        : null, // true (-), false (+), or null (no +/-)
 *   icon          : "images/folder.gif",
 *   iconSelected  : "images/folder_selected.gif",
 *   children      : [ ],  // each value is an index into _nodeArr
 *
 *   cellStyle     : "background-color:cyan"
 *   labelStyle    : "background-color:red;color:white"
 *
 *   // The following properties need not (and should not) be set by the
 *   // caller, but are automatically calculated.  Some are used internally,
 *   // while others may be of use to event listeners.
 *
 *   nodeId        : 42,   // The index in _nodeArr, useful to event listeners
 *
 *   level         : 2,    // The indentation level of this tree node
 *
 *   bFirstChild   : true,
 *   lastChild     : [ false ],  // Array where the index is the column of
 *                               // indentation, and the value is a boolean.
 *                               // These are used to locate the
 *                               // appropriate "tree line" icon.
 * }
 */
qx.OO.defineClass("qx.ui.treevirtual.SimpleTreeDataModel",
                  qx.ui.table.AbstractTableModel,
function()
{
  qx.ui.table.AbstractTableModel.call(this);

  this._rowArr = [ ];           // rows, resorted into tree order as necessary
  this._nodeArr = [ ];          // tree nodes, organized with hierarchy

  this._nodeRowMap = [ ];       // map nodeArr index to rowArr index.  The
                                // index of this array is the index of
                                // _nodeArr, and the values in this array are
                                // the indexes into _rowArr.


  this._treeColumn = 0;         // default column for tree nodes

  this._selections = { };       // list of indexes of selected nodes

  this._nodeArr.push(           // the root node, needed to store its children
    {
      label     : "<virtual root>",
      opened    : true,
      children  : [ ]
    });
});


// overridden
qx.Proto.setEditable = function(editable)
{
  throw new Error("Tree columns can not be made editable");
};


// overridden
qx.Proto.setColumnEditable = function(columnIndex, editable)
{
  throw new Error("Tree columns can not be made editable");
};


// overridden
qx.Proto.isColumnEditable = function(columnIndex)
{
  return false;
};


// overridden
qx.Proto.isColumnSortable = function(columnIndex)
{
  return false;
};


// overridden
qx.Proto.sortByColumn = function(columnIndex, ascending)
{
  throw new Error("Trees can not be sorted by column");
};


qx.Proto.getSortColumnIndex = function()
{
  return -1;
};


qx.Proto.isSortAscending = function()
{
  return true;
};


qx.Proto.getRowCount = function()
{
  return this._rowArr.length;
};


qx.Proto.setTreeColumn = function(columnIndex)
{
  this._treeColumn = columnIndex;
}


qx.Proto.getTreeColumn = function()
{
  return this._treeColumn;
}


qx.Proto.getRowData = function(rowIndex)
{
  return this._rowArr[rowIndex];
}


qx.Proto.getValue = function(columnIndex, rowIndex)
{
  if (rowIndex < 0 || rowIndex >= this._rowArr.length)
  {
    throw new Error ("this._rowArr row " +
                     "(" + rowIndex + ") out of bounds: " +
                     this._rowArr +
                     " (0.." +
                     (this._rowArr.length - 1) + ")");b
  }

  if (columnIndex < 0 || columnIndex >= this._rowArr[rowIndex].length)
  {
    throw new Error ("this._rowArr column " +
                     "(" + columnIndex + ") out of bounds: " +
                     this._rowArr[rowIndex] +
                     " (0.." +
                     (this._rowArr[rowIndex].length - 1) + ")");
  }

  return this._rowArr[rowIndex][columnIndex];
};


qx.Proto._addNode = function(parentNodeId,
                             label,
                             opened,
                             type,
                             icon,
                             iconSelected)
{
  var parentNode;

  // Ensure that if parent was specified, it exists
  if (parentNodeId)
  {
    parentNode = this._nodeArr[parentNodeId];
    if (! parentNode)
    {
        throw new Error("Request to add a child to a non-existent parent");
    }

    // Ensure parent isn't a leaf
    if (parentNode.type == qx.ui.treevirtual.SimpleTreeDataModel.Type.LEAF)
    {
      throw new Error("Sorry, a LEAF may not have children.");
    }
  }
  else
  {
    // This is a child of the root
    parentNode = this._nodeArr[0];
    parentNodeId = 0;
  }

  // If this is a file, we don't present open/close icon
  if (type == qx.ui.treevirtual.SimpleTreeDataModel.Type.LEAF && opened)
  {
    throw new Error("Attempt to display a LEAF opened [" + label + "]");
  }

  // Determine the node id of this new node
  var nodeId = this._nodeArr.length;

  // Set the data for this node.
  var node =
    {
      type         : type,
      parentNodeId : parentNodeId,
      label        : label,
      bSelected    : false,
      opened       : opened,
      icon         : icon,
      iconSelected : iconSelected,
      children     : [ ],
      columnData   : [ ]
    };

  // Add this node to the array
  this._nodeArr.push(node);

  // Add this node to its parent's child array.
  parentNode.children.push(nodeId);

  // Return the node id we just added
  return nodeId;
};



qx.Proto.addBranch = function(parentNodeId,
                              label,
                              opened,
                              icon,
                              iconSelected)
{
  return this._addNode(parentNodeId,
                       label,
                       opened,
                       qx.ui.treevirtual.SimpleTreeDataModel.Type.BRANCH,
                       icon,
                       iconSelected);
};


qx.Proto.addLeaf = function(parentNodeId,
                            label,
                            icon,
                            iconSelected)
{
  return this._addNode(parentNodeId,
                       label,
                       false,
                       qx.ui.treevirtual.SimpleTreeDataModel.Type.LEAF,
                       icon,
                       iconSelected);
};


qx.Proto.prune = function(nodeId)
{
  // First, recursively remove all children
  for (var i = 0; i < this._nodeArr[nodeId].children.length; i++)
  {
    this.prune(this._nodeArr[nodeId].children[i]);
  }

  // Delete ourself from our parent's children list
  var node = this._nodeArr[nodeId];
  qx.lang.Array.remove(this._nodeArr[node.parentNodeId].children, nodeId);

  // Delete ourself from the selections list, if we're in it.
  if (this._selections[nodeId])
  {
    delete this._selections[nodeId];
  }

  // We can't splice the node itself out, because that would muck up the
  // nodeId == index correspondence.  Instead, just replace the node with
  // null so its index just becomes unused.
  this._nodeArr[nodeId] = null;
};



/**
 * Sets the whole data en bulk, or notifies the data model that node
 * modifications are complete.
 *
 * @param nodeArr {Array | null}
 *   Pass either an Array of node objects, or null.
 *
 *   If non-null, nodeArr is an array of node objects containing the entire
 *   tree to be displayed.  If loading the whole data en bulk in this way, it
 *   is assumed that the data is correct!  No error checking or validation is
 *   done.  You'd better know what you're doing!  Caveat emptor.
 *
 *   If nodeArr is null, then this call is a notification that the user has
 *   completed building or modifying a tree by issuing a series of calls to
 *   addNode().
 */
qx.Proto.setData = function(nodeArr)
{
  if (nodeArr instanceof Array)
  {
    // Determine the set of selected nodes
    for (i = 0; i < nodeArr.length; i++)
    {
      if (nodeArr[i].selected)
      {
        this._selections[i] = true;
      }
    }

    // Save the user-supplied data.
    this._nodeArr = nodeArr;
  }
  else if (nodeArr !== null && nodeArr !== undefined)
  {
    throw new Error("Expected array of node objects or null/undefined; got " +
                    typeof(nodeArr));
  }

  // Re-render the row array
  this._render();
};


/**
 * Return the array of node data.
 *
 * @return {Array}
 *   Array of node objects.  See {@link qx.ui.treevirtual.SimpleTreeDataModel}
 *   for a description of each node.
 */
qx.Proto.getData = function()
{
  return this._nodeArr;
};



/**
 * Add data to an additional column of the tree.
 *
 * @param nodeId
 *   A node identifier, as previously returned by addBranch() or addLeaf().
 *
 * @param columnIndex
 *   The column number to which the provided data applies
 *
 * @param data
 *   The cell data for the specified column
 */
qx.Proto.setColumnData = function(nodeId, columnIndex, data)
{
  this._nodeArr[nodeId].columnData[columnIndex] = data;
}


qx.Proto.setState = function(nodeId, attributes)
{
  for (var attribute in attributes)
  {
    // If the selected state is changing...
    if (attribute == "bSelected")
    {
      // ... then keep track of what is selected
      if (attributes[attribute])
      {
        this._selections[nodeId] = true;
      }
      else
      {
        delete this._selections[nodeId];
      }
    }

    this._nodeArr[nodeId][attribute] = attributes[attribute];
  }
};


qx.Proto.getNodeRowMap = function()
{
  return this._nodeRowMap;
};


qx.Proto.clearSelections = function()
{
  // Clear selected state for any selected nodes.
  for (var selection in this._selections)
  {
    this._nodeArr[selection].bSelected = false;
  }

  // Reinitialize selections array.
  this._selections = { };
};


qx.Proto.getSelections = function()
{
  return this._selections;
};


/**
 * Render (or re-render) the tree.  Call this function after having added
 * and/or deleted tree nodes (Files or Folders), or after having made changes
 * to tree (or tree node) options that will cause the tree to be rendered
 * differently.  This function should typically be called after a set of
 * concurrent changes, not after each change.
 */
qx.Proto._render = function()
{
  var _this = this;

  var inorder = function(nodeId, level)
  {
    var child = null;
    var childNodeId;

    // For each child of the specified node...
    var numChildren = _this._nodeArr[nodeId].children.length;
    for (var i = 0; i < numChildren; i++)
    {
      // Determine the node id of this child
      childNodeId = _this._nodeArr[nodeId].children[i];

      // Get the child node
      child = _this._nodeArr[childNodeId];

      // Skip deleted nodes
      if (child == null)
      {
        continue;
      }

      // Listeners will need to know a node's id when they receive an event
      child.nodeId = childNodeId;

      // (Re-)assign this node's level
      child.level = level;

      // Determine if we're the first child of our parent
      child.bFirstChild = (i == 0);

      // Determine if we're the last child of our parent
      child.lastChild = [ i == numChildren - 1 ];

      // Get our parent.
      var parent = _this._nodeArr[child.parentNodeId];

      // For each parent node, determine if it is a last child
      while (parent.nodeId)
      {
        var bLast = parent.lastChild[parent.lastChild.length - 1];
        child.lastChild.unshift(bLast);
        parent = _this._nodeArr[parent.parentNodeId];
      }

      // Ensure there's an entry in the columnData array for each column
      if (! child.columnData)
      {
        child.columnData = [ ];
      }

      if (child.columnData.length < _this.getColumnCount())
      {
        child.columnData[_this.getColumnCount() - 1] = null;
      }

      // Add this node to the row array.  Initialize a row data array.
      var rowData = [ ];

      // If additional column data is provided...
      if (child.columnData)
      {
        // ... then add each column data.
        for (var j = 0; j < child.columnData.length; j++)
        {
          // Is this the tree column?
          if (j == _this._treeColumn)
          {
            // Yup.  Add the tree node data
            rowData.push(child);
          }
          else
          {
            // Otherwise, add the column data verbatim.
            rowData.push(child.columnData[j]);
          }
        }
      }
      else
      {
        // No column data.  Just add the tree node.
        rowData.push(child);
      }

      // If this node is selected, ...
      if (child.bSelected)
      {
        // ... indicate so for the row.
        rowData.selected = true;
      }

      // Track the _rowArr index for each node so we can handle selections
      _this._nodeRowMap[child.nodeId] = _this._rowArr.length;

      // Add the row data to the row array
      _this._rowArr.push(rowData)

      // If this child is opened, ...
      if (child.opened)
      {
        // ... then add its children too.
        inorder(childNodeId, level + 1);
      }
    }
  }

  // Reset the row array
  this._rowArr = [];

  // Reset the _nodeArr -> _rowArr map
  this._nodeRowMap = [ ];

  // Begin in-order traversal of the tree from the root to regenerate _rowArr
  inorder(0, 1);

  // Inform the listeners
  if (this.hasEventListeners(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED))
  {
    var data =
      {
        firstRow        : 0,
        lastRow         : this._rowArr.length - 1,
        firstColumn     : 0,
        lastColumn      : this.getColumnCount() - 1
      };

    this.dispatchEvent(new qx.event.type.DataEvent(
                         qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED,
                         data),
                       true);
  }
};


// We currently support these types of tree nodes
qx.Class.Type = {};
qx.Class.Type.LEAF            = 1;
qx.Class.Type.BRANCH          = 2;

