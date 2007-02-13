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
 * <pre>
 * {
 *   // USER-PROVIDED ATTRIBUTES
 *   // ------------------------
 *   type           : qx.ui.treevirtual.Type.LEAF,
 *   parentNodeId   : 23,    // index in _nodeArr of the parent node
 *   label          : "My Documents",
 *   bSelected      : true,  // true if node is selected; false otherwise
 *   bOpened        : true,  // true (-), false (+)
 *   bHideOpenClose : false, // whether to hide the open/close button
 *   icon           : "images/folder.gif",
 *   iconSelected   : "images/folder_selected.gif",
 *   children       : [ ],   // each value is an index into _nodeArr
 *
 *   cellStyle      : "background-color:cyan"
 *   labelStyle     : "background-color:red;color:white"
 *
 *   // INTERNALLY-CALCULATED ATTRIBUTES
 *   // --------------------------------
 *   // The following properties need not (and should not) be set by the
 *   // caller, but are automatically calculated.  Some are used internally,
 *   // while others may be of use to event listeners.
 *
 *   nodeId         : 42,   // The index in _nodeArr, useful to event listeners
 *
 *   level          : 2,    // The indentation level of this tree node
 *
 *   bFirstChild    : true,
 *   lastChild      : [ false ],  // Array where the index is the column of
 *                                // indentation, and the value is a boolean.
 *                                // These are used to locate the
 *                                // appropriate "tree line" icon.
 * }
 * </pre>
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
      bOpened   : true,
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


/**
 * Returns the column index the model is sorted by. This model is never
 * sorted, so -1 is returned.
 *
 * @return {Integer}
 *   -1, to indicate that the model is not sorted.
 */
qx.Proto.getSortColumnIndex = function()
{
  return -1;
};


/**
 * Specifies which column the tree is to be displayed in.  The tree is
 * displayed using the SimpleTreeDataCellRenderer.  Other columns may be
 * provided which use different cell renderers.
 *
 * @param columnIndex {Integer}
 *   The index of the column in which the tree should be displayed.
 */
qx.Proto.setTreeColumn = function(columnIndex)
{
  this._treeColumn = columnIndex;
};


/**
 * Get the column in which the tree is to be displayed.
 *
 * @return {Integer}
 *   The column in whcih the tree is to be displayed
 */
qx.Proto.getTreeColumn = function()
{
  return this._treeColumn;
};


// overridden
qx.Proto.getRowCount = function()
{
  return this._rowArr.length;
};


// overridden
qx.Proto.getRowData = function(rowIndex)
{
  return this._rowArr[rowIndex];
};


// overridden
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


/**
 * Add a node to the tree.
 *
 * NOTE: This method is for <b>internal use</b> and should not be called by
 *       users of this class.  Instead, call {@link #addBranch} or {@link
 *       #addLeaf}.  There is no guarantee that the interface to this method
 *       will remain unchanged over time.
 *
 * @param parentNodeId {Integer}
 *   The node id of the parent of the node being added
 *
 * @param label {String}
 *   The string to display as the label for this node
 *
 * @param bOpened {Integer}
 *   <i>true</i> if the tree should be rendered in its opened state;
 *   <i>false</i> otherwise.
 *
 * @param bHideOpenCloseButton
 *   <i>true</i> if the open/close button should be hidden (not displayed);
 *   </i>false</i> to display the open/close button for this node.
 *
 * @param type {Integer}
 *   The type of node being added.  The type determines whether children may
 *   be added, and determines the default icons to use.  This parameter must
 *   be one of the following values:
 *   <dl>
 *     <dt>qx.ui.treevirtual.SimpleTreeDataModel.Type.BRANCH</dt>
 *     <dd>
 *       This node is a branch.  A branch node may have children.
 *     </dd>
 *     <dt>qx.ui.treevirtual.SimpleTreeDataModel.Type.LEAF</dt>
 *     <dd>
 *       This node is a leaf, and may not have children
 *     </dd>
 *   </dl>
 *
 * @param icon {String}
 *   The relative (subject to alias expansion) or full path of the icon to
 *   display for this node when it is not a selected node.
 *
 * @param iconSelected {String}
 *   The relative (subject to alias expansion) or full path of the icon to
 *   display for this node when it is a selected node.
 *
 * @return {Integer}
 *   The node id of the newly-added node.
 */
qx.Proto._addNode = function(parentNodeId,
                             label,
                             bOpened,
                             bHideOpenCloseButton,
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

  // If this is a leaf, we don't present open/close icon
  if (type == qx.ui.treevirtual.SimpleTreeDataModel.Type.LEAF)
  {
    // mask off the opened bit but retain the hide open/close button bit
    bOpened = false;
    bHideOpenClose = false;
  }

  // Determine the node id of this new node
  var nodeId = this._nodeArr.length;

  // Set the data for this node.
  var node =
    {
      type           : type,
      parentNodeId   : parentNodeId,
      label          : label,
      bSelected      : false,
      bOpened        : bOpened,
      bHideOpenClose : bHideOpenCloseButton,
      icon           : icon,
      iconSelected   : iconSelected,
      children       : [ ],
      columnData     : [ ]
    };

  // Add this node to the array
  this._nodeArr.push(node);

  // Add this node to its parent's child array.
  parentNode.children.push(nodeId);

  // Return the node id we just added
  return nodeId;
};



/**
 * Add a branch to the tree.
 *
 * @param parentNodeId {Integer}
 *   The node id of the parent of the node being added
 *
 * @param label {String}
 *   The string to display as the label for this node
 *
 * @param bOpened {Boolean}
 *   <i>True</i> if the branch should be rendered in its opened state;
 *   <i>false</i> otherwise.
 *
 * @param bHideOpenCloseButton {Boolean}
 *   <i>True</i> if the open/close button should not be displayed;
 *   <i>false</i> if the open/close button should be displayed
 *
 * @param icon {String}
 *   The relative (subject to alias expansion) or full path of the icon to
 *   display for this node when it is not a selected node.
 *
 * @param iconSelected {String}
 *   The relative (subject to alias expansion) or full path of the icon to
 *   display for this node when it is a selected node.
 *
 * @return {Integer}
 *   The node id of the newly-added branch.
 */
qx.Proto.addBranch = function(parentNodeId,
                              label,
                              bOpened,
                              bHideOpenCloseButton,
                              icon,
                              iconSelected)
{
  return this._addNode(parentNodeId,
                       label,
                       bOpened,
                       bHideOpenCloseButton,
                       qx.ui.treevirtual.SimpleTreeDataModel.Type.BRANCH,
                       icon,
                       iconSelected);
};


/**
 * Add a leaf to the tree.
 *
 * @param parentNodeId {Integer}
 *   The node id of the parent of the node being added
 *
 * @param label {String}
 *   The string to display as the label for this node
 *
 * @param icon {String}
 *   The relative (subject to alias expansion) or full path of the icon to
 *   display for this node when it is not a selected node.
 *
 * @param iconSelected {String}
 *   The relative (subject to alias expansion) or full path of the icon to
 *   display for this node when it is a selected node.
 *
 * @return {Integer}
 *   The node id of the newly-added leaf.
 */
qx.Proto.addLeaf = function(parentNodeId,
                            label,
                            icon,
                            iconSelected)
{
  return this._addNode(parentNodeId,
                       label,
                       false,
                       false,
                       qx.ui.treevirtual.SimpleTreeDataModel.Type.LEAF,
                       icon,
                       iconSelected);
};


/**
 * Prune the tree by removing, recursively, all of a node's children.  If
 * requested, also remove the node itself.
 *
 * @param nodeId {Integer}
 *   The node id, previously returned by {@link #addLeaf} or {@link
 *   #addBranch}, of the node (and its children) to be pruned from the tree.
 *
 * @param bSelfAlso {Boolean}
 *   If <i>true</i> then remove the node identified by <i>nodeId</i> as well
 *   as all of the children.
 */
qx.Proto.prune = function(nodeId, bSelfAlso)
{
  // First, recursively remove all children
  for (var i = 0; i < this._nodeArr[nodeId].children.length; i++)
  {
    this.prune(this._nodeArr[nodeId].children[i], true);
  }

  if (bSelfAlso)
  {
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
  }
};



/**
 * Sets the whole data en bulk, or notifies the data model that node
 * modifications are complete.
 *
 * @param nodeArr {Array | null}
 *   Pass either an Array of node objects, or null.
 *   </p><p>
 *   If non-null, nodeArr is an array of node objects containing the entire
 *   tree to be displayed.  If loading the whole data en bulk in this way, it
 *   is assumed that the data is correct!  No error checking or validation is
 *   done.  You'd better know what you're doing!  Caveat emptor.
 *   </p><p>
 *   If nodeArr is null, then this call is a notification that the user has
 *   completed building or modifying a tree by issuing a series of calls to
 *   {@link #addBranch} and/or {@link #addLeaf}.
 *   <p>
 */
qx.Proto.setData = function(nodeArr)
{
  var _this = this;

  function render()
  {
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
        if (child.bOpened)
        {
          // ... then add its children too.
          inorder(childNodeId, level + 1);
        }
      }
    }

    // Reset the row array
    _this._rowArr = [];

    // Reset the _nodeArr -> _rowArr map
    _this._nodeRowMap = [ ];

    // Begin in-order traversal of the tree from the root to regenerate _rowArr
    inorder(0, 1);

    // Inform the listeners
    if (_this.hasEventListeners(qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED))
    {
      var data =
        {
          firstRow        : 0,
          lastRow         : _this._rowArr.length - 1,
          firstColumn     : 0,
          lastColumn      : _this.getColumnCount() - 1
        };

      _this.dispatchEvent(new qx.event.type.DataEvent(
                            qx.ui.table.TableModel.EVENT_TYPE_DATA_CHANGED,
                            data),
                          true);
    }
  }

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
  render();
};


/**
 * Return the array of node data.
 *
 * @return {Array}
 *   Array of node objects.  See {@link qx.ui.treevirtual.SimpleTreeDataModel}
 *   for a description nodes in this array.
 */
qx.Proto.getData = function()
{
  return this._nodeArr;
};



/**
 * Add data to an additional column (a column other than the tree column) of
 * the tree.
 *
 * @param nodeId
 *   A node identifier, as previously returned by {@link #addBranch} or {@link
 *   addLeaf}.
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


/**
 * Set state attributes of a node.
 *
 * @param nodeId {Integer}
 *   A node identifier, as previously returned by {@link #addBranch} or {@link
 *   addLeaf}.
 *
 * @param attributes {Map}
 *   Each property name in the map may correspond to the property names of a
 *   node which are specified as <i>USER-PROVIDED ATTRIBUTES</i> in {@link
 *   #SimpleTreeDataModel}.  Each property value will be assigned to the
 *   corresponding property of the node specified by nodeId.
 */
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


/**
 * Return the mapping of nodes to rendered rows.  This function is intended
 * for use by the cell renderer, not by users of this class.
 *
 * @return {Array}
 *   The array containing mappings of nodes to rendered rows.
 */
qx.Proto.getNodeRowMap = function()
{
  return this._nodeRowMap;
};


/*
 * Clear all selections in the data model.  This method does not clear
 * selections displayed in the widget, and is intended for internal use, not
 * by users of this class.
 */
qx.Proto._clearSelections = function()
{
  // Clear selected state for any selected nodes.
  for (var selection in this._selections)
  {
    this._nodeArr[selection].bSelected = false;
  }

  // Reinitialize selections array.
  this._selections = { };
};


/**
 * Return the nodes that are currently selected.
 *
 * @return {Array}
 *   An array containing the nodes that are currently selected.
 */
qx.Proto.getSelectedNodes = function()
{
  var nodes = [ ];

  for (var nodeId in this._selections)
  {
    nodes.push(this._nodeArr[nodeId]);
  }

  return nodes;
};


// We currently support these types of tree nodes
qx.Class.Type = {};
qx.Class.Type.LEAF            = 1;
qx.Class.Type.BRANCH          = 2;

