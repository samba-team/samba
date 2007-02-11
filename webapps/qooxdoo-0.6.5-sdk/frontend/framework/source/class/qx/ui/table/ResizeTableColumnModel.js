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

#module(table)
#require(qx.ui.table.DefaultResizeBehavior)
#embed(qx.icontheme/16/actions/view-refresh.png)

************************************************************************ */

/**
 * A table column model that automagically resizes columns based on a
 * selected behavior.
 *
 * @see qx.ui.table.TableColumnModel
 */
qx.OO.defineClass("qx.ui.table.ResizeTableColumnModel",
                  qx.ui.table.TableColumnModel,
function()
{
  qx.ui.table.TableColumnModel.call(this);

  // We don't want to recursively call ourself based on our resetting of
  // column sizes.  Track when we're resizing.
  this._bInProgress = false;

  // Track when the table has appeared.  We want to ignore resize events until
  // then since we won't be able to determine the available width anyway.
  this._bAppeared = false;
});


/*
 * The behavior to use.
 *
 * The provided behavior must extend {link @AbstractResizeBehavior} and
 * implement the <i>onAppear</i>, <i>onTableWidthChanged</i>,
 * <i>onColumnWidthChanged</i> and <i>onVisibilityChanged</i>methods.
 */
qx.OO.addProperty(
  {
    name         : "behavior",
    type         : "object",
    defaultValue : new qx.ui.table.DefaultResizeBehavior()
  });

// Behavior modifier
qx.Proto._modifyBehavior = function(propValue, propOldValue, propData)
{
  // Tell the new behavior how many columns there are
  this.getBehavior()._setNumColumns(this._columnDataArr.length);
  return true;
};


/**
 * Initializes the column model.
 *
 * @param colCount {Integer}
 *   The number of columns the model should have.
 *
 * @param table {qx.ui.table.Table}
 *   The table which this model is used for.  This allows us access to other
 *   aspects of the table, as the <i>behavior</i> sees fit.
 */
qx.Proto.init = function(numColumns, table)
{
  // Call our superclass
  qx.ui.table.TableColumnModel.prototype.init.call(this, numColumns);

  // Save the table so we can get at its features, as necessary.
  this._table = table;

  // We'll do our column resizing when the table appears, ...
  table.addEventListener("appear", this._onappear, this);

  // ... when the inner width of the table changes, ...
  table.addEventListener("tableWidthChanged", this._ontablewidthchanged, this);

  // ... when columns are resized, ...
  this.addEventListener("widthChanged", this._oncolumnwidthchanged, this);

  // ... and when a column visibility changes.
  this.addEventListener("visibilityChanged", this._onvisibilitychanged, this);

  // We want to manipulate the button visibility menu
  this._table.addEventListener("columnVisibilityMenuCreateEnd",
                               this._addResetColumnWidthButton,
                               this);

  // Tell the behavior how many columns there are
  this.getBehavior()._setNumColumns(numColumns);
};


/**
 * Reset the column widths to their "onappear" defaults.
 *
 * @param event {qx.event.type.DataEvent}
 *   The "columnVisibilityMenuCreateEnd" event indicating that the menu is
 *   being generated.  The data is a map containing propeties <i>table</i> and
 *   <i>menu</i>.
 */
qx.Proto._addResetColumnWidthButton = function(event)
{
  var data = event.getData();
  var menu = data.menu;
  var o;

  var Am = qx.manager.object.AliasManager;
  var icon = Am.getInstance().resolvePath("icon/16/actions/view-refresh.png");

  // Add a separator between the column names and our reset button
  o= new qx.ui.menu.Separator();
  menu.add(o);

  // Add a button to reset the column widths
  o = new qx.ui.menu.Button("Reset column widths", icon);
  menu.add(o);
  o.addEventListener("execute", this._onappear, this);
};

/**
 * Event handler for the "appear" event.
 *
 * @param event {qx.event.type.Event}
 *   The "onappear" event object.
 */
qx.Proto._onappear = function(event)
{
  // Is this a recursive call?
  if (this._bInProgress)
  {
    // Yup.  Ignore it.
    return;
  }

  this._bInProgress = true;
  this.debug("onappear");
  this.getBehavior().onAppear(this, event);
  this._bInProgress = false;

  this._bAppeared = true;
};


/**
 * Event handler for the "tableWidthChanged" event.
 *
 * @param event {qx.event.type.Event}
 *   The "onwidowresize" event object.
 */
qx.Proto._ontablewidthchanged = function(event)
{
  // Is this a recursive call or has the table not yet been rendered?
  if (this._bInProgress || ! this._bAppeared)
  {
    // Yup.  Ignore it.
    return;
  }

  this._bInProgress = true;
  this.debug("ontablewidthchanged");
  this.getBehavior().onTableWidthChanged(this, event);
  this._bInProgress = false;
};


/**
 * Event handler for the "widthChanged" event.
 *
 * @param event {qx.event.type.DataEvent}
 *   The "widthChanged" event object.
 */
qx.Proto._oncolumnwidthchanged = function(event)
{
  // Is this a recursive call or has the table not yet been rendered?
  if (this._bInProgress || ! this._bAppeared)
  {
    // Yup.  Ignore it.
    return;
  }

  this._bInProgress = true;
  this.debug("oncolumnwidthchanged");
  this.getBehavior().onColumnWidthChanged(this, event);
  this._bInProgress = false;
};


/**
 * Event handler for the "visibilityChanged" event.
 *
 * @param event {qx.event.type.DataEvent}
 *   The "visibilityChanged" event object.
 */
qx.Proto._onvisibilitychanged = function(event)
{
  // Is this a recursive call or has the table not yet been rendered?
  if (this._bInProgress || ! this._bAppeared)
  {
    // Yup.  Ignore it.
    return;
  }

  this._bInProgress = true;
  this.debug("onvisibilitychanged");
  this.getBehavior().onVisibilityChanged(this, event);
  this._bInProgress = false;
};

