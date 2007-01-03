/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 by David Perez

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * David Perez (david-perez)

************************************************************************ */

/* ************************************************************************

#module(ui_table)

************************************************************************ */

/**
 * For editing boolean data in a checkbox.  It is advisable to use this in conjuntion with BooleanDataCellRenderer.
 */
qx.OO.defineClass("qx.ui.table.CheckBoxCellEditorFactory", qx.ui.table.CellEditorFactory, function() {
  qx.ui.table.CellEditorFactory.call(this);
});

// overridden
qx.Proto.createCellEditor = function(cellInfo) {
  var editor = new qx.ui.form.CheckBox;
  with (editor) {
    setChecked(cellInfo.value);
  }
  return editor;
}

// overridden
qx.Proto.getCellEditorValue = function(cellEditor) {
   return cellEditor.getChecked();
}
