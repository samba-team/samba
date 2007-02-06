/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 David Perez

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

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
  editor.setChecked(cellInfo.value);

  return editor;
}

// overridden
qx.Proto.getCellEditorValue = function(cellEditor) {
   return cellEditor.getChecked();
}
