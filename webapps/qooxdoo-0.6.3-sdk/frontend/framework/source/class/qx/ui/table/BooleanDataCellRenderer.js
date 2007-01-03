/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 by STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Til Schneider (til132)
     * Carsten Lergenmueller (carstenl)

************************************************************************ */

/* ************************************************************************

#module(ui_table)

************************************************************************ */

/**
 * A data cell renderer for boolean values.
 */
qx.OO.defineClass("qx.ui.table.BooleanDataCellRenderer", qx.ui.table.IconDataCellRenderer,
function() {
  qx.ui.table.IconDataCellRenderer.call(this);

  this._iconUrlTrue  = qx.manager.object.AliasManager.getInstance().resolvePath("widget/table/boolean-true.png");
  this._iconUrlFalse = qx.manager.object.AliasManager.getInstance().resolvePath("widget/table/boolean-false.png");
  this._iconUrlNull  = qx.manager.object.AliasManager.getInstance().resolvePath("static/image/blank.gif");

});

//overridden
qx.Proto._identifyImage = function(cellInfo) {
  var IconDataCellRenderer = qx.ui.table.IconDataCellRenderer;
  var imageHints = { imageWidth:11, imageHeight:11 };
  switch (cellInfo.value) {
    case true:  imageHints.url = this._iconUrlTrue;  break;
    case false: imageHints.url = this._iconUrlFalse; break;
    default:    imageHints.url = this._iconUrlNull;  break;
  }
  return imageHints;
}
