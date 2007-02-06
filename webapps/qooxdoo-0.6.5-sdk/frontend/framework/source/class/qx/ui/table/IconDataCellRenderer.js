/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Til Schneider (til132)
     * Carsten Lergenmueller (carstenl)

************************************************************************ */

/* ************************************************************************

#module(ui_table)
#embed(qx.static/image/blank.gif)

************************************************************************ */

/**
 * A data cell renderer for boolean values.
 */
qx.OO.defineClass("qx.ui.table.IconDataCellRenderer", qx.ui.table.AbstractDataCellRenderer,
function() {
  qx.ui.table.AbstractDataCellRenderer.call(this);
  this.IMG_BLANK_URL = qx.manager.object.AliasManager.getInstance().resolvePath("static/image/blank.gif");
});


/**
 * Identifies the Image to show.
 *
 * @param cellInfo {Map} The information about the cell.
 *        See {@link #createDataCellHtml}.
 * @return {Map} A map having the following attributes:
 *         <ul>
 *         <li>"url": (type string) must be the URL of the image to show.</li>
 *         <li>"imageWidth": (type int) the width of the image in pixels.</li>
 *         <li>"imageHeight": (type int) the height of the image in pixels.</li>
 *         <li>"tooltip": (type string) must be the image tooltip text.</li>
 *         </ul>
 */
qx.Proto._identifyImage = function(cellInfo) {
  throw new Error("_identifyImage is abstract");
}


/**
 * Retrieves the image infos.
 *
 * @param cellInfo {Map} The information about the cell.
 *        See {@link #createDataCellHtml}.
 * @return {Map} Map with an "url" attribute (type string)
 *               holding the URL of the image to show
 *               and a "tooltip" attribute
 *               (type string) being the tooltip text (or null if none was specified)
 *
 */
qx.Proto._getImageInfos= function(cellInfo) {
  // Query the subclass about image and tooltip
  var urlAndTooltipMap = this._identifyImage(cellInfo);

  // If subclass refuses to give map, construct it
  if (urlAndTooltipMap == null || typeof urlAndTooltipMap == "string"){
    urlAndTooltipMap = {url:urlAndTooltipMap, tooltip:null};
  }

  // If subclass gave null as url, replace with url to empty image
  if (urlAndTooltipMap.url == null){
    urlAndTooltipMap.url = this.IMG_BLANK_URL;
  }

  return urlAndTooltipMap;
}

// overridden
qx.Proto._getCellStyle = function(cellInfo) {
  var style = qx.ui.table.AbstractDataCellRenderer.prototype._getCellStyle(cellInfo);
  style += qx.ui.table.IconDataCellRenderer.MAIN_DIV_STYLE;
  return style;
}


// overridden
qx.Proto._getContentHtml = function(cellInfo) {
  var IconDataCellRenderer = qx.ui.table.IconDataCellRenderer;

  var urlAndToolTip = this._getImageInfos(cellInfo);
  var html = IconDataCellRenderer.IMG_START;
  if (qx.core.Client.getInstance().isMshtml() && /\.png$/i.test(urlAndToolTip.url)) {
    html += qx.manager.object.AliasManager.getInstance().resolvePath("static/image/blank.gif")
      + '" style="filter:' + "progid:DXImageTransform.Microsoft.AlphaImageLoader(src='" + urlAndToolTip.url + "',sizingMethod='scale')";
  } else {
    html += urlAndToolTip.url + '" style="';
  }

  if (urlAndToolTip.imageWidth && urlAndToolTip.imageHeight) {
    html += ';width:' + urlAndToolTip.imageWidth + 'px'
         +  ';height:' + urlAndToolTip.imageHeight + 'px';
  }

  var tooltip = urlAndToolTip.tooltip;
  if (tooltip != null){
    html += IconDataCellRenderer.IMG_TITLE_START + tooltip;
  }
  html += IconDataCellRenderer.IMG_END;
  return html;
}


// overridden
qx.Proto.updateDataCellElement = function(cellInfo, cellElement) {
  // Set image and tooltip text
  var urlAndToolTip = this._getImageInfos(cellInfo);
  var img = cellElement.firstChild;
  if (qx.core.Client.getInstance().isMshtml()) {
    if (/\.png$/i.test(urlAndToolTip.url)) {
      img.src = qx.manager.object.AliasManager.getInstance().resolvePath("static/image/blank.gif");
      img.style.filter = "progid:DXImageTransform.Microsoft.AlphaImageLoader(src='" + urlAndToolTip.url + "',sizingMethod='scale')";
    } else {
      img.src = urlAndToolTip.url;
      img.style.filter = "";
    }
  } else {
    img.src = urlAndToolTip.url;
  }

  if (urlAndToolTip.imageWidth && urlAndToolTip.imageHeight) {
    img.style.width = urlAndToolTip.imageWidth + "px";
    img.style.height = urlAndToolTip.imageHeight + "px";
  }

  if (urlAndToolTip.tooltip != null){
    img.setAttribute("title", urlAndToolTip.tooltip);
  }
}


// overridden
qx.Proto._createCellStyle_array_join = function(cellInfo, htmlArr) {
  qx.ui.table.AbstractDataCellRenderer.prototype._createCellStyle_array_join(cellInfo, htmlArr);

  htmlArr.push(qx.ui.table.IconDataCellRenderer.MAIN_DIV_STYLE);
}

qx.Proto._createContentHtml_array_join = function(cellInfo, htmlArr) {
  var IconDataCellRenderer = qx.ui.table.IconDataCellRenderer;

  if (qx.ui.table.TablePane.USE_TABLE) {
    htmlArr.push(IconDataCellRenderer.TABLE_DIV);
    htmlArr.push(cellInfo.styleHeight - 2); // -1 for the border, -1 for the padding
    htmlArr.push(IconDataCellRenderer.TABLE_DIV_CLOSE);
  }

  htmlArr.push(IconDataCellRenderer.IMG_START);
  var urlAndToolTip = this._getImageInfos(cellInfo);
  htmlArr.push(urlAndToolTip.url);
  var tooltip = urlAndToolTip.tooltip;
  if (tooltip != null){
    IconDataCellRenderer.IMG_TITLE_START;
    htmlArr.push(tooltip);
  }
  htmlArr.push(IconDataCellRenderer.IMG_END);

  if (qx.ui.table.TablePane.USE_TABLE) {
    htmlArr.push(IconDataCellRenderer.TABLE_DIV_END);
  }
}

qx.Class.MAIN_DIV_STYLE = ';text-align:center;padding-top:1px;';
qx.Class.IMG_START = '<img src="';
qx.Class.IMG_END = '"/>';
qx.Class.IMG_TITLE_START = '" title="';
qx.Class.TABLE_DIV = '<div style="overflow:hidden;height:';
qx.Class.TABLE_DIV_CLOSE = 'px">';
qx.Class.TABLE_DIV_END = '</div>';

