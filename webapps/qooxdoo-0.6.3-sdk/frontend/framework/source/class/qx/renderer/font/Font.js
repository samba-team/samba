/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************

#module(ui_basic)
#load(qx.renderer.font.FontObject)

************************************************************************ */

/*!
  Font implementation for qx.ui.core.Widget instances.
*/

qx.OO.defineClass("qx.renderer.font.Font", qx.core.Object,
function(vSize, vName)
{
  qx.core.Object.call(this);

  this._defs = {};

  if (qx.util.Validation.isValidNumber(vSize)) {
    this.setSize(vSize);
  }

  if (qx.util.Validation.isValidString(vName)) {
    this.setName(vName);
  }
});





/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "size", type : "number", impl : "style" });
qx.OO.addProperty({ name : "name", type : "string", impl : "style" });
qx.OO.addProperty({ name : "bold", type : "boolean", defaultValue : false, impl : "style" });
qx.OO.addProperty({ name : "italic", type : "boolean", defaultValue : false, impl : "style" });
qx.OO.addProperty({ name : "underline", type : "boolean", defaultValue : false, impl : "style" });
qx.OO.addProperty({ name : "strikeout", type : "boolean", defaultValue : false, impl : "style" });





/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyStyle = function(propValue, propOldValue, propData)
{
  this._needsCompilation = true;
  return true;
}




/*
---------------------------------------------------------------------------
  UTILITY
---------------------------------------------------------------------------
*/

qx.renderer.font.Font.fromString = function(s)
{
  var vFont = new qx.renderer.font.Font;
  var vAllParts = s.split(/\s+/);
  var vName = [];
  var vPart;

  for (var i = 0; i < vAllParts.length; i++)
  {
    switch(vPart = vAllParts[i])
    {
      case "bold":
        vFont.setBold(true);
        break;

      case "italic":
        vFont.setItalic(true);
        break;

      case "underline":
        vFont.setUnderline(true);
        break;

      case "strikeout":
        vFont.setStrikeout(true);
        break;

      default:
        var vTemp = parseFloat(vPart);

        if(vTemp == vPart || qx.lang.String.contains(vPart, "px"))
        {
          vFont.setSize(vTemp);
        }
        else
        {
          vName.push(vPart);
        }

        break;
    }
  }

  if(vName.length > 0) {
    vFont.setName(vName.join(" "));
  }

  return vFont;
}




/*
---------------------------------------------------------------------------
  UTILITY
---------------------------------------------------------------------------
*/

qx.Proto._needsCompilation = true;

qx.Proto._compile = function()
{
  var vName = this.getName();
  var vSize = this.getSize();
  var vBold = this.getBold();
  var vItalic = this.getItalic();
  var vUnderline = this.getUnderline();
  var vStrikeout = this.getStrikeout();
  var vDecoration = "";

  if (this.getUnderline()) {
    vDecoration = "underline";
  }

  if (this.getStrikeout()) {
    vDecoration += " " + "strikeout";
  }

  this._defs.fontFamily = qx.util.Validation.isValidString(vName) ? vName : "";
  this._defs.fontSize = qx.util.Validation.isValidNumber(vSize) ? vSize + "px" : "";
  this._defs.fontWeight = this.getBold() ? "bold" : "normal";
  this._defs.fontStyle = this.getItalic() ? "italic" : "normal";
  this._defs.textDecoration = qx.util.Validation.isValidString(vDecoration) ? vDecoration : "";

  this._needsCompilation = false;
}

qx.Proto._applyWidget = function(vWidget)
{
  if (this._needsCompilation) {
    this._compile();
  }

  vWidget.setStyleProperty("fontFamily", this._defs.fontFamily);
  vWidget.setStyleProperty("fontSize", this._defs.fontSize);
  vWidget.setStyleProperty("fontWeight", this._defs.fontWeight);
  vWidget.setStyleProperty("fontStyle", this._defs.fontStyle);
  vWidget.setStyleProperty("textDecoration", this._defs.textDecoration);
}

qx.Proto._resetWidget = function(vWidget)
{
  vWidget.removeStyleProperty("fontFamily");
  vWidget.removeStyleProperty("fontSize");
  vWidget.removeStyleProperty("fontWeight");
  vWidget.removeStyleProperty("fontStyle");
  vWidget.removeStyleProperty("textDecoration");
}






/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return true;
  }

  delete this._defs;

  return qx.core.Object.prototype.dispose.call(this);
}
