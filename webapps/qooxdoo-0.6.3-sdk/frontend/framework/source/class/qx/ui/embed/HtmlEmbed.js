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
#require(qx.renderer.font.FontCache)
#after(qx.renderer.font.FontObject)

************************************************************************ */

qx.OO.defineClass("qx.ui.embed.HtmlEmbed", qx.ui.basic.Terminator,
function(vHtml)
{
  qx.ui.basic.Terminator.call(this);

  if (qx.util.Validation.isValidString(vHtml)) {
    this.setHtml(vHtml);
  }
});




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  Any text string which can contain HTML, too
*/
qx.OO.addProperty({ name : "html", type : "string" });

/*!
  The font property describes how to paint the font on the widget.
*/
qx.OO.addProperty({ name : "font", type : "object", instance : "qx.renderer.font.Font", convert : qx.renderer.font.FontCache, allowMultipleArguments : true });

/*!
  Wrap the text?
*/
qx.OO.addProperty({ name : "wrap", type : "boolean", defaultValue : true });




/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyHtml = function()
{
  if (this._isCreated) {
    this._syncHtml();
  }

  return true;
}

qx.Proto._modifyFont = function(propValue, propOldValue, propData)
{
  if (propValue) {
    propValue._applyWidget(this);
  } else if (propOldValue) {
    propOldValue._resetWidget(this);
  }

  return true;
}

qx.Proto._modifyWrap = function(propValue, propOldValue, propData)
{
  this.setStyleProperty("whiteSpace", propValue ? "normal" : "nowrap");
  return true;
}





/*
---------------------------------------------------------------------------
  ELEMENT HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._applyElementData = function() {
  this._syncHtml();
}

qx.Proto._syncHtml = function() {
  this.getElement().innerHTML = this.getHtml();
}
