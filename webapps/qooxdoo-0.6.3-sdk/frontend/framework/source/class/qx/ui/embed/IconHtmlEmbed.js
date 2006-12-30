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


************************************************************************ */

qx.OO.defineClass("qx.ui.embed.IconHtmlEmbed", qx.ui.embed.HtmlEmbed,
function(vHtml, vIcon, vIconWidth, vIconHeight)
{
  qx.ui.embed.HtmlEmbed.call(this, vHtml);

  if (typeof vIcon != "undefined")
  {
    this.setIcon(vIcon);

    if (typeof vIconWidth != "undefined") {
      this.setIconWidth(vIconWidth);
    }

    if (typeof vIconHeight != "undefined") {
      this.setIconHeight(vIconWidth);
    }
  }
});




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  Any URI String supported by qx.ui.basic.Image to display a icon
*/
qx.OO.addProperty({ name : "icon", type : "string", impl : "html" });

/*!
  The width of the icon.
  If configured, this makes qx.ui.embed.IconHtmlEmbed a little bit faster as it does not need to wait until the image loading is finished.
*/
qx.OO.addProperty({ name : "iconWidth", type : "number", impl : "html" });

/*!
  The height of the icon
  If configured, this makes qx.ui.embed.IconHtmlEmbed a little bit faster as it does not need to wait until the image loading is finished.
*/
qx.OO.addProperty({ name : "iconHeight", type : "number", impl : "html" });

/*!
  Space in pixels between the icon and the HTML.
*/
qx.OO.addProperty({ name : "spacing", type : "number", defaultValue : 4, impl : "html" });





/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto._mshtml = qx.sys.Client.getInstance().isMshtml();

qx.Proto._syncHtml = function()
{
  var vHtml = [];

  if (qx.util.Validation.isValidString(this.getIcon()))
  {
    vHtml.push("<img src=\"");
    vHtml.push(qx.manager.object.AliasManager.getInstance().resolvePath(this._mshtml ? "static/image/blank.gif" : this.getIcon()));
    vHtml.push("\" style=\"vertical-align:middle;");

    if (qx.util.Validation.isValidNumber(this.getSpacing()))
    {
      vHtml.push("margin-right:");
      vHtml.push(this.getSpacing());
      vHtml.push("px;");
    }

    if (qx.util.Validation.isValidNumber(this.getIconWidth()))
    {
      vHtml.push("width:");
      vHtml.push(this.getIconWidth());
      vHtml.push("px;");
    }

    if (qx.util.Validation.isValidNumber(this.getIconHeight()))
    {
      vHtml.push("height:");
      vHtml.push(this.getIconHeight());
      vHtml.push("px;");
    }

    if (this._mshtml)
    {
      vHtml.push("filter:");
      vHtml.push("progid:DXImageTransform.Microsoft.AlphaImageLoader(src='");
      vHtml.push(qx.manager.object.AliasManager.getInstance().resolvePath(this.getIcon()));
      vHtml.push("',sizingMethod='scale')");
      vHtml.push(";");
    }

    vHtml.push("\"/>");
  }

  if (qx.util.Validation.isValidString(this.getHtml())) {
    vHtml.push(this.getHtml());
  }

  this.getElement().innerHTML = vHtml.join("");
}
