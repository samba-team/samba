/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************

#module(ui_form)

************************************************************************ */

/**
 * @param vValue {String} this string is ddisplayed as the value of the TextArea.
 */
qx.OO.defineClass("qx.ui.form.TextArea", qx.ui.form.TextField,
function(vValue)
{
  qx.ui.form.TextField.call(this, vValue);

  this.setTagName("textarea");
  this.removeHtmlProperty("type");
});

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "text-area" });

qx.OO.addProperty({ name : "wrap", type : "boolean" });

if (qx.core.Client.getInstance().isMshtml())
{
  qx.Proto._modifyWrap = function(propValue, propOldValue, propData) {
    return this.setStyleProperty("whiteSpace", propValue ? "normal" : "nowrap");
  }
}
else
{
  qx.Proto._modifyWrap = function(propValue, propOldValue, propData) {
    return this.setHtmlProperty("wrap", propValue ? "soft" : "off");
  }
}

qx.Proto._computePreferredInnerHeight = function() {
  return 60;
}
