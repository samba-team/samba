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

#module(ui_basic)
#optional(qx.ui.embed.Flash)

************************************************************************ */

/**
 * A multi-purpose widget used by many more complex widgets.
 *
 * The intended purpose of qx.ui.basic.Atom is to easily align the common icon-text combination in different ways.
 * This is useful for all types of buttons, menuentries, tooltips, ...
 *
 * @param vLabel {String} label of the atom
 * @param vIcon {String?null} Icon of the atom
 * @param vIconWidth {Integer?null} desired width of the icon (the icon will be scaled to this size)
 * @param vIconHeight {Integer?null} desired height of the icon (the icon will be scaled to this size)
 * @param vFlash {qx.ui.embed.Flash?null} optional flash animation for the Atom. Needs valid width and height values.
 */
qx.OO.defineClass("qx.ui.basic.Atom", qx.ui.layout.BoxLayout,
function(vLabel, vIcon, vIconWidth, vIconHeight, vFlash)
{
  qx.ui.layout.BoxLayout.call(this);

  if (this.getOrientation() == null) {
    this.setOrientation("horizontal");
  }

  // Prohibit selection
  this.setSelectable(false);

  // Disable flex support
  this.getLayoutImpl().setEnableFlexSupport(false);

  // Apply constructor arguments
  this.setLabel(vLabel);

  // Simple flash wrapper
  if (qx.OO.isAvailable("qx.ui.embed.Flash") && vFlash != null && vIconWidth != null && vIconHeight != null && qx.ui.embed.Flash.getPlayerVersion().getMajor() > 0)
  {
    this._flashMode = true;

    this.setIcon(vFlash);

    // flash needs explicit dimensions!
    this.setIconWidth(vIconWidth);
    this.setIconHeight(vIconHeight);
  }
  else if (vIcon != null)
  {
    this.setIcon(vIcon);

    if (vIconWidth != null) {
      this.setIconWidth(vIconWidth);
    }

    if (vIconHeight != null) {
      this.setIconHeight(vIconHeight);
    }
  }
});

qx.ui.basic.Atom.SHOW_LABEL = "label";
qx.ui.basic.Atom.SHOW_ICON = "icon";
qx.ui.basic.Atom.SHOW_BOTH = "both";


/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  The label/caption/text of the qx.ui.basic.Atom instance
*/
qx.OO.addProperty({ name : "label" });

/*!
  Any URI String supported by qx.ui.basic.Image to display a icon
*/
qx.OO.addProperty({ name : "icon", type : "string" });

/**
 * Any URI String supported by qx.ui.basic.Image to display a disabled icon.
 * <p>
 * If not set the normal icon is shown transparently.
 */
qx.OO.addProperty({ name : "disabledIcon", type : "string" });

/*!
  Configure the visibility of the sub elements/widgets.
  Possible values: both, text, icon, none
*/
qx.OO.addProperty({ name : "show", type : "string", defaultValue : "both", possibleValues : [ "both", "label", "icon", "none", null ] });

/*!
  The position of the icon in relation to the text.
  Only useful/needed if text and icon is configured and 'show' is configured as 'both' (default)
*/
qx.OO.addProperty({ name : "iconPosition", type : "string", defaultValue : "left", possibleValues : [ "top", "right", "bottom", "left" ] });

/*!
  The width of the icon.
  If configured, this makes qx.ui.basic.Atom a little bit faster as it does not need to wait until the image loading is finished.
*/
qx.OO.addProperty({ name : "iconWidth", type : "number" });

/*!
  The height of the icon
  If configured, this makes qx.ui.basic.Atom a little bit faster as it does not need to wait until the image loading is finished.
*/
qx.OO.addProperty({ name : "iconHeight", type : "number" });

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "atom" });





/*
---------------------------------------------------------------------------
  SUB WIDGETS
---------------------------------------------------------------------------
*/

qx.Proto._flashMode = false;

qx.Proto._labelObject = null;
qx.Proto._iconObject = null;

qx.Proto._createLabel = function()
{
  var l = this._labelObject = new qx.ui.basic.Label(this.getLabel());

  l.setAnonymous(true);
  l.setEnabled(this.getEnabled());
  l.setSelectable(false);

  this.addAt(l, this._iconObject ? 1 : 0);
}

qx.Proto._createIcon = function()
{
  if (this._flashMode && qx.OO.isAvailable("qx.ui.embed.Flash"))
  {
    var i = this._iconObject = new qx.ui.embed.Flash(this.getIcon());
  }
  else
  {
    var i = this._iconObject = new qx.ui.basic.Image();
  }

  i.setAnonymous(true);

  this._updateIcon();

  this.addAt(i, 0);
}

qx.Proto._updateIcon = function() {
  // NOTE: We have to check whether the properties "icon" and "disabledIcon"
  //       exist, because some child classes remove them.
  if (this._iconObject && this.getIcon && this.getDisabledIcon) {
    var disabledIcon = this.getDisabledIcon();
    if (disabledIcon) {
      if (this.getEnabled()) {
        this._iconObject.setSource(this.getIcon());
      } else {
        this._iconObject.setSource(disabledIcon);
      }
      this._iconObject.setEnabled(true);
    } else {
      this._iconObject.setSource(this.getIcon());
      this._iconObject.setEnabled(this.getEnabled());
    }
  }
}

qx.Proto.getLabelObject = function() {
  return this._labelObject;
}

qx.Proto.getIconObject = function() {
  return this._iconObject;
}






/*
---------------------------------------------------------------------------
  MODIFIERS
---------------------------------------------------------------------------
*/

qx.Proto._modifyEnabled = function(propValue, propOldValue, propData)
{
  this._updateIcon();

  if (this._labelObject) {
    this._labelObject.setEnabled(propValue);
  }

  return qx.ui.layout.BoxLayout.prototype._modifyEnabled.call(this, propValue, propOldValue, propData);
}

qx.Proto._modifyIconPosition = function(propValue, propOldValue, propData)
{
  switch(propValue)
  {
    case "top":
    case "bottom":
      this.setOrientation("vertical");
      this.setReverseChildrenOrder(propValue == "bottom");
      break;

    default:
      this.setOrientation("horizontal");
      this.setReverseChildrenOrder(propValue == "right");
      break;
  }

  return true;
}

qx.Proto._modifyShow = function(propValue, propOldValue, propData)
{
  this._handleIcon();
  this._handleLabel();

  return true;
}

qx.Proto._modifyLabel = function(propValue, propOldValue, propData)
{
  if (this._labelObject) {
    this._labelObject.setHtml(propValue);
  }

  this._handleLabel();

  return true;
}

qx.Proto._modifyIcon = function(propValue, propOldValue, propData)
{
  this._updateIcon();
  this._handleIcon();

  return true;
}

qx.Proto._modifyDisabledIcon = function(propValue, propOldValue, propData)
{
  this._updateIcon();
  this._handleIcon();

  return true;
}

qx.Proto._modifyIconWidth = function(propValue, propOldValue, propData)
{
  this._iconObject.setWidth(propValue);
  return true;
}

qx.Proto._modifyIconHeight = function(propValue, propOldValue, propData)
{
  this._iconObject.setHeight(propValue);
  return true;
}






/*
---------------------------------------------------------------------------
  HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._iconIsVisible = false;
qx.Proto._labelIsVisible = false;

qx.Proto._handleLabel = function()
{
  switch(this.getShow())
  {
    case qx.ui.basic.Atom.SHOW_LABEL:
    case qx.ui.basic.Atom.SHOW_BOTH:
      this._labelIsVisible = qx.util.Validation.isValidString(this.getLabel()) || this.getLabel() instanceof qx.locale.LocalizedString;
      break;

    default:
      this._labelIsVisible = false;
  }

  if (this._labelIsVisible)
  {
    this._labelObject ? this._labelObject.setDisplay(true) : this._createLabel();
  }
  else if (this._labelObject)
  {
    this._labelObject.setDisplay(false);
  }
}

qx.Proto._handleIcon = function()
{
  switch(this.getShow())
  {
    case qx.ui.basic.Atom.SHOW_ICON:
    case qx.ui.basic.Atom.SHOW_BOTH:
      this._iconIsVisible = qx.util.Validation.isValidString(this.getIcon());
      break;

    default:
      this._iconIsVisible = false;
  }

  if (this._iconIsVisible)
  {
    this._iconObject ? this._iconObject.setDisplay(true) : this._createIcon();
  }
  else if (this._iconObject)
  {
    this._iconObject.setDisplay(false);
  }
}






/*
---------------------------------------------------------------------------
  CLONE
---------------------------------------------------------------------------
*/

// Omit recursive cloning
qx.Proto._cloneRecursive = qx.lang.Function.returnTrue;







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

  if (this._iconObject)
  {
    this._iconObject.dispose();
    this._iconObject = null;
  }

  if (this._labelObject)
  {
    this._labelObject.dispose();
    this._labelObject = null;
  }

  return qx.ui.layout.BoxLayout.prototype.dispose.call(this);
}