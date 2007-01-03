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
     * Fabian Jakobs (fjakobs)

************************************************************************ */

/* ************************************************************************

#module(ui_core)

************************************************************************ */

/**
 * This contains a command with shortcut.
 *
 * Each command could be assigned to multiple widgets.
 *
 * @event execute {qx.event.type.DataEvent} when the command is executed.
 *
 * @param vShortcut (string) shortcuts can be composed of optional modifier
 *    keys Control, Alt, Shift, Meta and a non modifier key.
 *    If no non modifier key is specified, the second paramater is evaluated.
 *    The key must be seperated by a ''+'' or ''-'' character.
 *    Examples: Alt+F1, Control+C, Control+Alt+Enf
 *
 * @param vKeyCodeOrIdentifier (int)  Additional key of the command. It is interpreted as a
 *    keyIdentifier if it is given as integer. Otherwhise it is interpreted as keyCode.
 */
qx.OO.defineClass("qx.client.Command", qx.core.Target,
function(vShortcut, vKeyCodeOrIdentifier)
{
  qx.core.Target.call(this);

  this._modifier = {};
  this._key = null;

  if (qx.util.Validation.isValid(vShortcut)) {
    this.setShortcut(vShortcut);
  }

  if (qx.util.Validation.isValid(vKeyCodeOrIdentifier))
  {
     if (qx.util.Validation.isValidString(vKeyCodeOrIdentifier))
     {
      this.setKeyIdentifier(vKeyCodeOrIdentifier);
     }
     else if (qx.util.Validation.isValidNumber(vKeyCodeOrIdentifier))
     {
      this.warn("The use of keyCode in command is deprecated. Use keyIdentifier instead.");
      this.setKeyCode(vKeyCodeOrIdentifier);
    }
    else
    {
      var msg = "vKeyCodeOrIdentifier must be of type string or number: " + vKeyCodeOrIdentifier;
      this.error(msg);
      throw msg;
    }
  }

  // OSX warning for Alt key combinations
  if (this._modifier.Alt && this._key && this._key.length == 1) {
    if (
      (this._key >= "A" && this._key <= "Z") ||
      (this._key >= "0" && this._key <= "9")
    ) {
      this.warn("A shortcut containing Alt and a letter or number will not work under OS X!");
    }
  }
  qx.event.handler.EventHandler.getInstance().addCommand(this);
});


/** the command shortcut */
qx.OO.addProperty({ name : "shortcut", type : "string" });

/**
 * keyCode (Deprecated)
 * Still there for compatibility with the old key handler/commands
 */
qx.OO.addProperty({ name : "keyCode", type : "number" });

/** KeyIdentifier */
qx.OO.addProperty({ name : "keyIdentifier", type : "string" });



/*
---------------------------------------------------------------------------
  USER METHODS
---------------------------------------------------------------------------
*/

/**
 * Fire the "execute" event on this command.
 *
 * @param vTarget (Object)
 */
qx.Proto.execute = function(vTarget)
{
  if (this.hasEventListeners("execute")) {
    this.dispatchEvent(new qx.event.type.DataEvent("execute", vTarget), true);
  }

  return false;
};



/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyShortcut = function(propValue, propOldValue, propData)
{
  if (propValue)
  {
    this._modifier = {};
    this._key = null;

    // split string to get each key which must be pressed
    // build a hash with active keys
    var a = propValue.split(/[-+\s]+/);
    var al = a.length;

    for (var i=0; i<al; i++)
    {
      var identifier = qx.event.handler.KeyEventHandler.getInstance().oldKeyNameToKeyIdentifier(a[i]);

      switch (identifier)
      {
        case "Control":
        case "Shift":
        case "Meta":
        case "Alt":
          this._modifier[identifier] = true;
          break;

        case "Unidentified":
          var msg = "Not a valid key name for a command: " + a[i];
          this.error(msg);
          throw msg;

        default:
          if (this._key) {
            var msg = "You can only specify one non modifier key!";
            this.error(msg);
            throw msg;
          }
          this._key = identifier;
      }
    }
  }
  return true;
};



/*
---------------------------------------------------------------------------
  INTERNAL MATCHING LOGIC
---------------------------------------------------------------------------
*/

/**
 * Checks wether the given key event matches the command's shortcut
 *
 * @param e (qx.event.type.KeyEvent) the key event object
 * @return (boolean) wether the commands shortcut matches the key event
 */
qx.Proto._matchesKeyEvent = function(e)
{
  var key = this._key || this.getKeyIdentifier();
  if (!key && !this.getKeyCode()) {
    // no shortcut defined.
    return;
  }

  // pre-check for check special keys
  // we handle this here to omit to check this later again.
  if (
    (this._modifier.Shift && !e.getShiftKey()) ||
    (this._modifier.Control && !e.getCtrlKey()) ||
//    (this._modifier.Meta && !e.getCtrlKey()) ||
    (this._modifier.Alt && !e.getAltKey())
  ) {
    return false;
  }

  if (key)
  {
    if (key == e.getKeyIdentifier()) {
      return true;
    }
  }
  else
  {
    if (this.getKeyCode() == e.getKeyCode()) {
      return true;
    }
  }

  return false;
};



/*
---------------------------------------------------------------------------
  STRING CONVERTION
---------------------------------------------------------------------------
*/

/**
 * Returns the shortcut as string
 *
 * @return (string) shortcut
 */
qx.Proto.toString = function()
{
  var vShortcut = this.getShortcut();
  var vKeyCode = this.getKeyCode();
  var vString = "";
  var vKeyIdentifier = this._key || this.getKeyIdentifier();

  var vKeyString = "";
  if (qx.util.Validation.isValidString(vKeyIdentifier))
  {
    vKeyString = vKeyIdentifier;
  }
  else if (qx.util.Validation.isValidNumber(vKeyCode))
  {
    var vTemp = qx.event.type.KeyEvent.codes[vKeyCode];
    vKeyString = vTemp ? qx.lang.String.toFirstUp(vTemp) : String(vKeyCode);
  }

  if (qx.util.Validation.isValidString(vShortcut))
  {
    vString = vShortcut + "+" + vKeyString;
  }
  else if (qx.util.Validation.isValidNumber(vKeyCode))
  {
    vString = vKeyString;
  }

  return vString;
};



/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

/**
 * Destructor
 */
qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  this._shortcutParts = null;

  var vMgr = qx.event.handler.EventHandler.getInstance();
  if (vMgr) {
    vMgr.removeCommand(this);
  }

  return qx.core.Target.prototype.dispose.call(this);
};
