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
     * Fabian Jakobs (fjakobs)

************************************************************************ */

/* ************************************************************************

#module(ui_core)
#require(qx.locale.Key)

************************************************************************ */

/**
 * This contains a command with shortcut.
 *
 * Each command could be assigned to multiple widgets.
 *
 * @event execute {qx.event.type.DataEvent} when the command is executed. Sets the
 *     "data" property of the event to the object that issued the command.
 *
 * @param vShortcut {String} shortcuts can be composed of optional modifier
 *    keys Control, Alt, Shift, Meta and a non modifier key.
 *    If no non modifier key is specified, the second paramater is evaluated.
 *    The key must be seperated by a <code>+</code> or <code>-</code> character.
 *    Examples: Alt+F1, Control+C, Control+Alt+Enf
 *
 * @param vKeyCode {Integer}  Additional key of the command interpreted as a keyCode.
 */
qx.OO.defineClass("qx.client.Command", qx.core.Target,
function(vShortcut, vKeyCode)
{
  qx.core.Target.call(this);

  this._modifier = {};
  this._key = null;

  if (vShortcut != null) {
    this.setShortcut(vShortcut);
  }

  if (vKeyCode != null)
  {
    this.warn("The use of keyCode in command is deprecated. Use keyIdentifier instead.");
    this.setKeyCode(vKeyCode);
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
 * keyCode
 * @deprecated
 *
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
 * @param vTarget {Object} Object which issued the execute event
 */
qx.Proto.execute = function(vTarget)
{
  if (this.hasEventListeners("execute")) {
    var event = new qx.event.type.DataEvent("execute", vTarget);
    this.dispatchEvent(event, true);
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
      var identifier = this._oldKeyNameToKeyIdentifier(a[i]);

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
--------------------------------------------------------------------------
  INTERNAL MATCHING LOGIC
---------------------------------------------------------------------------
*/

/**
 * Checks wether the given key event matches the command's shortcut
 *
 * @param e {qx.event.type.KeyEvent} the key event object
 * @return {Boolean} wether the commands shortcut matches the key event
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
    (this._modifier.Shift && !e.isShiftPressed()) ||
    (this._modifier.Control && !e.isCtrlPressed()) ||
//    (this._modifier.Meta && !e.getMetaKey()) ||
    (this._modifier.Alt && !e.isAltPressed())
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
  COMPATIBILITY TO COMMAND
---------------------------------------------------------------------------
*/

qx.Proto._oldKeyNameToKeyIdentifierMap =
{
  // all other keys are converted by converting the first letter to uppercase

  esc      : "Escape",
  ctrl     : "Control",
  print    : "PrintScreen",
  del      : "Delete",
  pageup   : "PageUp",
  pagedown : "PageDown",
  numlock  : "NumLock",
  numpad_0 : "0",
  numpad_1 : "1",
  numpad_2 : "2",
  numpad_3 : "3",
  numpad_4 : "4",
  numpad_5 : "5",
  numpad_6 : "6",
  numpad_7 : "7",
  numpad_8 : "8",
  numpad_9 : "9",
  numpad_divide   : "/",
  numpad_multiply : "*",
  numpad_minus    : "-",
  numpad_plus     : "+"
};


/**
 * converts an old key name as found in {@link qx.event.type.KeyEvent.keys} to
 * the new keyIdentifier.
 *
 * @param keyName {String} old name of the key.
 * @return {String} corresponding keyIdentifier or "Unidentified" if a conversion was not possible
 */
qx.Proto._oldKeyNameToKeyIdentifier = function(keyName)
{
  var keyHandler = qx.event.handler.KeyEventHandler.getInstance();
  var keyIdentifier = "Unidentified";

  if (keyHandler.isValidKeyIdentifier(keyName)) {
    return keyName;
  }

  if (keyName.length == 1 && keyName >= "a" && keyName <= "z") {
    return keyName.toUpperCase();
  }

  keyName = keyName.toLowerCase();

  // check wether its a valid old key name
  if (!qx.event.type.KeyEvent.keys[keyName]) {
    return "Unidentified";
  }

  var keyIdentifier = this._oldKeyNameToKeyIdentifierMap[keyName];
  if (keyIdentifier) {
    return keyIdentifier;
  } else {
    return qx.lang.String.toFirstUp(keyName);
  }
};


/*
---------------------------------------------------------------------------
  STRING CONVERTION
---------------------------------------------------------------------------
*/

/**
 * Returns the shortcut as string
 *
 * @return {String} shortcut
 */
qx.Proto.toString = function()
{
  //var vShortcut = this.getShortcut();
  var vKeyCode = this.getKeyCode();
  var key = this._key || this.getKeyIdentifier();

  var vString = [];

  for (var modifier in this._modifier) {
    vString.push(qx.locale.Key.getKeyName("short", modifier));
  }

  if (key) {
    vString.push(qx.locale.Key.getKeyName("short", key));
  }
  /*
  if (vShortcut != null) {
    vString.push(vShortcut);
  }
  */
  if (vKeyCode != null)
  {
    var vTemp = qx.event.type.KeyEvent.codes[vKeyCode];
    vString.push(vTemp ? qx.lang.String.toFirstUp(vTemp) : String(vKeyCode));
  }

  return vString.join("-");
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
