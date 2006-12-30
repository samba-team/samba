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
 * A key event instance contains all data for each occured key event
 *
 * @param vType (string) event type (keydown, keypress, keyinput, keyup)
 * @param vDomEvent (Element) DOM event object
 * @param vDomTarget (Element) target element of the DOM event
 * @param vTarget
 * @param vOriginalTarget
 * @param vKeyCode (int)
 * @param vCharCode (int)
 * @param vKeyIdentifier (string)
 */
qx.OO.defineClass("qx.event.type.KeyEvent", qx.event.type.DomEvent,
function(vType, vDomEvent, vDomTarget, vTarget, vOriginalTarget, vKeyCode, vCharCode, vKeyIdentifier)
{
  qx.event.type.DomEvent.call(this, vType, vDomEvent, vDomTarget, vTarget, vOriginalTarget);

  this.setKeyCode(vKeyCode);
  this.setCharCode(vCharCode);
  this.setKeyIdentifier(vKeyIdentifier);
});

/**
 * Legacy keycode
 * @deprecated Will be removed with qooxdoo 0.7
 */
qx.OO.addFastProperty({ name : "keyCode", setOnlyOnce : true, noCompute : true });

/**
 * Unicode number of the pressed character.
 * Only valid in "keyinput" events
 */
qx.OO.addFastProperty({ name : "charCode", setOnlyOnce : true, noCompute : true });

/**
 * Identifier of the pressed key.
 * Not Valid in "keyinput" events"
 */
qx.OO.addFastProperty({ name : "keyIdentifier", setOnlyOnce : true, noCompute : true });








/* ************************************************************************
   Class data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  CLASS PROPERTIES AND METHODS
---------------------------------------------------------------------------
*/

/**
 * Mapping of the old key identifiers to the key codes
 * @deprecated
 */
qx.event.type.KeyEvent.keys =
{
  esc : 27,
  enter : 13,
  tab : 9,
  space : 32,

  up : 38,
  down : 40,
  left : 37,
  right : 39,

  shift : 16,
  ctrl : 17,
  alt : 18,

  f1 : 112,
  f2 : 113,
  f3 : 114,
  f4 : 115,
  f5 : 116,
  f6 : 117,
  f7 : 118,
  f8 : 119,
  f9 : 120,
  f10 : 121,
  f11 : 122,
  f12 : 123,

  print : 124,

  del : 46,
  backspace : 8,
  insert : 45,
  home : 36,
  end : 35,

  pageup : 33,
  pagedown : 34,

  numlock : 144,

  numpad_0 : 96,
  numpad_1 : 97,
  numpad_2 : 98,
  numpad_3 : 99,
  numpad_4 : 100,
  numpad_5 : 101,
  numpad_6 : 102,
  numpad_7 : 103,
  numpad_8 : 104,
  numpad_9 : 105,

  numpad_divide : 111,
  numpad_multiply : 106,
  numpad_minus : 109,
  numpad_plus : 107
};

// create dynamic codes copy
(function() {
  qx.event.type.KeyEvent.codes = {};
  for (var i in qx.event.type.KeyEvent.keys) {
    qx.event.type.KeyEvent.codes[qx.event.type.KeyEvent.keys[i]] = i;
  }
})();
