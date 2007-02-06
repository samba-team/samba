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

#module(ui_core)
#require(qx.lang.Function)
#load(qx.renderer.color.ColorObject)

************************************************************************ */

qx.OO.defineClass("qx.renderer.color.Color", qx.core.Object,
function(vValue)
{
  if (vValue != null) {
    this.setValue(vValue);
  }

  qx.core.Object.call(this);
});





/* ************************************************************************
   Class data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  CORE METHODS
---------------------------------------------------------------------------
*/

qx.Class.rgb2style = function(r, g, b) {
  return "rgb(" + r + "," + g + "," + b + ")";
}





/*
---------------------------------------------------------------------------
  CORE DATA
---------------------------------------------------------------------------
*/

qx.renderer.color.Color.m_hex = [ "0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f" ];
qx.renderer.color.Color.m_rgb = { 0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,a:10,b:11,c:12,d:13,e:14,f:15 }

qx.renderer.color.Color.r_hex3 = /^#([0-9a-f]{1})([0-9a-f]{1})([0-9a-f]{1})$/;
qx.renderer.color.Color.r_hex6 = /^#([0-9a-f]{1})([0-9a-f]{1})([0-9a-f]{1})([0-9a-f]{1})([0-9a-f]{1})([0-9a-f]{1})$/;
qx.renderer.color.Color.r_cssrgb = /^rgb\(\s*([0-9]{1,3}\.{0,1}[0-9]*)\s*,\s*([0-9]{1,3}\.{0,1}[0-9]*)\s*,\s*([0-9]{1,3}\.{0,1}[0-9]*)\s*\)$/;

qx.renderer.color.Color.r_rgb = /^[0-9]{1,3},[0-9]{1,3},[0-9]{1,3}$/;
qx.renderer.color.Color.r_number = /^[0-9]{1,3}\.{0,1}[0-9]*$/;
qx.renderer.color.Color.r_percent = /^[0-9]{1,3}\.{0,1}[0-9]*%$/;

/**
 * CSS 3 colors (http://www.w3.org/TR/css3-color/#svg-color)
 *
 * This includes all classic HTML Color names (http://www.w3.org/TR/css3-color/#html4) and the <code>transparent</code> keyword.
 */
qx.Class.htmlNames =
{
  transparent : [-1,-1,-1],
  aliceblue : [ 240,248,255 ],
  antiquewhite : [ 250,235,215 ],
  aqua : [ 0,255,255 ],
  aquamarine : [ 127,255,212 ],
  azure : [ 240,255,255 ],
  beige : [ 245,245,220 ],
  bisque : [ 255,228,196 ],
  black : [ 0,0,0 ],
  blanchedalmond : [ 255,235,205 ],
  blue : [ 0,0,255 ],
  blueviolet : [ 138,43,226 ],
  brown : [ 165,42,42 ],
  burlywood : [ 222,184,135 ],
  cadetblue : [ 95,158,160 ],
  chartreuse : [ 127,255,0 ],
  chocolate : [ 210,105,30 ],
  coral : [ 255,127,80 ],
  cornflowerblue : [ 100,149,237 ],
  cornsilk : [ 255,248,220 ],
  crimson : [ 220,20,60 ],
  cyan : [ 0,255,255 ],
  darkblue : [ 0,0,139 ],
  darkcyan : [ 0,139,139 ],
  darkgoldenrod : [ 184,134,11 ],
  darkgray : [ 169,169,169 ],
  darkgreen : [ 0,100,0 ],
  darkgrey : [ 169,169,169 ],
  darkkhaki : [ 189,183,107 ],
  darkmagenta : [ 139,0,139 ],
  darkolivegreen : [ 85,107,47 ],
  darkorange : [ 255,140,0 ],
  darkorchid : [ 153,50,204 ],
  darkred : [ 139,0,0 ],
  darksalmon : [ 233,150,122 ],
  darkseagreen : [ 143,188,143 ],
  darkslateblue : [ 72,61,139 ],
  darkslategray : [ 47,79,79 ],
  darkslategrey : [ 47,79,79 ],
  darkturquoise : [ 0,206,209 ],
  darkviolet : [ 148,0,211 ],
  deeppink : [ 255,20,147 ],
  deepskyblue : [ 0,191,255 ],
  dimgray : [ 105,105,105 ],
  dimgrey : [ 105,105,105 ],
  dodgerblue : [ 30,144,255 ],
  firebrick : [ 178,34,34 ],
  floralwhite : [ 255,250,240 ],
  forestgreen : [ 34,139,34 ],
  fuchsia : [ 255,0,255 ],
  gainsboro : [ 220,220,220 ],
  ghostwhite : [ 248,248,255 ],
  gold : [ 255,215,0 ],
  goldenrod : [ 218,165,32 ],
  gray : [ 128,128,128 ],
  green : [ 0,128,0 ],
  greenyellow : [ 173,255,47 ],
  grey : [ 128,128,128 ],
  honeydew : [ 240,255,240 ],
  hotpink : [ 255,105,180 ],
  indianred : [ 205,92,92 ],
  indigo : [ 75,0,130 ],
  ivory : [ 255,255,240 ],
  khaki : [ 240,230,140 ],
  lavender : [ 230,230,250 ],
  lavenderblush : [ 255,240,245 ],
  lawngreen : [ 124,252,0 ],
  lemonchiffon : [ 255,250,205 ],
  lightblue : [ 173,216,230 ],
  lightcoral : [ 240,128,128 ],
  lightcyan : [ 224,255,255 ],
  lightgoldenrodyellow : [ 250,250,210 ],
  lightgray : [ 211,211,211 ],
  lightgreen : [ 144,238,144 ],
  lightgrey : [ 211,211,211 ],
  lightpink : [ 255,182,193 ],
  lightsalmon : [ 255,160,122 ],
  lightseagreen : [ 32,178,170 ],
  lightskyblue : [ 135,206,250 ],
  lightslategray : [ 119,136,153 ],
  lightslategrey : [ 119,136,153 ],
  lightsteelblue : [ 176,196,222 ],
  lightyellow : [ 255,255,224 ],
  lime : [ 0,255,0 ],
  limegreen : [ 50,205,50 ],
  linen : [ 250,240,230 ],
  magenta : [ 255,0,255 ],
  maroon : [ 128,0,0 ],
  mediumaquamarine : [ 102,205,170 ],
  mediumblue : [ 0,0,205 ],
  mediumorchid : [ 186,85,211 ],
  mediumpurple : [ 147,112,219 ],
  mediumseagreen : [ 60,179,113 ],
  mediumslateblue : [ 123,104,238 ],
  mediumspringgreen : [ 0,250,154 ],
  mediumturquoise : [ 72,209,204 ],
  mediumvioletred : [ 199,21,133 ],
  midnightblue : [ 25,25,112 ],
  mintcream : [ 245,255,250 ],
  mistyrose : [ 255,228,225 ],
  moccasin : [ 255,228,181 ],
  navajowhite : [ 255,222,173 ],
  navy : [ 0,0,128 ],
  oldlace : [ 253,245,230 ],
  olive : [ 128,128,0 ],
  olivedrab : [ 107,142,35 ],
  orange : [ 255,165,0 ],
  orangered : [ 255,69,0 ],
  orchid : [ 218,112,214 ],
  palegoldenrod : [ 238,232,170 ],
  palegreen : [ 152,251,152 ],
  paleturquoise : [ 175,238,238 ],
  palevioletred : [ 219,112,147 ],
  papayawhip : [ 255,239,213 ],
  peachpuff : [ 255,218,185 ],
  peru : [ 205,133,63 ],
  pink : [ 255,192,203 ],
  plum : [ 221,160,221 ],
  powderblue : [ 176,224,230 ],
  purple : [ 128,0,128 ],
  red : [ 255,0,0 ],
  rosybrown : [ 188,143,143 ],
  royalblue : [ 65,105,225 ],
  saddlebrown : [ 139,69,19 ],
  salmon : [ 250,128,114 ],
  sandybrown : [ 244,164,96 ],
  seagreen : [ 46,139,87 ],
  seashell : [ 255,245,238 ],
  sienna : [ 160,82,45 ],
  silver : [ 192,192,192 ],
  skyblue : [ 135,206,235 ],
  slateblue : [ 106,90,205 ],
  slategray : [ 112,128,144 ],
  slategrey : [ 112,128,144 ],
  snow : [ 255,250,250 ],
  springgreen : [ 0,255,127 ],
  steelblue : [ 70,130,180 ],
  tan : [ 210,180,140 ],
  teal : [ 0,128,128 ],
  thistle : [ 216,191,216 ],
  tomato : [ 255,99,71 ],
  turquoise : [ 64,224,208 ],
  violet : [ 238,130,238 ],
  wheat : [ 245,222,179 ],
  white : [ 255,255,255 ],
  whitesmoke : [ 245,245,245 ],
  yellow : [ 255,255,0 ],
  yellowgreen : [ 154,205,50 ]
};

/**
 * ActiveBorder: Active window border.
 * ActiveCaption: Active window caption.
 *
 * AppWorkspace: Background color of multiple document interface.
 * Background: Desktop background.
 *
 * ButtonFace: Face color for three-dimensional display elements.
 * ButtonHighlight: Highlight color for three-dimensional display elements (for edges facing away from the light source).
 * ButtonShadow: Shadow color for three-dimensional display elements.
 * ButtonText: Text on push buttons.
 *
 * CaptionText: Text in caption, size box, and scrollbar arrow box.
 * GrayText: Grayed (disabled) text.
 *
 * Highlight: Item(s) selected in a control.
 * HighlightText: Text of item(s) selected in a control.
 *
 * InactiveBorder: Inactive window border.
 * InactiveCaption: Inactive window caption.
 * InactiveCaptionText: Color of text in an inactive caption.
 *
 * InfoBackground: Background color for tooltip controls.
 * InfoText: Text color for tooltip controls.
 *
 * Menu: Menu background.
 * MenuText: Text in menus.
 *
 * Scrollbar: Scroll bar gray area.
 *
 * ThreeDDarkShadow: Dark shadow for three-dimensional display elements.
 * ThreeDFace: Face color for three-dimensional display elements.
 * ThreeDHighlight: Highlight color for three-dimensional display elements.
 * ThreeDLightShadow: Light color for three-dimensional display elements (for edges facing the light source).
 * ThreeDShadow: Dark shadow for three-dimensional display elements.
 *
 * Window: Window background.
 * WindowFrame: Window frame.
 * WindowText: Text in windows.
 */
qx.Class.themedNames =
{
  activeborder : 1,
  activecaption : 1,
  appworkspace : 1,
  background : 1,
  buttonface : 1,
  buttonhighlight : 1,
  buttonshadow : 1,
  buttontext : 1,
  captiontext : 1,
  graytext : 1,
  highlight : 1,
  highlighttext : 1,
  inactiveborder : 1,
  inactivecaption : 1,
  inactivecaptiontext : 1,
  infobackground : 1,
  infotext : 1,
  menu : 1,
  menutext : 1,
  scrollbar : 1,
  threeddarkshadow : 1,
  threedface : 1,
  threedhighlight : 1,
  threedlightshadow : 1,
  threedshadow : 1,
  window : 1,
  windowframe : 1,
  windowtext : 1
}







/* ************************************************************************
   Instance data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  UTILITY
---------------------------------------------------------------------------
*/

qx.Class.fromString = function(vDefString) {
  return new qx.renderer.color.Color(vDefString);
}

qx.Class.fromRandom = function() {
  return new qx.renderer.color.Color([Math.round(255*Math.random()), Math.round(255*Math.random()), Math.round(255*Math.random())]);
}






/*
---------------------------------------------------------------------------
  DATA
---------------------------------------------------------------------------
*/

qx.Proto._value = null;
qx.Proto._style = null;

qx.Proto._isRgbColor = false;
qx.Proto._isHtmlColor = false;
qx.Proto._isThemedColor = false;

qx.Proto._red = null;
qx.Proto._green = null;
qx.Proto._blue = null;

qx.Proto._hex = null;





/*
---------------------------------------------------------------------------
  COMPATIBILITY METHODS
---------------------------------------------------------------------------
*/

qx.Proto.add = qx.lang.Function.returnTrue;
qx.Proto.remove = qx.lang.Function.returnTrue;






/*
---------------------------------------------------------------------------
  PUBLIC METHODS
---------------------------------------------------------------------------
*/

qx.Proto.isRgbColor = function() {
  return this._isRgbColor;
}

qx.Proto.isHtmlColor = function() {
  return this._isHtmlColor;
}

qx.Proto.isThemedColor = function() {
  return this._isThemedColor;
}




qx.Proto.setValue = function(vValue)
{
  this._normalize(vValue);

  if (this._isThemedColor) {
    throw new Error("Please use qx.renderer.color.ColorObject for themed colors!");
  }
}

qx.Proto.getValue = function() {
  return this._value || "";
}




qx.Proto.getStyle = function()
{
  if (this._style == null) {
    this._evalStyle();
  }

  return this._style;
}

qx.Proto._evalStyle = function()
{
  if (this._isRgbColor)
  {
    this._style = qx.renderer.color.Color.rgb2style(this._red, this._green, this._blue);
  }
  else if (this._isThemedColor)
  {
    this._applyThemedValue();
  }
  else if (this._isHtmlColor)
  {
    this._style = this._value;
  }
  else if (this._value != null)
  {
    this.error("Could not handle non-rgb colors :" + this.getValue() + "!");
  }
}




qx.Proto.getHex = function()
{
  if (this._hex == null) {
    this._evalHex();
  }

  return this._hex;
}

qx.Proto._evalHex = function()
{
  if (this._isRgbColor)
  {
    var a = ["#"];

    var r = this.getRed();
    a.push(qx.renderer.color.Color.m_hex[Math.floor(r/16)]);
    a.push(qx.renderer.color.Color.m_hex[Math.floor(r%16)]);

    var g = this.getGreen();
    a.push(qx.renderer.color.Color.m_hex[Math.floor(g/16)]);
    a.push(qx.renderer.color.Color.m_hex[Math.floor(g%16)]);

    var b = this.getBlue();
    a.push(qx.renderer.color.Color.m_hex[Math.floor(b/16)]);
    a.push(qx.renderer.color.Color.m_hex[Math.floor(b%16)]);

    this._hex = a.join("");
  }
  else
  {
    // TODO
  }
}




qx.Proto.getRed = function()
{
  if (this._red == null) {
    this._evalRgb();
  }

  return this._red;
}

qx.Proto.getGreen = function()
{
  if (this._green == null) {
    this._evalRgb();
  }

  return this._green;
}

qx.Proto.getBlue = function()
{
  if (this._blue == null) {
    this._evalRgb();
  }

  return this._blue;
}




qx.Proto._evalRgb = function()
{
  if (this._isThemedColor)
  {
    this._applyThemedValue();
  }
  else if (this._isHtmlColor)
  {
    var a = qx.renderer.color.Color.htmlNames[this._value];

    this._red = a[0];
    this._green = a[1];
    this._blue = a[2];
  }
  else
  {
    throw new Error("_evalRgb needs implementation!");
  }
}





/*
---------------------------------------------------------------------------
  PRIVATE METHODS
---------------------------------------------------------------------------
*/

qx.Proto._normalize = function(vInValue)
{
  this._isThemedColor = this._isRgbColor = this._isHtmlColor = false;
  this._hex = null;

  var invalid = new Error("Invalid color: " + vInValue);

  switch(typeof vInValue)
  {
    case "string":
      vInValue = vInValue.toLowerCase();

      if (qx.renderer.color.Color.htmlNames[vInValue])
      {
        this._isHtmlColor = true;
      }
      else if (qx.renderer.color.Color.themedNames[vInValue])
      {
        this._isThemedColor = true;
      }
      else if (qx.renderer.color.Color.r_cssrgb.test(vInValue))
      {
        this._red   = parseInt(RegExp.$1);
        this._green = parseInt(RegExp.$2);
        this._blue  = parseInt(RegExp.$3);

        this._isRgbColor = true;
      }
      else if (qx.renderer.color.Color.r_hex3.test(vInValue))
      {
        this._hex = vInValue;

        this._red   = (qx.renderer.color.Color.m_rgb[RegExp.$1] * 16) + qx.renderer.color.Color.m_rgb[RegExp.$1];
        this._green = (qx.renderer.color.Color.m_rgb[RegExp.$2] * 16) + qx.renderer.color.Color.m_rgb[RegExp.$2];
        this._blue  = (qx.renderer.color.Color.m_rgb[RegExp.$3] * 16) + qx.renderer.color.Color.m_rgb[RegExp.$3];

        this._isRgbColor = true;
      }
      else if (qx.renderer.color.Color.r_hex6.test(vInValue))
      {
        this._hex = vInValue;

        this._red   = (qx.renderer.color.Color.m_rgb[RegExp.$1] * 16) + qx.renderer.color.Color.m_rgb[RegExp.$2];
        this._green = (qx.renderer.color.Color.m_rgb[RegExp.$3] * 16) + qx.renderer.color.Color.m_rgb[RegExp.$4];
        this._blue  = (qx.renderer.color.Color.m_rgb[RegExp.$5] * 16) + qx.renderer.color.Color.m_rgb[RegExp.$6];

        this._isRgbColor = true;
      }
      else
      {
        throw invalid;
      }

      break;

    case "number":
      if (vInValue >= 0 && vInValue <= 255)
      {
        this._red = this._green = this._blue = vInValue;
        this._isRgbColor = true;
      }
      else
      {
        throw invalid;
      }

      break;

    case "object":
      if (qx.util.Validation.isValidArray(vInValue) && vInValue.length == 3)
      {
        this._red = vInValue[0];
        this._green = vInValue[1];
        this._blue = vInValue[2];

        this._isRgbColor = true;
        break;
      }

    default:
      throw invalid;
  }

  if (!this._isRgbColor)
  {
    this._red = this._green = this._blue = null;
    this._style = this._isHtmlColor ? vInValue : null;
  }
  else
  {
    this._style = null;

    if (!(this._red >= 0 && this._red <= 255 && this._green >= 0 && this._green <= 255 && this._blue >= 0 && this._blue <= 255)) {
      throw invalid;
    }
  }

  return this._value = vInValue;
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

  delete this._value;
  delete this._style;

  delete this._red;
  delete this._green;
  delete this._blue;

  delete this._isRgbColor;
  delete this._isHtmlColor;
  delete this._isThemedColor;

  return qx.core.Object.prototype.dispose.call(this);
}
