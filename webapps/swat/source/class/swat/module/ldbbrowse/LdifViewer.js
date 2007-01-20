/*                                                                                                                    
 * Copyright::                                                                                                         
 *   (C) 2006 by Simo Sorce
 * 
 * License: 
 *   GPL v2 or later
 */

/**
 * Swat LDB Browser class graphical user interface
 */

qx.OO.defineClass("swat.module.ldbbrowse.LdifViewer", qx.ui.embed.HtmlEmbed,
function()
{
  qx.ui.embed.HtmlEmbed.call(this, "");

  this.setStyleProperty("whiteSpace", "nowrap");
  this.setStyleProperty("textOverflow", "ellipsis");

  this.setOverflow("auto");
  this.setSelectable(true);

  this.innerText = "";
});

qx.OO.addProperty({ name : "innerText", type : "string" });

qx.Class.empty = {
  html : "",
  innerText : ""
}

qx.Proto.reset = function() {
  this.innerText = "";
  this.setHtml("");
}

qx.Proto._update = function() {
  this.setHtml("<pre>" + this.innerText + "</pre>");
}

qx.Proto.appendComment = function(aText) {
  this.innerText = this.innerText + "# " + a Text + "\n\n";
  this._update();
}

qx.Proto.appendObject = function(o) {

  // First print the Object name as comment
  // TODO: Prettify it later
  var ldifRecord = "# " + o["dn"] + "\n";

  // Now the dn
  ldifRecord = ldifRecord + "dn: " + o["dn"] + "\n";

  // Now the attributes;
  for (var field in o)
  {

    // If it's multi-valued (type is an array)...
    if (typeof(o[field]) == "object")
    {
      // ... then add each value with same name
      var a = o[field];
      for (var i = 0; i < a.length; i++)
      {
        ldifRecord = ldifRecord + field + ": " + a[i] + "\n";
      }
    }
    else    // single-valued
    {
      ldifRecord = ldifRecord + field + ": " + o[field] + "\n";
    }
  }

  // Terminate the record with an empty line
  ldifRecord = ldifRecord + "\n";

  this.innerText = this.innerText + ldifRecord;
  this._update();
}
