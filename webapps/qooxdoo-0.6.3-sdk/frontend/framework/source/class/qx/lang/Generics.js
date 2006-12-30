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

qx.OO.defineClass("qx.lang.Generics");


/*
---------------------------------------------------------------------------
  DEFAULT SETTINGS
---------------------------------------------------------------------------
*/

qx.Settings.setDefault("enable", false);





/*
---------------------------------------------------------------------------
  JAVASCRIPT 1.6 GENERICS
---------------------------------------------------------------------------
*/

// Copyright 2006 Erik Arvidsson
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// http://erik.eae.net/archives/2006/02/28/00.39.52/

// Relicensed under LGPL for qooxdoo.

qx.lang.Generics.init = function()
{
  // Make generic versions of instance methods
  var makeGeneric = [
  {
    object: Array,
    methods:
    [
      "join",
      "reverse",
      "sort",
      "push",
      "pop",
      "shift",
      "unshift",
      "splice",
      "concat",
      "slice",
      "indexOf",
      "lastIndexOf",
      "forEach",
      "map",
      "filter",
      "some",
      "every"
    ]
  },
  {
    object: String,
    methods:
    [
      "quote",
      "substring",
      "toLowerCase",
      "toUpperCase",
      "charAt",
      "charCodeAt",
      "indexOf",
      "lastIndexOf",
      "toLocaleLowerCase",
      "toLocaleUpperCase",
      "localeCompare",
      "match",
      "search",
      "replace",
      "split",
      "substr",
      "concat",
      "slice"
    ]
  }];

  for (var i=0, l=makeGeneric.length; i<l; i++)
  {
    var constr = makeGeneric[i].object;
    var methods = makeGeneric[i].methods;

    for (var j=0; j<methods.length; j++)
    {
      var name = methods[j];

      if (!constr[name])
      {
        constr[methods[j]] = (function(constr, name)
        {
          return function(s)
          {
            var args = Array.prototype.slice.call(arguments, 1);
            return constr.prototype[name].apply(s, args);
          }
        })(constr, name);
      }
    }
  }
}

if (qx.Settings.getValueOfClass("qx.lang.Generics", "enable")) {
  qx.lang.Generics.init();
}
