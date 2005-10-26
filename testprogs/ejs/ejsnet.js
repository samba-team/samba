#!/usr/bin/env smbscript

var ctx = NetContext("Administrator", "admin");
ctx.CreateUser("noname");
