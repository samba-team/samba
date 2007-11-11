/*
 * Copyright (c) 2007 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "krb5_locl.h"
RCSID("$Id$");

/**
 * 
 */

/*! \mainpage Heimdal NTLM library
 *
 * \section intro Introduction
 *
 * Heimdal libheimntlm library is a implementation of the NTLM
 * protocol, both version 1 and 2. It also support transport
 * encryption and integrity checking.
 * 
 * NTLM is a protocol for mutual authentication, its still used in
 * many protocol where Kerberos is not support, one example is
 * EAP/X802.1x mechanism LEAP from Microsoft and Cisco.
 *
 * This is a support library for the core protocol, its used in
 * Heimdal to implement and GSS-API mechanism. There is also support
 * in the KDC to do remote digest authenticiation, this to allow
 * services to authenticate users w/o direct access to the users ntlm
 * hashes (same as Kerberos arcfour enctype hashes).
 *
 * More information about the NTLM protocol can found here
 * http://davenport.sourceforge.net/ntlm.html .
 * 
 * The Heimdal projects web page: http://www.h5l.org/
 */

/** @defgroup ntlm_core Heimdal NTLM library */
