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

import org.ietf.jgss.*;
import java.io.*;
import java.net.Socket;
import java.net.ServerSocket;

public class jgssapi_server {

    static byte [] getMessage(DataInputStream inStream)
	throws IOException
    {
	byte[] token;
	token = new byte[inStream.readInt()];
	inStream.readFully(token);
	return token;
    }
    
    static void putMessage(DataOutputStream outStream, byte [] token)
	throws IOException
    {
	outStream.writeInt(token.length);
	outStream.write(token);
    }


    public static void main(String[] args) 
	throws IOException, GSSException {

	GSSManager manager = GSSManager.getInstance();

	GSSContext context = manager.createContext((GSSCredential)null);

	byte[] token = null;
	    
	int port = 4717;

	System.out.println("listen on port " + port);

	Socket s = new ServerSocket(port).accept();

	DataInputStream inStream = new DataInputStream(s.getInputStream());
	DataOutputStream outStream =  new DataOutputStream(s.getOutputStream());

	System.out.println("negotiate context");
	while (!context.isEstablished()) {
	    token = getMessage(inStream);

	    token = context.acceptSecContext(token, 0, token.length);
	    if (token != null)
		putMessage(outStream, token);
	}

	System.out.println("done");

	/*
	 * mic
	 */
	System.out.println("mic test");

	System.out.println("  verify mic");

	byte[] intoken = getMessage(inStream);
	byte[] outtoken = getMessage(inStream);
	byte[] bytes = null;

	context.verifyMIC(outtoken, 0, outtoken.length, 
			  intoken, 0, intoken.length, new MessageProp(0, false));

	System.out.println("  create mic");

	bytes = new byte[] { 0x66, 0x6f, 0x6f };

	outtoken = context.getMIC(bytes, 0, bytes.length, new MessageProp(0, false));
	putMessage(outStream, bytes);
	putMessage(outStream, outtoken);

	/*
	 * wrap int
	 */
	System.out.println("warp int");

	outtoken = getMessage(inStream);
	
	bytes = context.unwrap(outtoken, 0, outtoken.length, new MessageProp(0, false));

	if (bytes == null)
	    System.err.println("wrap int failed");

	/*
	 * wrap conf
	 */
	System.out.println("warp conf");

	outtoken = getMessage(inStream);
	
	bytes = context.unwrap(outtoken, 0, outtoken.length, new MessageProp(0, true));

	if (bytes == null)
	    System.err.println("wrap conf failed");


	/*
	 * wrap conf
	 */
	System.out.println("warp conf");
	intoken = new byte[] { 0x66, 0x6f, 0x6f };
	outtoken = context.wrap(intoken, 0, intoken.length, new MessageProp(0, true));
	putMessage(outStream, outtoken);
	outtoken = getMessage(inStream);

	context.dispose();

	System.exit(0);
    }
}

