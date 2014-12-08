/*
 * Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.util;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

/**
 * Provides an easy way to read a byte array in chunks.
 */
//  ByteArrayInputStream cannot throw IOExceptions, so this class is converting checked exceptions to unchecked.
public class ByteInputStream extends DataInputStream {

    public ByteInputStream(byte[] data) {
        super(new ByteArrayInputStream(data));
    }

    public byte[] read(int numberOfBytes) {
        byte[] readBytes = new byte[numberOfBytes];
        try {
            readFully(readBytes);
        } catch (IOException e) {
            throw new AssertionError();
        }
        return readBytes;
    }

    public byte[] readAll() {
        try {
            byte[] readBytes = new byte[available()];
            readFully(readBytes);
            return readBytes;
        } catch (IOException e) {
            throw new AssertionError();
        }
    }

    public int readInteger() {
        try {
            return readInt();
        } catch (IOException e) {
            throw new AssertionError();
        }
    }

    public byte readSigned() {
        try {
            return readByte();
        } catch (IOException e) {
            throw new AssertionError();
        }
    }

    public int readUnsigned() {
        try {
            return readUnsignedByte();
        } catch (IOException e) {
            throw new AssertionError();
        }
    }
}
