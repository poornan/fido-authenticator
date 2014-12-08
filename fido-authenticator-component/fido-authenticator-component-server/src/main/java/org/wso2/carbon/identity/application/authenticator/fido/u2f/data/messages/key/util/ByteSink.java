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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Provides an easy way to construct a byte array.
 */
public class ByteSink {

    private final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    private final DataOutputStream dataOutputStream = new DataOutputStream(baos);

    public ByteSink putInt(int i) {
        try {
            dataOutputStream.writeInt(i);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    public ByteSink put(byte b) {
        try {
            dataOutputStream.write(b);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    public ByteSink put(byte[] b) {
        try {
            dataOutputStream.write(b);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    public byte[] toByteArray() {
        try {
            dataOutputStream.flush();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return baos.toByteArray();
    }

    public static ByteSink create() {
        return new ByteSink();
    }
}