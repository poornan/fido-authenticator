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

package org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages;

import org.wso2.carbon.identity.application.authenticator.fido.u2f.exceptions.U2fException;
import org.junit.Test;

import static org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.ClientData.canonicalizeOrigin;
import static org.junit.Assert.*;

public class ClientDataTest {

    @Test
    public void shouldCanonicalizeOrigin() throws U2fException {
        assertEquals("http://example.com", canonicalizeOrigin("http://example.com"));
        assertEquals("http://example.com", canonicalizeOrigin("http://example.com/"));
        assertEquals("http://example.com", canonicalizeOrigin("http://example.com/foo"));
        assertEquals("http://example.com", canonicalizeOrigin("http://example.com/foo?bar=b"));
        assertEquals("http://example.com", canonicalizeOrigin("http://example.com/foo#fragment"));
        assertEquals("https://example.com", canonicalizeOrigin("https://example.com"));
        assertEquals("https://example.com", canonicalizeOrigin("https://example.com/foo"));
        assertEquals("android:apk-key-hash:2jmj7l5rSw0yVb/vlWAYkK/YBwk",
                canonicalizeOrigin("android:apk-key-hash:2jmj7l5rSw0yVb/vlWAYkK/YBwk"));
    }
}