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

package org.wso2.carbon.identity.application.authenticator.fido.u2f.softkey.messages;

public class AuthenticateRequest {

    private final byte control;
    private final byte[] challengeSha256;
    private final byte[] applicationSha256;
    private final byte[] keyHandle;

    public AuthenticateRequest(byte control, byte[] challengeSha256, byte[] applicationSha256,
                               byte[] keyHandle) {
        this.control = control;
        this.challengeSha256 = challengeSha256;
        this.applicationSha256 = applicationSha256;
        this.keyHandle = keyHandle;
    }

    /**
     * The FIDO Client will set the control byte to one of the following values:
     * 0x07 ("check-only")
     * 0x03 ("enforce-user-presence-and-sign")
     */
    public byte getControl() {
        return control;
    }

    /**
     * The challenge parameter is the SHA-256 hash of the Client Data, a
     * stringified JSON datastructure that the FIDO Client prepares. Among other
     * things, the Client Data contains the challenge from the relying party
     * (hence the name of the parameter). See below for a detailed explanation of
     * Client Data.
     */
    public byte[] getChallengeSha256() {
        return challengeSha256;
    }

    /**
     * The application parameter is the SHA-256 hash of the application identity
     * of the application requesting the registration
     */
    public byte[] getApplicationSha256() {
        return applicationSha256;
    }

    /**
     * The key handle obtained during registration.
     */
    public byte[] getKeyHandle() {
        return keyHandle;
    }
}