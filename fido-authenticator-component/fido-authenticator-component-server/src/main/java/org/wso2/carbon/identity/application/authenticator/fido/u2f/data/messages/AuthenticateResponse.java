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

import com.google.common.base.Objects;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.json.JsonObject;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.json.Persistable;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.exceptions.U2fException;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public class AuthenticateResponse extends JsonObject implements Persistable {
    private static final int MAX_SIZE = 20000;

    /* base64(client data) */
    private final String clientData;

    /* base64(raw response from U2F device) */
    private final String signatureData;

    /* keyHandle originally passed */
    private final String keyHandle;

    private AuthenticateResponse() {
        clientData = null;
        signatureData = null;
        keyHandle = null; // Gson requires a no-args constructor.
    }

    public AuthenticateResponse(String clientData, String signatureData, String keyHandle) {
        this.clientData = checkNotNull(clientData);
        this.signatureData = checkNotNull(signatureData);
        this.keyHandle = checkNotNull(keyHandle);
    }

    public ClientData getClientData() throws U2fException {
        return new ClientData(clientData);
    }

    public String getSignatureData() {
        return signatureData;
    }

    public String getKeyHandle() {
        return keyHandle;
    }

    public String getRequestId() throws U2fException {
        return getClientData().getChallenge();
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(clientData, signatureData, keyHandle);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AuthenticateResponse))
            return false;
        AuthenticateResponse other = (AuthenticateResponse) obj;
        return Objects.equal(clientData, other.clientData)
                && Objects.equal(keyHandle, other.keyHandle)
                && Objects.equal(signatureData, other.signatureData);
    }

    public static AuthenticateResponse fromJson(String json) {
        checkArgument(json.length() < MAX_SIZE, "Client response bigger than allowed");
        return GSON.fromJson(json, AuthenticateResponse.class);
    }
}
