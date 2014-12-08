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
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2F;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.crypto.ChallengeGenerator;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.DeviceRegistration;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.json.JsonObject;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.json.Persistable;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.exceptions.NoDevicesRegisteredException;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.exceptions.U2fException;

import java.util.List;

public class AuthenticateRequestData extends JsonObject implements Persistable {

    private static final long serialVersionUID = 35378338769078256L;

    private final List<AuthenticateRequest> authenticateRequests;

    public AuthenticateRequestData(String appId, Iterable<? extends DeviceRegistration> devices, U2F u2f, ChallengeGenerator challengeGenerator) throws U2fException {
        if(Iterables.isEmpty(devices)) {
            throw new NoDevicesRegisteredException();
        }
        ImmutableList.Builder<AuthenticateRequest> requestBuilder = ImmutableList.builder();
        byte[] challenge = challengeGenerator.generateChallenge();
        for(DeviceRegistration device : devices) {
            requestBuilder.add(u2f.startAuthentication(appId, device, challenge));
        }
        this.authenticateRequests = requestBuilder.build();
    }

    public List<AuthenticateRequest> getAuthenticateRequests() {
        return ImmutableList.copyOf(authenticateRequests);
    }

    public AuthenticateRequest getAuthenticateRequest(AuthenticateResponse response) throws U2fException {
        if(!Objects.equal(getRequestId(), response.getRequestId())) {
            throw new U2fException("Wrong request for response data");
        }
        for(AuthenticateRequest request : authenticateRequests) {
            if(Objects.equal(request.getKeyHandle(), response.getKeyHandle())) {
                return request;
            }
        }
        throw new U2fException("Unknown keyHandle");
    }

    public String getRequestId() {
        return Iterables.getFirst(authenticateRequests, null).getChallenge();
    }

    public static AuthenticateRequestData fromJson(String json) {
        return GSON.fromJson(json, AuthenticateRequestData.class);
    }
}
