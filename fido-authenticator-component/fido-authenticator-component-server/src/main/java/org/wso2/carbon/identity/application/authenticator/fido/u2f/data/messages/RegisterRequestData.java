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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2F;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.crypto.ChallengeGenerator;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.DeviceRegistration;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.json.JsonObject;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.json.Persistable;

import java.util.List;

public class RegisterRequestData extends JsonObject implements Persistable {

    private static final long serialVersionUID = 60855174227617680L;

    private final List<AuthenticateRequest> authenticateRequests;
    private final List<RegisterRequest> registerRequests;

    public RegisterRequestData(String appId, Iterable<? extends DeviceRegistration> devices, U2F u2f, ChallengeGenerator challengeGenerator) {
        ImmutableList.Builder<AuthenticateRequest> authenticateRequests = ImmutableList.builder();
        for(DeviceRegistration device : devices) {
            authenticateRequests.add(u2f.startAuthentication(appId, device));
        }

        this.authenticateRequests = authenticateRequests.build();
        this.registerRequests = ImmutableList.of(u2f.startRegistration(appId, challengeGenerator.generateChallenge()));
    }

    private RegisterRequestData() {
        authenticateRequests = null;
        registerRequests = null; // Gson requires a no-args constructor.
    }

    public List<AuthenticateRequest> getAuthenticateRequests() {
        return ImmutableList.copyOf(authenticateRequests);
    }

    public List<RegisterRequest> getRegisterRequests() {
        return ImmutableList.copyOf(registerRequests);
    }

    public RegisterRequest getRegisterRequest(RegisterResponse response) {
        return Iterables.getOnlyElement(registerRequests);
    }

    public String getRequestId()  {
        return Iterables.getOnlyElement(registerRequests).getChallenge();
    }

    public static RegisterRequestData fromJson(String json) {
        return GSON.fromJson(json, RegisterRequestData.class);
    }
}
