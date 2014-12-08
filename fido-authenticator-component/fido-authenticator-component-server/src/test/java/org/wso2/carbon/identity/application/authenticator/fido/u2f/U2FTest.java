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

package org.wso2.carbon.identity.application.authenticator.fido.u2f;

import com.google.common.collect.ImmutableSet;
import org.junit.Before;
import org.junit.Test;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.testdata.AcmeKey;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.testdata.TestVectors;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.DeviceRegistration;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.AuthenticateRequest;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.AuthenticateResponse;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.RegisterRequest;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.RegisterResponse;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.exceptions.U2fException;

import java.util.HashSet;
import java.util.Set;

import static org.mockito.MockitoAnnotations.initMocks;
import static org.wso2.carbon.identity.application.authenticator.fido.u2f.testdata.GnubbyKey.ATTESTATION_CERTIFICATE;
import static org.wso2.carbon.identity.application.authenticator.fido.u2f.testdata.TestVectors.*;
import static org.junit.Assert.*;

public class U2FTest {
    final HashSet<String> allowedOrigins = new HashSet<String>();
    U2F u2f = new U2F();

    @Before
    public void setup() throws Exception {
        initMocks(this);
        allowedOrigins.add("http://example.com");
    }

    @Test
    public void finishRegistration() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);

        u2f.finishRegistration(registerRequest, new RegisterResponse(TestVectors.REGISTRATION_DATA_BASE64, CLIENT_DATA_REGISTRATION_BASE64), TRUSTED_DOMAINS);
    }

    @Test
    public void finishRegistration2() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);

        DeviceRegistration deviceRegistration = u2f.finishRegistration(registerRequest, new RegisterResponse(AcmeKey.REGISTRATION_DATA_BASE64, AcmeKey.CLIENT_DATA_BASE64), TRUSTED_DOMAINS);

        assertEquals(new DeviceRegistration(AcmeKey.KEY_HANDLE, AcmeKey.USER_PUBLIC_KEY_B64, AcmeKey.ATTESTATION_CERTIFICATE, 0), deviceRegistration);
    }

    @Test
    public void finishAuthentication() throws Exception {
        AuthenticateRequest authenticateRequest = new AuthenticateRequest(SERVER_CHALLENGE_SIGN_BASE64, APP_ID_SIGN, KEY_HANDLE_BASE64);

        AuthenticateResponse tokenResponse = new AuthenticateResponse(CLIENT_DATA_AUTHENTICATE_BASE64,
                SIGN_RESPONSE_DATA_BASE64, SERVER_CHALLENGE_SIGN_BASE64);

        u2f.finishAuthentication(authenticateRequest, tokenResponse, new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0), allowedOrigins);
    }


    @Test(expected = U2fException.class)
    public void finishAuthentication_badOrigin() throws Exception {
        Set<String> allowedOrigins = ImmutableSet.of("some-other-domain.com");
        AuthenticateRequest authentication = new AuthenticateRequest(SERVER_CHALLENGE_SIGN_BASE64,
                APP_ID_SIGN, KEY_HANDLE_BASE64);

        AuthenticateResponse response = new AuthenticateResponse(CLIENT_DATA_AUTHENTICATE_BASE64,
                SIGN_RESPONSE_DATA_BASE64, SERVER_CHALLENGE_SIGN_BASE64);

        u2f.finishAuthentication(authentication, response, new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0), allowedOrigins);
    }
}
