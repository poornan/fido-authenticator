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

package org.wso2.carbon.identity.application.authenticator.fido.u2f.softkey;

import org.junit.Before;
import org.junit.Test;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2F;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.DeviceRegistration;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.AuthenticateRequest;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.AuthenticateResponse;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.ClientData;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.Client;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.util.U2fB64Encoding;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.exceptions.U2fException;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.testdata.AcmeKey;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.testdata.GnubbyKey;

import java.security.KeyPair;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;

public class SoftKeyTest {

    public static final String APP_ID = "my-app";

    private U2F u2f;

    @Before
    public void setup() {
        u2f = new U2F();
    }

    @Test
    public void shouldRegister() throws Exception {
        Client client = createClient();
        client.register();
    }

    @Test
    public void shouldAuthenticate() throws Exception {
        Client client = createClient();
        DeviceRegistration registeredDevice = client.register();
        authenticateUsing(client, registeredDevice);
    }

    // Tests FIDO Security Measure [SM-3]
    @Test
    public void shouldProvideAttestationCert() throws Exception {
        Client client = createClient();
        DeviceRegistration deviceRegistration = client.register();
        assertEquals("CN=Gnubby Pilot", deviceRegistration.getAttestationCertificate().getIssuerDN().getName());
    }

    @Test(expected = U2fException.class)
    public void shouldVerifyAttestationCert() throws Exception {
        SoftKey key = new SoftKey(
                new HashMap<String, KeyPair>(),
                0,
                AcmeKey.ATTESTATION_CERTIFICATE,
                GnubbyKey.ATTESTATION_CERTIFICATE_PRIVATE_KEY
        );
        new Client(key).register();
    }

    // Tests FIDO Security Measure [SM-15]
    @Test(expected = U2fException.class)
    public void shouldProtectAgainstClonedDevices() throws Exception {
        SoftKey key = new SoftKey();
        Client client = new Client(key);

        SoftKey clonedKey = key.clone();
        Client clientUsingClone = new Client(clonedKey);

        DeviceRegistration registeredDevice = client.register();

        authenticateUsing(client, registeredDevice);
        authenticateUsing(clientUsingClone, registeredDevice);
    }

    @Test(expected = U2fException.class)
    public void shouldVerifyKeySignatures() throws Exception {

        Client client = createClient();

        DeviceRegistration registeredDevice = client.register();

        AuthenticateRequest authenticateRequest = u2f.startAuthentication(APP_ID, registeredDevice);
        AuthenticateResponse originalResponse = client.authenticate(registeredDevice, authenticateRequest);
        AuthenticateResponse tamperedResponse = new AuthenticateResponse(
                tamperChallenge(originalResponse.getClientData()),
                originalResponse.getSignatureData(),
                originalResponse.getKeyHandle()
        );
        u2f.finishAuthentication(authenticateRequest, tamperedResponse, registeredDevice);
    }

    private String tamperChallenge(ClientData clientData) {
        byte[] rawClientData = clientData.asJson().getBytes();
        rawClientData[50] += 1;
        return U2fB64Encoding.encode(rawClientData);
    }

    private Client createClient() {
        SoftKey key = new SoftKey();
        return new Client(key);
    }

    private void authenticateUsing(Client client, DeviceRegistration registeredDevice) throws Exception {
        AuthenticateRequest authenticateRequest = u2f.startAuthentication(APP_ID, registeredDevice);
        AuthenticateResponse authenticateResponse = client.authenticate(registeredDevice, authenticateRequest);
        u2f.finishAuthentication(authenticateRequest, authenticateResponse, registeredDevice);
    }
}
