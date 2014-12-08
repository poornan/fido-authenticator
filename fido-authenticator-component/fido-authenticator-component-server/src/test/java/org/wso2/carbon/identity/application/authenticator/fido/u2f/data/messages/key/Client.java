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

package org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key;

import com.google.common.collect.ImmutableSet;
import com.google.gson.Gson;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.U2F;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.crypto.BouncyCastleCrypto;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.DeviceRegistration;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.AuthenticateRequest;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.AuthenticateResponse;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.RegisterRequest;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.RegisterResponse;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.util.ByteSink;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.util.U2fB64Encoding;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.exceptions.U2fException;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.softkey.SoftKey;

import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class Client {
    public static final byte REGISTRATION_RESERVED_BYTE_VALUE = (byte) 0x05;
    public static final ImmutableSet<String> TRUSTED_DOMAINS = ImmutableSet.of("http://example.com");
    public static final String APP_ID = "my-app";

    private final BouncyCastleCrypto crypto = new BouncyCastleCrypto();
    private final Gson gson = new Gson();
    private final SoftKey key;
    private final U2F u2f = new U2F();

    public Client(SoftKey key) {
        this.key = key;
    }

    public static byte[] encodeRegisterResponse(RawRegisterResponse rawRegisterResponse)
            throws U2fException {
        byte[] userPublicKey = rawRegisterResponse.userPublicKey;
        byte[] keyHandle = rawRegisterResponse.keyHandle;
        X509Certificate attestationCertificate = rawRegisterResponse.attestationCertificate;
        byte[] signature = rawRegisterResponse.signature;

        byte[] attestationCertificateBytes;
        try {
            attestationCertificateBytes = attestationCertificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new U2fException("Error when encoding attestation certificate.", e);
        }

        if (keyHandle.length > 255) {
            throw new U2fException("keyHandle length cannot be longer than 255 bytes!");
        }

        byte[] result = new byte[1 + userPublicKey.length + 1 + keyHandle.length
                + attestationCertificateBytes.length + signature.length];
        ByteBuffer.wrap(result)
                .put(REGISTRATION_RESERVED_BYTE_VALUE)
                .put(userPublicKey)
                .put((byte) keyHandle.length)
                .put(keyHandle)
                .put(attestationCertificateBytes)
                .put(signature);
        return result;
    }

    public static RegisterResponse encodeTokenRegistrationResponse(String clientDataJson, RawRegisterResponse registerResponse) throws U2fException {
        byte[] rawRegisterResponse = Client.encodeRegisterResponse(registerResponse);
        String rawRegisterResponseBase64 = U2fB64Encoding.encode(rawRegisterResponse);
        String clientDataBase64 = U2fB64Encoding.encode(clientDataJson.getBytes());
        return new RegisterResponse(rawRegisterResponseBase64, clientDataBase64);
    }

    public DeviceRegistration register() throws Exception {
        RegisterRequest registerRequest = u2f.startRegistration(APP_ID);

        Map<String, String> clientData = new HashMap<String, String>();
        clientData.put("typ", "navigator.id.finishEnrollment");
        clientData.put("challenge", registerRequest.getChallenge());
        clientData.put("origin", "http://example.com");
        String clientDataJson = gson.toJson(clientData);

        byte[] clientParam = crypto.hash(clientDataJson);
        byte[] appParam = crypto.hash(registerRequest.getAppId());

        RawRegisterResponse rawRegisterResponse = key.register(new org.wso2.carbon.identity.application.authenticator.fido.u2f.softkey.messages.RegisterRequest(appParam, clientParam));

        // client encodes data
        RegisterResponse tokenResponse = Client.encodeTokenRegistrationResponse(clientDataJson, rawRegisterResponse);

        return u2f.finishRegistration(registerRequest, tokenResponse, TRUSTED_DOMAINS);
    }

    public AuthenticateResponse authenticate(DeviceRegistration registeredDevice, AuthenticateRequest startedAuthentication) throws Exception {
        Map<String, String> clientData = new HashMap<String, String>();
        clientData.put("typ", "navigator.id.getAssertion");
        clientData.put("challenge", startedAuthentication.getChallenge());
        clientData.put("origin", "http://example.com");
        String clientDataJson = gson.toJson(clientData);


        byte[] clientParam = crypto.hash(clientDataJson);
        byte[] appParam = crypto.hash(startedAuthentication.getAppId());
        org.wso2.carbon.identity.application.authenticator.fido.u2f.softkey.messages.AuthenticateRequest authenticateRequest = new org.wso2.carbon.identity.application.authenticator.fido.u2f.softkey.messages.AuthenticateRequest((byte) 0x01, clientParam, appParam, U2fB64Encoding.decode(registeredDevice.getKeyHandle()));

        RawAuthenticateResponse rawAuthenticateResponse = key.authenticate(authenticateRequest);

        String clientDataBase64 = U2fB64Encoding.encode(clientDataJson.getBytes());
        byte[] authData = ByteSink.create()
                .put(rawAuthenticateResponse.getUserPresence())
                .putInt(rawAuthenticateResponse.getCounter())
                .put(rawAuthenticateResponse.getSignature())
                .toByteArray();

        return new AuthenticateResponse(
                clientDataBase64,
                U2fB64Encoding.encode(authData),
                startedAuthentication.getKeyHandle()
        );
    }
}
