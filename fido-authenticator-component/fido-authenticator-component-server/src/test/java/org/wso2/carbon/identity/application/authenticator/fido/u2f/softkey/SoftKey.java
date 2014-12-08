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

import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.RawAuthenticateResponse;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.RawRegisterResponse;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.util.ByteInputStream;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.softkey.messages.AuthenticateRequest;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.softkey.messages.RegisterRequest;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.testdata.GnubbyKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.base.Preconditions.checkNotNull;

public final class SoftKey implements Cloneable {

    private final X509Certificate attestationCertificate;
    private final PrivateKey certificatePrivateKey;
    private final Map<String, KeyPair> dataStore;
    private int deviceCounter = 0;

    public SoftKey() {
        this(
                new HashMap<String, KeyPair>(),
                0,
                GnubbyKey.ATTESTATION_CERTIFICATE,
                GnubbyKey.ATTESTATION_CERTIFICATE_PRIVATE_KEY
        );
    }

    public SoftKey(
            Map<String, KeyPair> dataStore,
            int deviceCounter,
            X509Certificate attestationCertificate,
            PrivateKey certificatePrivateKey
    ) {
        this.dataStore = dataStore;
        this.deviceCounter = deviceCounter;
        this.attestationCertificate = attestationCertificate;
        this.certificatePrivateKey = certificatePrivateKey;
    }

    @Override
    public SoftKey clone() {
        return new SoftKey(
                this.dataStore,
                this.deviceCounter,
                this.attestationCertificate,
                this.certificatePrivateKey
        );
    }

    public RawRegisterResponse register(RegisterRequest registerRequest) throws Exception {

        byte[] applicationSha256 = registerRequest.getApplicationSha256();
        byte[] challengeSha256 = registerRequest.getChallengeSha256();

        // generate ECC key
        SecureRandom random = new SecureRandom();
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA");
        g.initialize(ecSpec, random);
        KeyPair keyPair = g.generateKeyPair();

        byte[] keyHandle = new byte[64];
        random.nextBytes(keyHandle);
        dataStore.put(new String(keyHandle), keyPair);

        byte[] userPublicKey = stripMetaData(keyPair.getPublic().getEncoded());

        byte[] signedData = RawRegisterResponse.packBytesToSign(applicationSha256, challengeSha256,
                keyHandle, userPublicKey);

        byte[] signature = sign(signedData, certificatePrivateKey);

        return new RawRegisterResponse(userPublicKey, keyHandle, attestationCertificate, signature);
    }

    private byte[] stripMetaData(byte[] a) {
        ByteInputStream bis = new ByteInputStream(a);
        bis.read(3);
        bis.read(bis.readUnsigned() + 1);
        int keyLength = bis.readUnsigned();
        bis.read(1);
        return bis.read(keyLength - 1);
    }

    public RawAuthenticateResponse authenticate(AuthenticateRequest authenticateRequest) throws Exception {

        byte[] applicationSha256 = authenticateRequest.getApplicationSha256();
        byte[] challengeSha256 = authenticateRequest.getChallengeSha256();
        byte[] keyHandle = authenticateRequest.getKeyHandle();

        KeyPair keyPair = checkNotNull(dataStore.get(new String(keyHandle)));
        int counter = ++deviceCounter;
        byte[] signedData = RawAuthenticateResponse.packBytesToSign(applicationSha256, RawAuthenticateResponse.USER_PRESENT_FLAG,
                counter, challengeSha256);

        byte[] signature = sign(signedData, keyPair.getPrivate());

        return new RawAuthenticateResponse(RawAuthenticateResponse.USER_PRESENT_FLAG, counter, signature);
    }

    private byte[] sign(byte[] signedData, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(signedData);
        return signature.sign();
    }
}