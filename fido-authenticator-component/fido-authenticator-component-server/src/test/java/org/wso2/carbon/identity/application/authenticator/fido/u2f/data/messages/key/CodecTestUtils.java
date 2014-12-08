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

import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.util.ByteSink;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.exceptions.U2fException;

import java.security.cert.CertificateEncodingException;

public class CodecTestUtils {
    public static byte[] encodeAuthenticateResponse(RawAuthenticateResponse rawAuthenticateResponse) {
        return ByteSink.create()
                .put(rawAuthenticateResponse.getUserPresence())
                .putInt(rawAuthenticateResponse.getCounter())
                .put(rawAuthenticateResponse.getSignature())
                .toByteArray();
    }

    public static byte[] encodeRegisterResponse(RawRegisterResponse rawRegisterResponse) throws U2fException {
        byte[] keyHandle = rawRegisterResponse.keyHandle;
        if (keyHandle.length > 255) {
            throw new U2fException("keyHandle length cannot be longer than 255 bytes!");
        }

        try {
            return ByteSink.create()
                    .put(RawRegisterResponse.REGISTRATION_RESERVED_BYTE_VALUE)
                    .put(rawRegisterResponse.userPublicKey)
                    .put((byte) keyHandle.length)
                    .put(keyHandle)
                    .put(rawRegisterResponse.attestationCertificate.getEncoded())
                    .put(rawRegisterResponse.signature)
                    .toByteArray();
        } catch (CertificateEncodingException e) {
            throw new U2fException("Error when encoding attestation certificate.", e);
        }
    }
}
