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

package org.wso2.carbon.identity.application.authenticator.fido.u2f.codec;

import org.wso2.carbon.identity.application.authenticator.fido.u2f.crypto.BouncyCastleCrypto;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.crypto.Crypto;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.CodecTestUtils;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.RawAuthenticateResponse;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.RawRegisterResponse;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.testdata.TestVectors;
import org.junit.Test;

import static org.wso2.carbon.identity.application.authenticator.fido.u2f.testdata.GnubbyKey.ATTESTATION_CERTIFICATE;
import static org.wso2.carbon.identity.application.authenticator.fido.u2f.testdata.TestVectors.*;
import static org.junit.Assert.*;

public class SerialCodecTest {

    private static final Crypto crypto = new BouncyCastleCrypto();

    @Test
    public void testEncodeRegisterResponse() throws Exception {
        RawRegisterResponse rawRegisterResponse = new RawRegisterResponse(USER_PUBLIC_KEY_REGISTER_HEX,
                KEY_HANDLE, ATTESTATION_CERTIFICATE, SIGNATURE_REGISTER);

        byte[] encodedBytes = CodecTestUtils.encodeRegisterResponse(rawRegisterResponse);

        assertArrayEquals(TestVectors.REGISTRATION_RESPONSE_DATA, encodedBytes);
    }

    @Test
    public void testEncodeRegisterSignedBytes() throws Exception {
        byte[] encodedBytes = RawRegisterResponse.packBytesToSign(APP_ID_ENROLL_SHA256,
                CLIENT_DATA_ENROLL_SHA256, KEY_HANDLE, USER_PUBLIC_KEY_REGISTER_HEX);

        assertArrayEquals(EXPECTED_REGISTER_SIGNED_BYTES, encodedBytes);
    }

    @Test
    public void testDecodeRegisterResponse() throws Exception {
        RawRegisterResponse rawRegisterResponse =
                RawRegisterResponse.fromBase64(TestVectors.REGISTRATION_DATA_BASE64, crypto);

        assertEquals(new RawRegisterResponse(USER_PUBLIC_KEY_REGISTER_HEX,
                KEY_HANDLE, ATTESTATION_CERTIFICATE, SIGNATURE_REGISTER), rawRegisterResponse);
    }

    @Test
    public void testEncodeAuthenticateResponse() throws Exception {
        RawAuthenticateResponse rawAuthenticateResponse = new RawAuthenticateResponse(
                RawAuthenticateResponse.USER_PRESENT_FLAG, COUNTER_VALUE, SIGNATURE_AUTHENTICATE);

        byte[] encodedBytes = CodecTestUtils.encodeAuthenticateResponse(rawAuthenticateResponse);

        assertArrayEquals(AUTHENTICATE_RESPONSE_DATA, encodedBytes);
    }

    @Test
    public void testDecodeAuthenticateResponse() throws Exception {
        RawAuthenticateResponse rawAuthenticateResponse =
                RawAuthenticateResponse.fromBase64(SIGN_RESPONSE_DATA_BASE64, crypto);

        assertEquals(new RawAuthenticateResponse(RawAuthenticateResponse.USER_PRESENT_FLAG, COUNTER_VALUE,
                SIGNATURE_AUTHENTICATE), rawAuthenticateResponse);
    }

    @Test
    public void testEncodeAuthenticateSignedBytes() throws Exception {
        byte[] encodedBytes = RawAuthenticateResponse.packBytesToSign(APP_ID_SIGN_SHA256,
                RawAuthenticateResponse.USER_PRESENT_FLAG, COUNTER_VALUE, CLIENT_DATA_AUTHENTICATE_SHA256);

        assertArrayEquals(EXPECTED_AUTHENTICATE_SIGNED_BYTES, encodedBytes);
    }
}
