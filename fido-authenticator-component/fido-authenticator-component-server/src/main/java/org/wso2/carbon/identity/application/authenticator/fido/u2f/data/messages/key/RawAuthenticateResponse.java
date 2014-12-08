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

import com.google.common.base.Objects;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.crypto.BouncyCastleCrypto;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.crypto.Crypto;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.util.ByteInputStream;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.util.ByteSink;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.util.U2fB64Encoding;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.exceptions.U2fException;

import java.util.Arrays;

/**
 * The authenticate response produced by the token/key, which is transformed by the client into an AuthenticateResponse
 * and sent to the server.
 */
public class RawAuthenticateResponse {
    public static final byte USER_PRESENT_FLAG = 0x01;

    private final byte userPresence;
    private final int counter;
    private final byte[] signature;
    private final Crypto crypto;

    public RawAuthenticateResponse(byte userPresence, int counter, byte[] signature) {
        this(userPresence, counter, signature, new BouncyCastleCrypto());
    }

    public RawAuthenticateResponse(byte userPresence, int counter, byte[] signature, Crypto crypto) {
        this.userPresence = userPresence;
        this.counter = counter;
        this.signature = signature;
        this.crypto = crypto;
    }

    public static RawAuthenticateResponse fromBase64(String rawDataBase64, Crypto crypto) {
        ByteInputStream bytes = new ByteInputStream(U2fB64Encoding.decode(rawDataBase64));
        return new RawAuthenticateResponse(
                bytes.readSigned(),
                bytes.readInteger(),
                bytes.readAll(),
                crypto
        );
    }

    public void checkSignature(String appId, String clientData, byte[] publicKey) throws U2fException {
        byte[] signedBytes = packBytesToSign(
                crypto.hash(appId),
                userPresence,
                counter,
                crypto.hash(clientData)
        );
        crypto.checkSignature(
                crypto.decodePublicKey(publicKey),
                signedBytes,
                signature
        );
    }

    public static byte[] packBytesToSign(byte[] appIdHash, byte userPresence, int counter, byte[] challengeHash) {
        return ByteSink.create()
                .put(appIdHash)
                .put(userPresence)
                .putInt(counter)
                .put(challengeHash)
                .toByteArray();
    }

    /**
     * Bit 0 is set to 1, which means that user presence was verified. (This
     * version of the protocol doesn't specify a way to request authentication
     * responses without requiring user presence.) A different value of bit 0, as
     * well as bits 1 through 7, are reserved for future use. The values of bit 1
     * through 7 SHOULD be 0
     */
    public byte getUserPresence() {
        return userPresence;
    }

    /**
     * This is the big-endian representation of a counter value that the U2F device
     * increments every time it performs an authentication operation.
     */
    public int getCounter() {
        return counter;
    }

    /**
     * This is a ECDSA signature (on P-256)
     */
    public byte[] getSignature() {
        return signature;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(userPresence, counter, signature);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof RawAuthenticateResponse))
            return false;
        RawAuthenticateResponse other = (RawAuthenticateResponse) obj;
        return Objects.equal(counter, other.counter)
                && Arrays.equals(signature, signature)
                && Objects.equal(userPresence, other.userPresence);
    }

    public void checkUserPresence() throws U2fException {
        if (userPresence != USER_PRESENT_FLAG) {
            throw new U2fException("User presence invalid during authentication");
        }
    }
}
