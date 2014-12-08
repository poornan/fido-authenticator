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

import com.google.common.io.BaseEncoding;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

public class TestUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final BaseEncoding HEX = BaseEncoding.base16().lowerCase();
    public static final BaseEncoding BASE64 = BaseEncoding.base64();

    public static X509Certificate fetchCertificate(InputStream resourceAsStream) {
        Scanner in = new Scanner(resourceAsStream);
        String base64String = in.nextLine();
        return parseCertificate(BASE64.decode(base64String));
    }

    public static X509Certificate parseCertificate(byte[] encodedDerCertificate) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                    new ByteArrayInputStream(encodedDerCertificate));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate parseCertificate(String encodedDerCertificateHex) {
        return parseCertificate(HEX.decode(encodedDerCertificateHex));
    }

    public static PrivateKey parsePrivateKey(InputStream is) {
        String keyBytesHex = new Scanner(is).nextLine();
        return parsePrivateKey(keyBytesHex);
    }

    public static PrivateKey parsePrivateKey(String keyBytesHex) {
        try {
            KeyFactory fac = KeyFactory.getInstance("ECDSA");
            X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
            ECParameterSpec curveSpec = new ECParameterSpec(
                    curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
            ECPrivateKeySpec keySpec = new ECPrivateKeySpec(
                    new BigInteger(keyBytesHex, 16),
                    curveSpec);
            return fac.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey parsePublicKey(byte[] keyBytes) {
        try {
            X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
            ECParameterSpec curveSpec = new ECParameterSpec(curve.getCurve(), curve.getG(), curve.getN(),
                    curve.getH());
            ECPoint point = curve.getCurve().decodePoint(keyBytes);
            return KeyFactory.getInstance("ECDSA").generatePublic(
                    new ECPublicKeySpec(point, curveSpec));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
