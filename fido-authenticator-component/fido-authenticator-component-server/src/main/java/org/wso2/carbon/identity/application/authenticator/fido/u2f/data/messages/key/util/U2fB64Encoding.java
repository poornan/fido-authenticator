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

package org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.util;

import com.google.common.io.BaseEncoding;

public class U2fB64Encoding {
    private final static BaseEncoding U2F_ENCODING = BaseEncoding.base64Url().omitPadding();

    public static String encode(byte[] decoded) {
        return U2F_ENCODING.encode(decoded);
    }

    public static byte[] decode(String encoded) {
	    return U2F_ENCODING.decode(encoded);
    }
}
