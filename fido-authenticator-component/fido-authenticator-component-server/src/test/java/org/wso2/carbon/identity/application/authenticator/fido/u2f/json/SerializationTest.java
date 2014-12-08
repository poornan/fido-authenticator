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

package org.wso2.carbon.identity.application.authenticator.fido.u2f.json;

import com.google.gson.Gson;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.AuthenticateResponse;
import org.junit.Test;

import static com.google.common.base.Preconditions.checkNotNull;

public class SerializationTest {

    Gson gson = new Gson();

    @Test
    public void tokenAuthenticationResponse() throws Exception {
        String response = "{ \"signatureData\": \"AQAAAAUwRAIgB1Q5iWRzC4zkZE2eIqoJZsXXCcg_6FVbZk-sMtLXcz4CIHxWaQsjLc-vD_kZLeg-p7IQ1HAmAFgiTk_dq6Q6iGcu\", \"clientData\": \"eyAiY2hhbGxlbmdlIjogIkQ1VG1CaEQzbTg0c3BRd3FfVm81VWZFSm8xV2JXTnBnRHdvZ0dWcmtBd00iLCAib3JpZ2luIjogImh0dHA6XC9cL2V4YW1wbGUuY29tIiwgInR5cCI6ICJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiB9\", \"keyHandle\": \"fSgg0l0JefF0GAFGAi9cOf5iL1nnzSswSmgpathyRRhsZ8QTzxPH1WAu8TqTbadfnNHOnINoF0UkMjKrxKVZLA\" }";
        AuthenticateResponse ar = gson.fromJson(response, AuthenticateResponse.class);
        checkNotNull(ar.getKeyHandle());
        checkNotNull(ar.getClientData());
        checkNotNull(ar.getSignatureData());

    }
}
