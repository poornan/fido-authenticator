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

package org.wso2.carbon.identity.application.authenticator.fido.u2f.data;

import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.key.Client;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.softkey.SoftKey;
import org.junit.Test;

import static org.junit.Assert.*;

public class DeviceRegistrationJsonTest {

    @Test
    public void shouldSerialize() throws Exception {
        SoftKey key = new SoftKey();
        Client client = new Client(key);
        DeviceRegistration deviceRegistration = client.register();

        String json = deviceRegistration.toJson();

        DeviceRegistration deserializedDeviceRegistration = DeviceRegistration.fromJson(json);
        assertEquals(deviceRegistration.getKeyHandle(), deserializedDeviceRegistration.getKeyHandle());
        assertEquals(deviceRegistration.getPublicKey(), deserializedDeviceRegistration.getPublicKey());
        assertEquals(deviceRegistration.getCounter(), deserializedDeviceRegistration.getCounter());
    }

}