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

import com.google.common.collect.ImmutableSet;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.DeviceRegistration;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.AuthenticateRequest;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.AuthenticateResponse;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.RegisterRequest;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.RegisterResponse;
import org.junit.Ignore;

import java.util.Scanner;

@Ignore("Includes manual steps")
public class SystemTest {

    public static final ImmutableSet<String> TRUSTED_DOMAINS = ImmutableSet.of("http://example.com");
    public static final String APP_ID = "my-app";
    private static Scanner scan = new Scanner(System.in);
    private static final U2F u2f = new U2F();

    /*
      For manual testing with physical keys. Can e.g. be combined with these libu2f-host commands:

        u2f-host -aregister -o http://example.com
        u2f-host -aauthenticate -o http://example.com
     */
    public static void main(String... args) throws Exception {
        String startedRegistration = u2f.startRegistration(APP_ID).toJson();
        System.out.println("Registration data:");
        System.out.println(startedRegistration);

        System.out.println();
        System.out.println("Enter token response:");

        String json = scan.nextLine();
        RegisterResponse registerResponse = RegisterResponse.fromJson(json);
        registerResponse.getClientData().getChallenge();
        DeviceRegistration deviceRegistration = u2f.finishRegistration(
                RegisterRequest.fromJson(startedRegistration),
                registerResponse,
                TRUSTED_DOMAINS
        );

        System.out.println(deviceRegistration);

        String startedAuthentication = u2f.startAuthentication(APP_ID, deviceRegistration).toJson();
        System.out.println("Authentication data:");
        System.out.println(startedAuthentication);

        System.out.println();
        System.out.println("Enter token response:");

        u2f.finishAuthentication(
                AuthenticateRequest.fromJson(startedAuthentication),
                AuthenticateResponse.fromJson(scan.nextLine()),
                deviceRegistration,
                TRUSTED_DOMAINS
        );
        System.out.println("Device counter: " + deviceRegistration.getCounter());
    }
}
