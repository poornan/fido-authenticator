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

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.authenticator.proxy.AuthenticationAdminStub;
import org.wso2.carbon.um.ws.api.WSRealmBuilder;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;

public class U2FUser {

	private static Log log = LogFactory.getLog(U2FUser.class);

	/**
	 * @param username
	 * @param registration
	 * @param appID
	 * @return
	 */
	/*public static String createUser(String username, String registration, String appID) {

		String status = "";
		final String SERVER_URL = "https://localhost:9443/services/";
		AuthenticationAdminStub authstub;
		ConfigurationContext configContext;
		String cookie;

		System.setProperty("javax.net.ssl.trustStore", "wso2carbon.jks");
		System.setProperty("javax.net.ssl.trustStorePassword", "wso2carbon");

		try {
			configContext = ConfigurationContextFactory.createConfigurationContextFromFileSystem(
					"repo", "repo/conf/client.axis2.xml");
			authstub = new AuthenticationAdminStub(configContext, SERVER_URL
			                                                      + "AuthenticationAdmin");

			// Authenticates as a user having rights to add users.
			if (authstub.login("admin", "admin", appID)) {
				cookie = (String) authstub._getServiceClient().getServiceContext().getProperty(
						HTTPConstants.COOKIE_STRING);

				UserRealm realm = WSRealmBuilder.createWSRealm(SERVER_URL, cookie, configContext);
				UserStoreManager storeManager = realm.getUserStoreManager();

				if (!storeManager.isExistingRole(appID)) {

					storeManager.addRole(appID, null, null);

				} else {
					throw new U2fException("Can not create user role");
				}

				if (!storeManager.isExistingUser(username)) {

					Map<String, String> claims = new HashMap<String, String>();

					claims.put("http://wso2.org/claims/registration", registration);

					storeManager.addUser(username, "password", new String[] { appID, "loginOnly" },
					                     claims, null);

					status = "SUCCESS";
				} else {
					throw new U2fException("User already exists");
				}

			}

		} catch (Exception e) {
			log.error("Could not add user to user store");
		}
		return status;
	}*/

	public static String getDeviceRegistration(String username, String appID) {
		String deviceRegistration = "";
		final String SERVER_URL = "https://localhost:9443/services/";
		AuthenticationAdminStub authstub;
		ConfigurationContext configContext;
		String cookie;

		System.setProperty("javax.net.ssl.trustStore", "wso2carbon.jks");
		System.setProperty("javax.net.ssl.trustStorePassword", "wso2carbon");

		try {
			configContext = ConfigurationContextFactory.createConfigurationContextFromFileSystem(
					"repo", "repo/conf/client.axis2.xml");
			authstub = new AuthenticationAdminStub(configContext, SERVER_URL
			                                                      + "AuthenticationAdmin");

			// Authenticates as a user having rights to add users.
			if (authstub.login("admin", "admin", appID)) {
				cookie = (String) authstub._getServiceClient().getServiceContext().getProperty(
						HTTPConstants.COOKIE_STRING);

				UserRealm realm = WSRealmBuilder.createWSRealm(SERVER_URL, cookie, configContext);
				UserStoreManager storeManager = realm.getUserStoreManager();

				if (storeManager.isExistingUser(username)) {
					deviceRegistration = storeManager
							.getUserClaimValue(username, "http://wso2.org/claims/registration",
							                   null);
				} else {
					System.out.println("The user you are trying is not in the system");
				}

			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return deviceRegistration;
	}

}
