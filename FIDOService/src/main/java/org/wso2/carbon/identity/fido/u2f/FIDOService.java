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

package org.wso2.carbon.identity.fido.u2f;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.yubico.u2f.U2F;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.AuthenticateRequestData;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.RegisterRequestData;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.exceptions.U2fException;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.wso2.carbon.authenticator.proxy.AuthenticationAdminStub;
import org.wso2.carbon.um.ws.api.WSRealmBuilder;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by ananthaneshan on 12/11/14.
 */
public class FIDOService {
	private final Map<String, String> requestStorage = new HashMap<String, String>();
	private final Multimap<String, String> userStorage = ArrayListMultimap.create();
	private final U2F u2f = new U2F();

	private Iterable<DeviceRegistration> getRegistrations(String username, String appID) {
		List<DeviceRegistration> registrations = new ArrayList<DeviceRegistration>();
		registrations.add(
				DeviceRegistration.fromJson(getDeviceRegistration(username, appID)));
		return registrations;
	}

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

	/**
	 * Initiate FIDO authentication.
	 *
	 * @param username username.
	 * @param appID    Application host address.
	 * @return AuthenticateRequestData.
	 * @throws U2fException
	 */
	public String startAuthentication(String username, String appID) throws U2fException {
		AuthenticateRequestData authenticateRequestData =
				u2f.startAuthentication(appID, getRegistrations(username, appID));
		requestStorage
				.put(authenticateRequestData.getRequestId(), authenticateRequestData.toJson());
		return authenticateRequestData.toJson();
	}

	/**
	 * Finish FIDO authentication.
	 *
	 * @param response tokenResponse
	 * @param username username
	 * @throws U2fException
	 */
	public void finishAuthentication(String response,
	                                  String username, String appID) throws U2fException {
		AuthenticateResponse authenticateResponse = AuthenticateResponse.fromJson(response);
		AuthenticateRequestData authenticateRequest = AuthenticateRequestData
				.fromJson(requestStorage.get(authenticateResponse.getRequestId()));
		requestStorage.remove(authenticateResponse.getRequestId());
		u2f.finishAuthentication(authenticateRequest, authenticateResponse,
		                         getRegistrations(username, appID));
	}

	/**
	 * Initiate FIDO Device Registration.
	 * @param username Username.
	 * @param appID Application host address.
	 * @return String RegisterRequestData.
	 */
	public String startRegistration(String username, String appID) {
		RegisterRequestData registerRequestData =
				u2f.startRegistration(appID, getRegistrations(username, appID));
		requestStorage.put(registerRequestData.getRequestId(), registerRequestData.toJson());
		return registerRequestData.toJson();
	}

	/**
	 * Finish FIDO Device registration
	 * @param response tokenResponse.
	 * @param username username.
	 * @return success or failure.
	 * @throws U2fException
	 */
	public String finishRegistration(String response, String username, String appID)
			throws U2fException {
		RegisterResponse registerResponse = RegisterResponse.fromJson(response);
		RegisterRequestData registerRequestData =
				RegisterRequestData.fromJson(requestStorage.get(registerResponse.getRequestId()));
		DeviceRegistration registration =
				u2f.finishRegistration(registerRequestData, registerResponse);
		addRegistration(username, registration, appID);

		requestStorage.remove(registerResponse.getRequestId());

		return "SUCCESS";
	}

	private void addRegistration(String username, DeviceRegistration registration) {
		userStorage.put(username, registration.toJson());
	}

	private void addRegistration(String username, DeviceRegistration registration, String appID) {
		//U2FUser.createUser(username, registration.toJson(),appID);
		addRegistration(username,registration);
	}

}
