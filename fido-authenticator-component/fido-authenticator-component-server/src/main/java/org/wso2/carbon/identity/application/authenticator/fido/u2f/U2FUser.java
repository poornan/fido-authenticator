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

import java.util.HashMap;
import java.util.Map;

public class U2FUser {

	private static Log log = LogFactory.getLog(U2FUser.class);
/*
	*//**
	 * create user in user store.
	 *
	 * @param userName     user name.
	 * @param registration device registration details.
	 * @return status.
	 *//*
	public static String createUser(String userName, String registration) {
		String status = "";
		try {
			SCIMUtils.loadConfiguration();
			SCIMUtils.setKeyStore();
			SCIMClient scimClient = new SCIMClient();
			User scimUser = scimClient.createUser();
			scimUser.setUserName(userName);
			//scimUser.setPassword(password);

			Map<String, Object> subs = new HashMap<String, Object>();
			subs.put("registration", registration);
			MultiValuedAttribute fidoRegistration = new MultiValuedAttribute("entitlements");

			fidoRegistration.setComplexValue(subs);
			fidoRegistration = (MultiValuedAttribute) DefaultAttributeFactory.createAttribute(
					SCIMSchemaDefinitions.ENTITLEMENTS, fidoRegistration);
			scimUser.setAttribute(fidoRegistration);

			String encodedUser = scimClient.encodeSCIMObject(scimUser, SCIMConstants.JSON);
			System.out.println("");
			System.out.println(
					"*//******User to be created in json format: " + encodedUser + "******//*");
			System.out.println("");

			PostMethod postMethod = new PostMethod(SCIMUtils.userEndpointURL);
			//add authorization header
			String authHeader = SCIMUtils.getAuthorizationHeader();
			postMethod.addRequestHeader(SCIMConstants.AUTHORIZATION_HEADER, authHeader);
			//create request entity with the payload.
			RequestEntity requestEntity =
					new StringRequestEntity(encodedUser, SCIMUtils.CONTENT_TYPE, null);
			postMethod.setRequestEntity(requestEntity);

			//create http client
			HttpClient httpClient = new HttpClient();
			//send the request
			int responseStatus = httpClient.executeMethod(postMethod);

			String response = postMethod.getResponseBodyAsString();

			System.out.println("");
			System.out.println("");
			System.out.println("*//******SCIM user creation response status: " + responseStatus);
			System.out.println("SCIM user creation response data: " + response + "******//*");
			System.out.println("");
			status = response;
		} catch (IOException e) {
			log.error("IOException");
		} catch (CharonException e1) {
			log.error("CharonException");
		}
		return status;
	}*/

	/*public static String getDeviceRegistrationAlternative(String userName) {
		String deviceRegistration = "";
		try {
			//create http client
			HttpClient httpFilterUserClient = new HttpClient();
			//create get method for filtering
			GetMethod getMethod = new GetMethod(SCIMUtils.userEndpointURL);
			//add authorization header
			String authHeader = SCIMUtils.getAuthorizationHeader();
			getMethod.addRequestHeader(SCIMConstants.AUTHORIZATION_HEADER, authHeader);
			//get corresponding userIds
			String filter = SCIMUtils.USER_FILTER + userName;
			getMethod.setQueryString(filter);
			int responseCode = httpFilterUserClient.executeMethod(getMethod);
			String response = getMethod.getResponseBodyAsString();

			SCIMClient scimClient = new SCIMClient();
			//check for success of the response
			if (scimClient.evaluateResponseStatus(responseCode)) {
				ListedResource listedUserResource =
						scimClient.decodeSCIMResponseWithListedResource(
								response, SCIMConstants.identifyFormat(SCIMUtils.CONTENT_TYPE),
								SCIMConstants.USER_INT);
				List<SCIMObject> filteredUsers = listedUserResource.getScimObjects();
				for (SCIMObject filteredUser : filteredUsers) {

					MultiValuedAttribute entitlements =
							(MultiValuedAttribute) filteredUser.getAttribute("entitlements");
					deviceRegistration = ((DeviceRegistration) entitlements
							.getAttributeValueByType("registration")).toJson();
				}

			}
		} catch (IOException e) {
			log.error("Error in obtaining the SCIM Id for user: " + userName);
		} catch (CharonException e) {
			log.error("Error in obtaining the SCIM Id for user: " + userName);
		} catch (BadRequestException e) {
			log.error("Error in obtaining the SCIM Id for user: " + userName);
		} catch (NotFoundException e) {
			log.error("Error in obtaining the SCIM Id for user: " + userName);
		}
		return deviceRegistration;
	}*/

	/**
	 *
	 * @param username
	 * @param registration
	 * @param appID
	 * @return
	 */
	public static String createUser(String username, String registration, String appID) {

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
					System.out.println("The role added successfully to the system");
				} else {
					System.out.println("The role trying to add - already there in the system");
				}

				if (!storeManager.isExistingUser(username)) {

					Map<String, String> claims = new HashMap<String, String>();

					claims.put("http://wso2.org/claims/registration", registration);

					storeManager.addUser(username, "password", new String[] { appID, "loginOnly" },
					                     claims, null);
					System.out.println("The use added successfully to the system");
					status = "SUCCESS";
				} else {
					System.out.println("The user trying to add - already there in the system");
				}

			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		return status;
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

}
