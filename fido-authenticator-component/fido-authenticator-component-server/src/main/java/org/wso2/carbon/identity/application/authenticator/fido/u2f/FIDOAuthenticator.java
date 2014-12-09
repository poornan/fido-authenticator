/*
 * Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
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

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.DeviceRegistration;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.AuthenticateRequestData;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.data.messages.AuthenticateResponse;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.exceptions.U2fException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * FIDO U2F Specification based authentication.
 */
public class FIDOAuthenticator extends AbstractApplicationAuthenticator {

	private static final String AUTHENTICATOR_NAME = "FIDOAuthenticator";
	private final Map<String, String> requestStorage = new HashMap<String, String>();
	private final Multimap<String, String> userStorage = ArrayListMultimap.create();
	private final U2F u2f = new U2F();

	private Iterable<DeviceRegistration> getRegistrations(String username) {
		Collection<String> serializedRegistrations = userStorage.get(username);
		List<DeviceRegistration> registrations = new ArrayList<DeviceRegistration>();
		for (String serialized : serializedRegistrations) {
			registrations.add(DeviceRegistration.fromJson(serialized));
		}
		return registrations;
	}

	private Iterable<DeviceRegistration> getRegistrations(String username, String appID) {
		List<DeviceRegistration> registrations = new ArrayList<DeviceRegistration>();
		registrations.add(
				DeviceRegistration.fromJson(U2FUser.getDeviceRegistration(username, appID)));
		return registrations;
	}

	/*private void addRegistration(String username, DeviceRegistration registration) {
		userStorage.put(username, registration.toJson());
	}

	private void addRegistration(String username, DeviceRegistration registration, String appID) {
		U2FUser.createUser(username, registration.toJson(), appID);
	}*/

	/**
	 * Initiate FIDO Device Registration.
	 *
	 * @param username Username.
	 * @param appID    Application host address.
	 * @return String RegisterRequestData.
	 *//*
	private String startRegistration(String username, String appID) {
		RegisterRequestData registerRequestData =
				u2f.startRegistration(appID, getRegistrations(username, appID));
		requestStorage.put(registerRequestData.getRequestId(), registerRequestData.toJson());
		return registerRequestData.toJson();
	}*/

	/**
	 * Finish FIDO Device registration
	 *
	 * @param response tokenResponse.
	 * @param username username.
	 * @return success or failure.
	 * @throws U2fException
	 *//*
	private String finishRegistration(String response, String username, String appID)
			throws U2fException {
		RegisterResponse registerResponse = RegisterResponse.fromJson(response);
		RegisterRequestData registerRequestData =
				RegisterRequestData.fromJson(requestStorage.get(registerResponse.getRequestId()));
		DeviceRegistration registration =
				u2f.finishRegistration(registerRequestData, registerResponse);
		addRegistration(username, registration, appID);

		requestStorage.remove(registerResponse.getRequestId());

		return "SUCCESS";
	}*/

	/**
	 * Initiate FIDO authentication.
	 *
	 * @param username username.
	 * @param appID    Application host address.
	 * @return AuthenticateRequestData.
	 * @throws U2fException
	 */
	private String startAuthentication(String username, String appID) throws U2fException {
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
	private void finishAuthentication(String response,
	                                  String username) throws U2fException {
		AuthenticateResponse authenticateResponse = AuthenticateResponse.fromJson(response);
		AuthenticateRequestData authenticateRequest = AuthenticateRequestData
				.fromJson(requestStorage.get(authenticateResponse.getRequestId()));
		requestStorage.remove(authenticateResponse.getRequestId());
		u2f.finishAuthentication(authenticateRequest, authenticateResponse,
		                         getRegistrations(username));
	}

	@Override protected void processAuthenticationResponse(
			HttpServletRequest request,
			HttpServletResponse response,
			AuthenticationContext authenticationContext) throws AuthenticationFailedException {
		String tokenResponse = request.getParameter("tokenResponse");
		String appID = request.getServerName();
		try {
			finishAuthentication(tokenResponse, appID);
		} catch (U2fException e) {
			throw new AuthenticationFailedException(e.getMessage(), e);
		}
	}

	@Override public boolean canHandle(javax.servlet.http.HttpServletRequest httpServletRequest) {
		String tokenResponse = httpServletRequest.getParameter("tokenResponse");

		return null != tokenResponse;

	}

	@Override public String getContextIdentifier(
			javax.servlet.http.HttpServletRequest httpServletRequest) {
		return httpServletRequest.getParameter("sessionDataKey");
	}

	@Override public String getName() {
		return AUTHENTICATOR_NAME;
	}

	@Override public String getFriendlyName() {
		return "FIDO";
	}

	@Override protected void initiateAuthenticationRequest(HttpServletRequest request,
	                                                       HttpServletResponse response,
	                                                       AuthenticationContext context)
			throws AuthenticationFailedException {
		String username = request.getParameter("username");
		String appID = request.getServerName();
		String registrationData;
		try {
			registrationData = startAuthentication(username, appID);

			String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
			String queryParams = FrameworkUtils
					.getQueryStringWithFrameworkContextId(context.getQueryParams(),
					                                      context.getCallerSessionKey(),
					                                      context.getContextIdentifier());

			response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
			                      + "&authenticators=" + getName() + "&deviceRegistration=" +
			                      registrationData);
		} catch (IOException e) {
			throw new AuthenticationFailedException(e.getMessage(), e);
		} catch (U2fException e) {
			throw new AuthenticationFailedException(e.getMessage(), e);
		}
	}

	@Override protected boolean retryAuthenticationEnabled() {
		return false;
	}

}

