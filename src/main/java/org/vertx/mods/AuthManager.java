/*
 * Copyright 2011-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.vertx.mods;

import java.util.UUID;

import org.jasypt.util.password.StrongPasswordEncryptor;
import org.vertx.java.busmods.BusModBase;
import org.vertx.java.core.Handler;
import org.vertx.java.core.eventbus.Message;
import org.vertx.java.core.json.JsonObject;
import org.vertx.java.core.shareddata.Shareable;

/**
 * Basic Authentication Manager Bus Module
 * <p>
 * Please see the busmods manual for a full description
 * <p>
 * 
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthManager extends BusModBase {

	private Handler<Message<JsonObject>> loginHandler;
	private Handler<Message<JsonObject>> logoutHandler;
	private Handler<Message<JsonObject>> authoriseHandler;

	private static final long DEFAULT_SESSION_TIMEOUT = 30 * 60 * 1000;

	private String address;
	private String userCollection;
	private String persistorAddress;
	private long sessionTimeout;

	private static final class LoginInfo implements Shareable{

		private static final long serialVersionUID = 1L;
		final long timerID;
		final String sessionID;
		final String userID;

		private LoginInfo(long timerID, String sessionID, String userID) {
			this.timerID = timerID;
			this.sessionID = sessionID;
			this.userID = userID;
		}
	}

	/**
	 * Start the busmod
	 */
	public void start() {
		super.start();
		this.address = getOptionalStringConfig("address", "vertx.basicauthmanager");
		this.userCollection = getOptionalStringConfig("user_collection", "User");
		this.persistorAddress = getOptionalStringConfig("persistor_address", "vertx.mongopersistor");
		Number timeout = config.getNumber("session_timeout");
		if (timeout != null) {
			if (timeout instanceof Long) {
				this.sessionTimeout = (Long) timeout;
			} else if (timeout instanceof Integer) {
				this.sessionTimeout = (Integer) timeout;
			}
		} else {
			this.sessionTimeout = DEFAULT_SESSION_TIMEOUT;
		}

		loginHandler = new Handler<Message<JsonObject>>() {
			public void handle(Message<JsonObject> message) {
				doLogin(message);
			}
		};
		eb.registerHandler(address + ".login", loginHandler);
		logoutHandler = new Handler<Message<JsonObject>>() {
			public void handle(Message<JsonObject> message) {
				doLogout(message);
			}
		};
		eb.registerHandler(address + ".logout", logoutHandler);
		authoriseHandler = new Handler<Message<JsonObject>>() {
			public void handle(Message<JsonObject> message) {
				doAuthorise(message);
			}
		};
		eb.registerHandler(address + ".authorise", authoriseHandler);
	}

	private void doLogin(final Message<JsonObject> message) {

		final String email = getMandatoryString("email", message);
		if (email == null) {
			return;
		}
		final String password = getMandatoryString("password", message);
		if (password == null) {
			return;
		}

		JsonObject findMsg = new JsonObject().putString("action", "findone").putString("collection", userCollection);
		JsonObject matcher = new JsonObject().putString("email", email);
		findMsg.putObject("matcher", matcher);

		eb.send(persistorAddress, findMsg, new Handler<Message<JsonObject>>() {
			public void handle(Message<JsonObject> reply) {

				if (reply.body().getString("status").equals("ok")) {
					if (reply.body().getObject("result") != null) {

						StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();
						String encryptedPassword = reply.body().getObject("result").getString("password");
						if (passwordEncryptor.checkPassword(password, encryptedPassword)) {

							// Check if already logged in, if so logout of the
							// old session
							LoginInfo info = (LoginInfo) vertx.sharedData().getMap("logins").get(email);
							if (info != null) {
								logout(info.sessionID);
							}

							// Found
							final String sessionID = UUID.randomUUID().toString();
							long timerID = vertx.setTimer(sessionTimeout, new Handler<Long>() {
								public void handle(Long timerID) {
									vertx.sharedData().getMap("sessions").remove(sessionID);
									vertx.sharedData().getMap("logins").remove(email);
								}
							});
							String userID = reply.body().getObject("result").getString("_id");
							vertx.sharedData().getMap("sessions").put(sessionID, email);
							vertx.sharedData().getMap("logins").put(email, new LoginInfo(timerID, sessionID, userID));
							JsonObject jsonReply = new JsonObject().putString("sessionID", sessionID);
							sendOK(message, jsonReply);
						} else {
							sendStatus("denied", message);
						}
					} else {
						// Not found
						sendStatus("denied", message);
					}
				} else {
					sendError(message, "Failed to excecute login");
				}
			}
		});
	}

	protected void doLogout(final Message<JsonObject> message) {
		final String sessionID = getMandatoryString("sessionID", message);
		if (sessionID != null) {
			if (logout(sessionID)) {
				sendOK(message);
			} else {
				super.sendError(message, "Not logged in");
			}
		}
	}

	protected boolean logout(String sessionID) {
		String email = (String) vertx.sharedData().getMap("sessions").remove(sessionID);
		if (email != null) {
			LoginInfo info = (LoginInfo) vertx.sharedData().getMap("logins").remove(email);
			vertx.cancelTimer(info.timerID);
			return true;
		} else {
			return false;
		}
	}

	protected void doAuthorise(Message<JsonObject> message) {
		String sessionID = getMandatoryString("sessionID", message);
		if (sessionID == null) {
			return;
		}
		String email = (String) vertx.sharedData().getMap("sessions").get(sessionID);
		// In this basic auth manager we don't do any resource specific
		// authorisation
		// The user is always authorised if they are logged in

		if (email != null) {
			String userID = ((LoginInfo) vertx.sharedData().getMap("logins").get(email)).userID;
			JsonObject reply = new JsonObject().putString("email", email).putString("user_id", userID);
			sendOK(message, reply);
		} else {
			sendStatus("denied", message);
		}
	}
}
