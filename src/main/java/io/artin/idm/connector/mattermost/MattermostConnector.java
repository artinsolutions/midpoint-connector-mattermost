/**
 * Copyright (c) ARTIN solutions
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
package io.artin.idm.connector.mattermost;

import com.evolveum.polygon.rest.AbstractRestConfiguration;
import com.evolveum.polygon.rest.AbstractRestConnector;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.*;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.util.EntityUtils;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.*;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.*;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * @author gpalos
 *
 */
@ConnectorClass(displayNameKey = "mattermost.connector.display", configurationClass = MattermostConfiguration.class)
public class MattermostConnector extends AbstractRestConnector<MattermostConfiguration> implements TestOp, SchemaOp, CreateOp, UpdateOp, DeleteOp, SearchOp<MattermostFilter>  {

	private static final Log LOG = Log.getLog(MattermostConnector.class);
	
	public static final String OBJECT_CLASS_USER = "user";
	
	
	public static final String ATTR_ID = "id";
	public static final String ATTR_USERNAME = "username";
	public static final String ATTR_FIRST_NAME = "first_name";
	public static final String ATTR_LAST_NAME = "last_name";
	public static final String ATTR_NICKNAME = "nickname";
	public static final String ATTR_EMAIL = "email";
	public static final String ATTR_EMAIL_VERIFIER = "email_verified";
	public static final String ATTR_AUTH_SERVICE = "auth_service";
	public static final String ATTR_ROLES_DELIMITER = " ";
	public static final String ATTR_ROLES = "roles";
	public static final String ATTR_LOCALE = "locale";
	public static final String ATTR_PROPS = "props";
	public static final String ATTR_FAILED_ATTEMPTS = "failed_attempts";
	public static final String ATTR_MFA_ACTIVE = "mfa_active";
	public static final String ATTR_TERM_OF_SERVICE_ID = "terms_of_service_id";
	public static final String ATTR_TERM_OF_SERVICE_CREATE_AT = "terms_of_service_create_at";
	public static final String ATTR_CREATE_AT = "create_at";
	public static final String ATTR_UPDATE_AT = "update_at";
	public static final String ATTR_DELETE_AT = "delete_at";
	public static final String ATTR_LAST_PASSWORD_UPDATE = "last_password_update";
	public static final String ATTR_LAST_PICTURE_UPDATE = "last_picture_update";
	
	public static final String DELIMITER = "__";

	public static final String ATTR_TIMEZONE = "timezone";
	public static final String ATTR_TIMEZONE__USEAUTOMATICTIMEZIONE = "useAutomaticTimezone";
	public static final String ATTR_TIMEZONE__MANUALTIMEZONE = "manualTimezone";
	public static final String ATTR_TIMEZONE__AUTOMATICTIMEZONE = "automaticTimezone";
	
	public static final String ATTR_NOTIFY_PROPS = "notify_props";
	public static final String ATTR_NOTIFY_PROPS__EMAIL = "email";
	public static final String ATTR_NOTIFY_PROPS__PUSH = "push";
	public static final String ATTR_NOTIFY_PROPS__DESKTOP = "desktop";
	public static final String ATTR_NOTIFY_PROPS__DESKTOP_SOUND = "desktop_sound";
	public static final String ATTR_NOTIFY_PROPS__MENTION_KEYS = "mention_keys";
	public static final String ATTR_NOTIFY_PROPS__CHANNEL = "channel";
	public static final String ATTR_NOTIFY_PROPS__FIRST_NAME = "first_name";

	public static final String ATTR_IS_BOT = "is_bot";
	public static final String ATTR_BOT_DESCRIPTION = "bot_description";

	public static final String ATTR_IMAGE = "image";

	public static final String ATTR_USER_ID = "user_id";
	public static final String ATTR_TEAM_ID= "team_id";

	public static final String ATTR_ERR_ID = "id";
	public static final String ATTR_ERR_MESSAGE = "message";
	public static final String ATTR_ACTIVE = "active";
	
	private String token = null;

	@Override
    public void init(Configuration configuration) {
        LOG.info("Initializing {0} connector instance {1}", this.getClass().getSimpleName(), this);
    	super.init(configuration);
        
    	// alternative authorization - getting Token from username/password 
    	if(getConfiguration().getAuthMethod().equals(AbstractRestConfiguration.AuthMethod.NONE.name())) {
	    	final List<String> passwordList = new ArrayList<>(1);
	        GuardedString guardedPassword = getConfiguration().getPassword();
	        if (guardedPassword != null) {
	            guardedPassword.access(new GuardedString.Accessor() {
	                @Override
	                public void access(char[] chars) {
	                    passwordList.add(new String(chars));
	                }
	            });
	        }
	        String password = null;
	        if (!passwordList.isEmpty()) {
	            password = passwordList.get(0);
	        }  
	        
	        // log in
	        HttpPost httpPost = new HttpPost(getConfiguration().getServiceAddress()+"/users/login");
	     
	        JSONObject jo = new JSONObject();
	        jo.put("login_id", getConfiguration().getUsername());
	        jo.put("password", password);
	        
	        try {
				String response = callRequest(httpPost, jo.toString());
				LOG.info("Init response is: {0}", response);        
			} catch (ConnectorIOException e) {
				LOG.error("cannot log in to mattermost: " + e, e);
				throw new ConnectorIOException(e.getMessage(), e);
			}
        }
    }
		
    @Override
    public void dispose() {
        super.dispose();
    }    

	@Override
	public void test() {
        HttpGet httpGet = new HttpGet(getConfiguration().getServiceAddress()+"/system/ping");
        
        try {
        	String response = callRequest(httpGet);
			LOG.info("Ping response is {0}", response);
		} catch (ConnectorIOException e) {
			LOG.error("cannot ping to mattermost: " + e, e);
			throw new ConnectorIOException(e.getMessage(), e);
		}
	}
	

	@Override
	public Schema schema() {
		SchemaBuilder schemaBuilder = new SchemaBuilder(MattermostConnector.class);
		
        buildUserClass(schemaBuilder);

        return schemaBuilder.build();
	}
	
	private void buildUserClass(SchemaBuilder schemaBuilder) {
		ObjectClassInfoBuilder objClassBuilder = new ObjectClassInfoBuilder();
		objClassBuilder.setType(OBJECT_CLASS_USER);

//		UID=id, NAME=username
//		AttributeInfoBuilder attrIdBuilder = new AttributeInfoBuilder(ATTR_ID);
//        objClassBuilder.addAttributeInfo(attrIdBuilder.build());
//		AttributeInfoBuilder attrUsernameBuilder = new AttributeInfoBuilder(ATTR_USERNAME);
//        objClassBuilder.addAttributeInfo(attrUsernameBuilder.build());
        
		AttributeInfoBuilder attrFirstNameBuilder = new AttributeInfoBuilder(ATTR_FIRST_NAME);
        objClassBuilder.addAttributeInfo(attrFirstNameBuilder.build());
		AttributeInfoBuilder attrLastNameBuilder = new AttributeInfoBuilder(ATTR_LAST_NAME);
        objClassBuilder.addAttributeInfo(attrLastNameBuilder.build());
		AttributeInfoBuilder attrNickNameBuilder = new AttributeInfoBuilder(ATTR_NICKNAME);
        objClassBuilder.addAttributeInfo(attrNickNameBuilder.build());
		AttributeInfoBuilder attrEmailBuilder = new AttributeInfoBuilder(ATTR_EMAIL);
        objClassBuilder.addAttributeInfo(attrEmailBuilder.build());
		AttributeInfoBuilder attrEmailVerifiedBuilder = new AttributeInfoBuilder(ATTR_EMAIL_VERIFIER);
		attrEmailVerifiedBuilder.setType(Boolean.class);
        objClassBuilder.addAttributeInfo(attrEmailVerifiedBuilder.build());
		AttributeInfoBuilder attrAuthServiceBuilder = new AttributeInfoBuilder(ATTR_AUTH_SERVICE);
        objClassBuilder.addAttributeInfo(attrAuthServiceBuilder.build());
		AttributeInfoBuilder attrRolesBuilder = new AttributeInfoBuilder(ATTR_ROLES);
		attrRolesBuilder.setMultiValued(true);
        objClassBuilder.addAttributeInfo(attrRolesBuilder.build());
		AttributeInfoBuilder attrLocaleBuilder = new AttributeInfoBuilder(ATTR_LOCALE);
        objClassBuilder.addAttributeInfo(attrLocaleBuilder.build());
		AttributeInfoBuilder attrPropsBuilder = new AttributeInfoBuilder(ATTR_PROPS);
		attrPropsBuilder.setMultiValued(true);
        objClassBuilder.addAttributeInfo(attrPropsBuilder.build());
		AttributeInfoBuilder attrFailedAttemptsBuilder = new AttributeInfoBuilder(ATTR_FAILED_ATTEMPTS);
		attrFailedAttemptsBuilder.setType(Long.class);
        objClassBuilder.addAttributeInfo(attrFailedAttemptsBuilder.build());
		AttributeInfoBuilder attrMfaActiveBuilder = new AttributeInfoBuilder(ATTR_MFA_ACTIVE);
		attrMfaActiveBuilder.setType(Boolean.class);
        objClassBuilder.addAttributeInfo(attrMfaActiveBuilder.build());
		AttributeInfoBuilder attrTermOfServiceIdBuilder = new AttributeInfoBuilder(ATTR_TERM_OF_SERVICE_ID);
        objClassBuilder.addAttributeInfo(attrTermOfServiceIdBuilder.build());
		AttributeInfoBuilder attrTermOfServiceCreateAtBuilder = new AttributeInfoBuilder(ATTR_TERM_OF_SERVICE_CREATE_AT);
		attrTermOfServiceCreateAtBuilder.setType(Long.class);
        objClassBuilder.addAttributeInfo(attrTermOfServiceCreateAtBuilder.build());
		AttributeInfoBuilder attrCreateAtBuilder = new AttributeInfoBuilder(ATTR_CREATE_AT);
		attrCreateAtBuilder.setType(Long.class);
		attrCreateAtBuilder.setUpdateable(false);
        objClassBuilder.addAttributeInfo(attrCreateAtBuilder.build());
		AttributeInfoBuilder attrUpdateAtBuilder = new AttributeInfoBuilder(ATTR_UPDATE_AT);
		attrUpdateAtBuilder.setType(Long.class);
		attrUpdateAtBuilder.setUpdateable(false);
        objClassBuilder.addAttributeInfo(attrUpdateAtBuilder.build());
		AttributeInfoBuilder attrDeleteAtBuilder = new AttributeInfoBuilder(ATTR_DELETE_AT);
		attrDeleteAtBuilder.setType(Long.class);
		attrDeleteAtBuilder.setUpdateable(false);
        objClassBuilder.addAttributeInfo(attrDeleteAtBuilder.build());
		AttributeInfoBuilder attrLastPasswordUpdateBuilder = new AttributeInfoBuilder(ATTR_LAST_PASSWORD_UPDATE);
		attrLastPasswordUpdateBuilder.setType(Long.class);
        objClassBuilder.addAttributeInfo(attrLastPasswordUpdateBuilder.build());
		AttributeInfoBuilder attrLastPictureUpdateBuilder = new AttributeInfoBuilder(ATTR_LAST_PICTURE_UPDATE);
		attrLastPictureUpdateBuilder.setType(Long.class);
        objClassBuilder.addAttributeInfo(attrLastPictureUpdateBuilder.build());
        
		AttributeInfoBuilder attrUseAutomaticTimezoneBuilder = new AttributeInfoBuilder(ATTR_TIMEZONE+DELIMITER+ATTR_TIMEZONE__USEAUTOMATICTIMEZIONE);
		attrUseAutomaticTimezoneBuilder.setType(Boolean.class);
        objClassBuilder.addAttributeInfo(attrUseAutomaticTimezoneBuilder.build());
		AttributeInfoBuilder attrManualTimezoneBuilder = new AttributeInfoBuilder(ATTR_TIMEZONE+DELIMITER+ATTR_TIMEZONE__MANUALTIMEZONE);
        objClassBuilder.addAttributeInfo(attrManualTimezoneBuilder.build());
		AttributeInfoBuilder attrAutomaticTimezoneBuilder = new AttributeInfoBuilder(ATTR_TIMEZONE+DELIMITER+ATTR_TIMEZONE__AUTOMATICTIMEZONE);
        objClassBuilder.addAttributeInfo(attrAutomaticTimezoneBuilder.build());

        AttributeInfoBuilder attrNPEmailBuilder = new AttributeInfoBuilder(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__EMAIL);
        attrNPEmailBuilder.setType(Boolean.class);
        objClassBuilder.addAttributeInfo(attrNPEmailBuilder.build());
		AttributeInfoBuilder attrNPPushBuilder = new AttributeInfoBuilder(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__PUSH);
        objClassBuilder.addAttributeInfo(attrNPPushBuilder.build());
		AttributeInfoBuilder attrNPDesktopBuilder = new AttributeInfoBuilder(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__DESKTOP);
        objClassBuilder.addAttributeInfo(attrNPDesktopBuilder.build());
		AttributeInfoBuilder attrNPDesktopSoundBuilder = new AttributeInfoBuilder(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__DESKTOP_SOUND);
		attrNPDesktopSoundBuilder.setType(Boolean.class);
        objClassBuilder.addAttributeInfo(attrNPDesktopSoundBuilder.build());
		AttributeInfoBuilder attrNPMentionKeysBuilder = new AttributeInfoBuilder(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__MENTION_KEYS);
        objClassBuilder.addAttributeInfo(attrNPMentionKeysBuilder.build());
		AttributeInfoBuilder attrNPChannelBuilder = new AttributeInfoBuilder(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__CHANNEL);
		attrNPChannelBuilder.setType(Boolean.class);
        objClassBuilder.addAttributeInfo(attrNPChannelBuilder.build());
		AttributeInfoBuilder attrNPFirstNameBuilder = new AttributeInfoBuilder(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__FIRST_NAME);
		attrNPFirstNameBuilder.setType(Boolean.class);
        objClassBuilder.addAttributeInfo(attrNPFirstNameBuilder.build());
		
		AttributeInfoBuilder attrIsBotBuilder = new AttributeInfoBuilder(ATTR_IS_BOT);
		attrIsBotBuilder.setType(Boolean.class);
        objClassBuilder.addAttributeInfo(attrIsBotBuilder.build());
		AttributeInfoBuilder attrBotDescriptionBuilder = new AttributeInfoBuilder(ATTR_BOT_DESCRIPTION);
        objClassBuilder.addAttributeInfo(attrBotDescriptionBuilder.build());

        AttributeInfoBuilder attrImage = new AttributeInfoBuilder(ATTR_IMAGE);
        attrImage.setType(byte[].class);
        objClassBuilder.addAttributeInfo(attrImage.build());

		objClassBuilder.addAttributeInfo(OperationalAttributeInfos.ENABLE);

		schemaBuilder.defineObjectClass(objClassBuilder.build());
	}

	@Override
	public FilterTranslator<MattermostFilter> createFilterTranslator(ObjectClass objectClass,
			OperationOptions options) {
		return new MattermostFilterTranslator();
	}

	@Override
	public void executeQuery(ObjectClass objectClass, MattermostFilter query, ResultsHandler handler,
			OperationOptions options) 
	{
		try {
            LOG.info("executeQuery on {0}, query: {1}, options: {2}", objectClass, query, options);
            if (objectClass.is(OBJECT_CLASS_USER)) {
                if (query != null && query.byUid != null) {
                    HttpGet httpGet = new HttpGet(getConfiguration().getServiceAddress()+"/users/"+query.byUid);
                    JSONObject user = new JSONObject(callRequest(httpGet));
                    ConnectorObject connectorObject = convertUserToConnectorObject(user);
                    handler.handle(connectorObject);
                } else  if (query != null && query.byName != null) {
                	JSONArray params = new JSONArray();
                	params.put(query.byName);
                    HttpPost httpPost = new HttpPost(getConfiguration().getServiceAddress()+"/users/usernames");
                    JSONArray users = new JSONArray(callRequest(httpPost, params.toString()));
            		for (int i = 0; i < users.length(); ++i) {
            		    JSONObject user = users.getJSONObject(i);
                        ConnectorObject connectorObject = convertUserToConnectorObject(user);
                        handler.handle(connectorObject);
            		}
                } else {
	                Integer pageSize = 60; // default in mattermost, max 200
	                Integer offset = 0; // first page in mattermost
	                boolean readAll = true;
	                if (options != null && options.getPageSize() != null) {
                		pageSize = options.getPageSize();
                		offset = options.getPagedResultsOffset();
                		readAll = false;
                		LOG.ok("Paging options offset: {0}, pageSize: {1}", offset, pageSize);
                	}
	                HttpGet httpGet = new HttpGet(getConfiguration().getServiceAddress()+"/users?per_page="+pageSize+"&page="+offset);
	                
	    			JSONArray users = new JSONArray(callRequest(httpGet));
	        		for (int i = 0; i < users.length(); ++i) {
	        		    JSONObject user = users.getJSONObject(i);
	                    ConnectorObject connectorObject = convertUserToConnectorObject(user);
	                    handler.handle(connectorObject);
	        		}
	        		if (readAll) {
                		LOG.ok("Reading all users, current offset: {0}, pageSize: {1}", offset, pageSize);
	        			while (users.length()==pageSize) {
		        			offset++;
	    	                httpGet = new HttpGet(getConfiguration().getServiceAddress()+"/users?per_page="+pageSize+"&page="+offset);
	    	                
	    	    			users = new JSONArray(callRequest(httpGet));
	    	        		for (int i = 0; i < users.length(); ++i) {
	    	        		    JSONObject user = users.getJSONObject(i);
	    	                    ConnectorObject connectorObject = convertUserToConnectorObject(user);
	    	                    handler.handle(connectorObject);
	    	        		}
	        			}
	        		}
                }
            } else {
                // not found
                throw new UnsupportedOperationException("Unsupported object class " + objectClass);
            }
        } catch (IOException e) {
            throw new ConnectorIOException(e.getMessage(), e);
        }
	}

	private ConnectorObject convertUserToConnectorObject(JSONObject user) throws IOException {
		LOG.ok("JSON MM User as input: \n{0}", user);
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        ObjectClass objectClass = new ObjectClass(OBJECT_CLASS_USER);
        builder.setObjectClass(objectClass);        

        String id = user.getString(ATTR_ID);
        builder.setUid(new Uid(id));
        builder.setName(new Name(user.getString(ATTR_USERNAME)));
        
        if (user.has(ATTR_FIRST_NAME))
        	builder.addAttribute(ATTR_FIRST_NAME, user.getString(ATTR_FIRST_NAME));
        if (user.has(ATTR_LAST_NAME))
            builder.addAttribute(ATTR_LAST_NAME, user.getString(ATTR_LAST_NAME));
        if (user.has(ATTR_NICKNAME))
            builder.addAttribute(ATTR_NICKNAME, user.getString(ATTR_NICKNAME));
        if (user.has(ATTR_EMAIL))
            builder.addAttribute(ATTR_EMAIL, user.getString(ATTR_EMAIL));
        if (user.has(ATTR_EMAIL_VERIFIER))
            builder.addAttribute(ATTR_EMAIL_VERIFIER, user.getBoolean(ATTR_EMAIL_VERIFIER));
        if (user.has(ATTR_AUTH_SERVICE))
            builder.addAttribute(ATTR_AUTH_SERVICE, user.getString(ATTR_AUTH_SERVICE));
        if (user.has(ATTR_ROLES))
            builder.addAttribute(ATTR_ROLES, (Object[]) user.getString(ATTR_ROLES).split(ATTR_ROLES_DELIMITER));
        if (user.has(ATTR_LOCALE))
            builder.addAttribute(ATTR_LOCALE, user.getString(ATTR_LOCALE));
//        builder.addAttribute(ATTR_PROPS, user.getString(ATTR_PROPS)); //TODO if we know what is here....
        if (user.has(ATTR_FAILED_ATTEMPTS))
            builder.addAttribute(ATTR_FAILED_ATTEMPTS, user.getLong(ATTR_FAILED_ATTEMPTS));
        if (user.has(ATTR_MFA_ACTIVE))
            builder.addAttribute(ATTR_MFA_ACTIVE, user.getBoolean(ATTR_MFA_ACTIVE));
        if (user.has(ATTR_TERM_OF_SERVICE_ID))
            builder.addAttribute(ATTR_TERM_OF_SERVICE_ID, user.getString(ATTR_TERM_OF_SERVICE_ID));
        if (user.has(ATTR_TERM_OF_SERVICE_CREATE_AT))
            builder.addAttribute(ATTR_TERM_OF_SERVICE_CREATE_AT, user.getLong(ATTR_TERM_OF_SERVICE_CREATE_AT));
        if (user.has(ATTR_CREATE_AT))
            builder.addAttribute(ATTR_CREATE_AT, user.getLong(ATTR_CREATE_AT));
        if (user.has(ATTR_UPDATE_AT))
            builder.addAttribute(ATTR_UPDATE_AT, user.getLong(ATTR_UPDATE_AT));
        if (user.has(ATTR_DELETE_AT))
            builder.addAttribute(ATTR_DELETE_AT, user.getLong(ATTR_DELETE_AT));
        if (user.has(ATTR_LAST_PASSWORD_UPDATE))
            builder.addAttribute(ATTR_LAST_PASSWORD_UPDATE, user.getLong(ATTR_LAST_PASSWORD_UPDATE));
        if (user.has(ATTR_LAST_PICTURE_UPDATE))
            builder.addAttribute(ATTR_LAST_PICTURE_UPDATE, user.getLong(ATTR_LAST_PICTURE_UPDATE));

        if (user.has(ATTR_IS_BOT))
            builder.addAttribute(ATTR_IS_BOT, user.getBoolean(ATTR_IS_BOT));
        if (user.has(ATTR_BOT_DESCRIPTION))
            builder.addAttribute(ATTR_BOT_DESCRIPTION, user.getString(ATTR_BOT_DESCRIPTION));
         
        if (user.has(ATTR_TIMEZONE)) {
	        JSONObject timezone = user.getJSONObject(ATTR_TIMEZONE);
	        if (timezone.has(ATTR_TIMEZONE__USEAUTOMATICTIMEZIONE))
	            builder.addAttribute(ATTR_TIMEZONE+DELIMITER+ATTR_TIMEZONE__USEAUTOMATICTIMEZIONE, timezone.getBoolean(ATTR_TIMEZONE__USEAUTOMATICTIMEZIONE));
	        if (timezone.has(ATTR_TIMEZONE__MANUALTIMEZONE))
	            builder.addAttribute(ATTR_TIMEZONE+DELIMITER+ATTR_TIMEZONE__MANUALTIMEZONE, timezone.getString(ATTR_TIMEZONE__MANUALTIMEZONE));
	        if (timezone.has(ATTR_TIMEZONE__AUTOMATICTIMEZONE))
	            builder.addAttribute(ATTR_TIMEZONE+DELIMITER+ATTR_TIMEZONE__AUTOMATICTIMEZONE, timezone.getString(ATTR_TIMEZONE__AUTOMATICTIMEZONE));
        }
        
        if (user.has(ATTR_NOTIFY_PROPS)) {
	        JSONObject notifyProps = user.getJSONObject(ATTR_NOTIFY_PROPS);
	        if (notifyProps.has(ATTR_NOTIFY_PROPS__EMAIL))
	            builder.addAttribute(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__EMAIL, notifyProps.getBoolean(ATTR_NOTIFY_PROPS__EMAIL));
	        if (notifyProps.has(ATTR_NOTIFY_PROPS__PUSH))
	            builder.addAttribute(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__PUSH, notifyProps.getString(ATTR_NOTIFY_PROPS__PUSH));
	        if (notifyProps.has(ATTR_NOTIFY_PROPS__DESKTOP))
	            builder.addAttribute(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__DESKTOP, notifyProps.getString(ATTR_NOTIFY_PROPS__DESKTOP));
	        if (notifyProps.has(ATTR_NOTIFY_PROPS__DESKTOP_SOUND))
	            builder.addAttribute(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__DESKTOP_SOUND, notifyProps.getBoolean(ATTR_NOTIFY_PROPS__DESKTOP_SOUND));
	        if (notifyProps.has(ATTR_NOTIFY_PROPS__MENTION_KEYS))
	            builder.addAttribute(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__MENTION_KEYS, notifyProps.getString(ATTR_NOTIFY_PROPS__MENTION_KEYS));
	        if (notifyProps.has(ATTR_NOTIFY_PROPS__CHANNEL))
	            builder.addAttribute(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__CHANNEL, notifyProps.getBoolean(ATTR_NOTIFY_PROPS__CHANNEL));
	        if (notifyProps.has(ATTR_NOTIFY_PROPS__FIRST_NAME))
	            builder.addAttribute(ATTR_NOTIFY_PROPS+DELIMITER+ATTR_NOTIFY_PROPS__FIRST_NAME, notifyProps.getBoolean(ATTR_NOTIFY_PROPS__FIRST_NAME));
        }

		if (user.has(ATTR_DELETE_AT)) {
			boolean enable = false;
			if (user.getInt(ATTR_DELETE_AT) == 0) {
				enable = true;
			}
			builder.addAttribute(OperationalAttributes.ENABLE_NAME, enable);
		}

		byte[] image = getUserProfilePicture(new Uid(id));
		builder.addAttribute(ATTR_IMAGE, image);

        ConnectorObject connectorObject = builder.build();
        LOG.ok("convertUserToConnectorObject, user: {0}, \n\tconnectorObject: {1}", id, connectorObject);
        return connectorObject;
	}

	
    protected String callRequest(HttpEntityEnclosingRequestBase request, String body) {
		request.setHeader("Content-Type", ContentType.APPLICATION_JSON.getMimeType()+"; charset=UTF-8");
		request.setHeader("Accept", ContentType.APPLICATION_JSON.getMimeType());

		request.setEntity(new StringEntity(body, ContentType.APPLICATION_JSON));
		return callRequest(request);
    }

	protected String callRequest(HttpEntityEnclosingRequestBase request) {
		if (token != null)
			request.setHeader("Authorization", "Bearer "+token);

		CloseableHttpResponse response = execute(request);

		// read new token after init() auth
		if(getConfiguration().getAuthMethod().equals(AbstractRestConfiguration.AuthMethod.NONE.name()) && token == null) {
			// token auth https://api.mattermost.com/#tag/authentication
			token = response.getFirstHeader("Token").getValue();
			LOG.ok("New token is saved: {0}", token);
		}
		LOG.ok("response: \n{0}", response);

		String result = processMattermostResponseErrors(response);
		LOG.ok("response body: \n{0}", result);
		closeResponse(response);

		return result;
	}
	
    protected String callRequest(HttpRequestBase request) {
    	request.setHeader("Content-Type", ContentType.APPLICATION_JSON.getMimeType()+"; charset=UTF-8");
        request.setHeader("Accept", ContentType.APPLICATION_JSON.getMimeType());

        if (token != null)
        	request.setHeader("Authorization", "Bearer "+token);

        CloseableHttpResponse response = execute(request);
        LOG.ok("response: \n{0}", response);

        String result = processMattermostResponseErrors(response);
        LOG.ok("response body: \n{0}", result);
        closeResponse(response);
        
        return result;
    }

    private String processMattermostResponseErrors(CloseableHttpResponse response) {
    	// in body is also error result message
    	String result;
		try {
			result = EntityUtils.toString(response.getEntity(), "UTF-8");
		} catch (IOException e) {
			throw new ConnectorIOException("Error when reading response from Mattermost: "+e, e);
		}
        LOG.ok("Result body: {0}", result);
        
    	// super.processResponseErrors(response);
		LOG.ok("To String getStatusLine = {0}", response.getStatusLine().toString());

        int statusCode = response.getStatusLine().getStatusCode();
		LOG.ok("Result body: Status code: {0}", statusCode);

        if (statusCode < 200 || statusCode > 299) {
	        String message = "HTTP error " + statusCode + " " + response.getStatusLine().getReasonPhrase() + " : " + result;
	        LOG.error("{0}", message);
	        if (statusCode == 400 || statusCode == 405 || statusCode == 406) {
				JSONObject resultJO = new JSONObject(result);
	        	String resultErrId = resultJO.getString(ATTR_ERR_ID);
				if (resultErrId.equals("app.user.save.email_exists.app_error") ||
						resultErrId.equals("app.user.save.username_exists.app_error") ||
						resultErrId.equals("app.user.save.existing.app_error")) {
					closeResponse(response);
					throw new AlreadyExistsException(message + ":" + resultJO.getString(ATTR_ERR_MESSAGE));
				}

				if (resultErrId.equals("app.user.update.find.app_error")) {
					closeResponse(response);
					throw new UnknownUidException(message + ":" + resultJO.getString(ATTR_ERR_MESSAGE));
				}

				if (resultErrId.equals("model.user.is_valid.pwd_lowercase_uppercase_number_symbol.app_error") ||
						resultErrId.equals("api.context.invalid_body_param.app_error")) {
					throw new InvalidAttributeValueException(resultJO.getString(message + ":" + ATTR_ERR_MESSAGE));
				}

	            closeResponse(response);
	            throw new ConnectorIOException(message);
	        }
	        if (statusCode == 401 || statusCode == 402 || statusCode == 403 || statusCode == 407) {
	            closeResponse(response);
	            throw new PermissionDeniedException(message);
	        }
	        if (statusCode == 404 || statusCode == 410) {
	            closeResponse(response);
	            throw new UnknownUidException(message);
	        }
	        if (statusCode == 408) {
	            closeResponse(response);
	            throw new OperationTimeoutException(message);
	        }
	        if (statusCode == 412) {
	            closeResponse(response);
	            throw new PreconditionFailedException(message);
	        }
	        if (statusCode == 418) {
	            closeResponse(response);
	            throw new UnsupportedOperationException("Sorry, no cofee: " + message);
	        }
			if (statusCode == 500) {
				closeResponse(response);
				throw new InvalidAttributeValueException("Sorry, no cofee: " + message);
			}
		}
 
    	return result;
    }

    private Uid parseUidFromString(String response) {
		JSONObject joParser = new JSONObject(response);

		Uid responseUid = new Uid(joParser.getString(ATTR_ID));

		LOG.ok("Parsed Uid from response String = {0}", responseUid.getUidValue());
		return responseUid;
	}

	@Override
	public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
//		https://api.mattermost.com/#tag/users/paths/~1users~1{user_id}/delete
		if (uid == null) {
			throw new UnknownUidException("Uid is empty");
		}

		HttpDelete request = new HttpDelete(getConfiguration().getServiceAddress() + "/users/" + uid.getUidValue());

		LOG.ok("Deleting user with UID = {0}", uid.getUidValue());
		callRequest(request);
		LOG.ok("User with UID = {0} - deleted", uid.getUidValue());
	}

	@Override
	public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> replaceAttributes, OperationOptions options) {
//		https://api.mattermost.com/#tag/users/paths/~1users~1{user_id}~1patch/put
		if (replaceAttributes == null || replaceAttributes.isEmpty()) {
			throw new UnknownUidException("Atributes are empty");
		}

		JSONObject jo = new JSONObject();

		if (uid == null) {
			throw new InvalidAttributeValueException("Missing mandatory attribute - uid");
		}

		HttpPut request = new HttpPut(getConfiguration().getServiceAddress() + "/users/" + uid.getUidValue() + "/patch");

		handleAttributes(replaceAttributes, jo, uid);

		String response = callRequest(request, jo.toString());

		Uid responseUid = parseUidFromString(response);
		LOG.ok("UPDATE activation status for user with uid = {0}", responseUid.getUidValue());
		handleEnable(responseUid, replaceAttributes);
		LOG.ok("Handle enable done");

		handleProfileImage(responseUid, replaceAttributes);
		LOG.ok("Handle profile image done");

		return responseUid;
	}

	private void handleAttributes(Set<Attribute>  replaceAttributes, JSONObject jo, Uid uid) {
		for (Attribute attr:replaceAttributes) {
			String attrName = attr.getName();
			if (!attrName.equals(OperationalAttributeInfos.PASSWORD.getName()) && !attrName.equals(OperationalAttributeInfos.ENABLE.getName())
					&& !attrName.equals(ATTR_ID) && !attrName.equals(Name.NAME) && !attrName.equals(ATTR_IMAGE)) {
				LOG.ok("Reading attribute {0} with value {1}", attrName, attr.getValue());
				jo.put(attrName, getStringAttr(replaceAttributes, attrName));
			} else if (attrName.equals(Name.NAME)) {
				jo.put(ATTR_USERNAME, getStringAttr(replaceAttributes, Name.NAME));
			}
		}

		final List<String> passwordList = new ArrayList<>();
		GuardedString guardedPassword = getAttr(replaceAttributes, OperationalAttributeInfos.PASSWORD.getName(), GuardedString.class);
		String password = null;
		if (guardedPassword != null) {
			guardedPassword.access(new GuardedString.Accessor() {
				@Override
				public void access(char[] chars) {
					passwordList.add(new String(chars));
				}
			});
		}
		if (!passwordList.isEmpty()) {
			password = passwordList.get(0);
			if (uid==null)
				jo.put("password", password);
			else {
				// update password for existing user
				HttpPut pwdRequest = new HttpPut(getConfiguration().getServiceAddress() + "/users/" + uid.getUidValue() + "/password");
				JSONObject pwd = new JSONObject();
				pwd.put("current_password", "");
				pwd.put("new_password", password);
				callRequest(pwdRequest, pwd.toString());
				
				// revoke current session
				HttpPost revokeSessionsRequest = new HttpPost(getConfiguration().getServiceAddress() + "/users/" + uid.getUidValue() + "/sessions/revoke/all");
				callRequest(revokeSessionsRequest);
				LOG.ok("New password set");
			}
		}
	}

	@Override
	public Uid create(ObjectClass objectClass, Set<Attribute> createAttributes, OperationOptions options) {
//		https://api.mattermost.com/#tag/users/paths/~1users/post
		if (createAttributes == null || createAttributes.isEmpty()) {
			throw new UnknownUidException("Atributes are empty");
		}

		JSONObject jo = new JSONObject();

		if (StringUtil.isBlank(getStringAttr(createAttributes, Name.NAME))) {
			throw new InvalidAttributeValueException("Missing mandatory attribute " + Name.NAME);
		} else {
			jo.put(ATTR_USERNAME, getStringAttr(createAttributes, Name.NAME));
		}

		if (StringUtil.isBlank(getStringAttr(createAttributes, ATTR_EMAIL))) {
			throw new InvalidAttributeValueException("Missing mandatory attribute " + ATTR_EMAIL);
		}

		HttpPost request = new HttpPost(getConfiguration().getServiceAddress() + "/users");

		handleAttributes(createAttributes, jo, null);

		String response = callRequest(request, jo.toString());

		Uid responseUid = parseUidFromString(response);

		handleEnable(responseUid, createAttributes);
		LOG.ok("Handle enable done");

		handleProfileImage(responseUid, createAttributes);
		LOG.ok("Handle profile image done");

		setDefaultTeam(responseUid);
		LOG.ok("Setting team done");

		setDefaultChannels(responseUid);
		LOG.ok("Setting channels done");
		
		verifyEmail(responseUid);
		LOG.ok("Verify email done");

		return responseUid;
	}

	private void handleEnable(Uid uid, Set<Attribute> attributes) {
		Boolean enable = getAttr(attributes, OperationalAttributes.ENABLE_NAME, Boolean.class);

		LOG.ok("Handle enable value = {0} for uid = {1}", enable, uid.getUidValue());

		if (enable != null) {
//			https://api.mattermost.com/#tag/users/paths/~1users~1{user_id}~1active/put
			HttpPut enableRequest = new HttpPut(getConfiguration().getServiceAddress() + "/users/" + uid.getUidValue() + "/active");
			JSONObject jo = new JSONObject();
			jo.put(ATTR_ACTIVE, enable);
			callRequest(enableRequest, jo.toString());
		}
	}
	
	protected void verifyEmail(Uid uid) {
		HttpPost enableRequest = new HttpPost(getConfiguration().getServiceAddress() + "/users/" + uid.getUidValue() + "/email/verify/member");
		callRequest(enableRequest);
	}
	

	private void setDefaultTeam(Uid uid) {
//		https://api.mattermost.com/#tag/teams/paths/~1teams~1{team_id}~1members/post
		String teamId = getConfiguration().getDefaultTeamId();
		LOG.ok("Adding uid = {0} to team = {1}", uid.getUidValue(), teamId);

		HttpPost teamRequest = new HttpPost(getConfiguration().getServiceAddress() + "/teams/" + teamId + "/members");
		JSONObject jo = new JSONObject();
		jo.put(ATTR_TEAM_ID, teamId);
		jo.put(ATTR_USER_ID, uid.getUidValue());
		callRequest(teamRequest, jo.toString());
	}

	private void setDefaultChannels(Uid uid) {
//		https://api.mattermost.com/#tag/channels/paths/~1channels~1{channel_id}~1members/post
		String[] channelIds = getConfiguration().getDefaultChannelIds();

		for (String channelId: channelIds) {
			LOG.ok("Adding uid = {0} to channel = {1}", uid.getUidValue(), channelId);
			HttpPost channelRequest = new HttpPost(getConfiguration().getServiceAddress() + "/channels/" + channelId + "/members");
			JSONObject jo = new JSONObject();
			jo.put(ATTR_USER_ID, uid.getUidValue());
			callRequest(channelRequest, jo.toString());
		}
	}

	private byte[] getUserProfilePicture(Uid uid) throws IOException {
//		https://api.mattermost.com/#tag/users/paths/~1users~1{user_id}~1image/get/
		HttpGet request = new HttpGet(getConfiguration().getServiceAddress() + "/users/" + uid.getUidValue() + "/image");

		request.setHeader("Content-Type", ContentType.APPLICATION_JSON.getMimeType());
		request.setHeader("Accept", ContentType.APPLICATION_JSON.getMimeType());

		if (token != null)
			request.setHeader("Authorization", "Bearer "+token);

		CloseableHttpResponse response = execute(request);
		LOG.ok("response: \n{0}", response);

		HttpEntity entity = response.getEntity();
		InputStream is = entity.getContent();
		byte[] downloadedPicture = new byte[is.available()];
		is.read(downloadedPicture, 0, downloadedPicture.length);
		is.close();

		closeResponse(response);

		return downloadedPicture;
  	}

	protected void handleProfileImage(Uid uid, Set<Attribute> attributes)   {
//		https://api.mattermost.com/#tag/users/paths/~1users~1{user_id}~1image/post
		HttpPost request = new HttpPost(getConfiguration().getServiceAddress() + "/users/" + uid.getUidValue() + "/image");

		byte[] base64Image = getAttr(attributes, ATTR_IMAGE, byte[].class);
		if (base64Image==null || base64Image.length==0)
			return;
		InputStream targetStream = new ByteArrayInputStream(base64Image);

		MultipartEntityBuilder builder = MultipartEntityBuilder.create();
		builder.addBinaryBody(
				ATTR_IMAGE,
				targetStream,
				ContentType.APPLICATION_OCTET_STREAM,
				uid.getUidValue() +"image.jpg"
		);
		HttpEntity multipart = builder.build();

		request.setEntity(multipart);

		callRequest(request);
	}
}