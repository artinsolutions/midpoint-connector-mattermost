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
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.OperationTimeoutException;
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException;
import org.identityconnectors.framework.common.exceptions.PreconditionFailedException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateOp;
import org.json.JSONArray;
import org.json.JSONObject;

import com.evolveum.polygon.rest.AbstractRestConnector;

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
	
	private String token = null;

	@Override
    public void init(Configuration configuration) {
        LOG.info("Initializing {0} connector instance {1}", this.getClass().getSimpleName(), this);
    	super.init(configuration);
        
    	final List<String> passwordList = new ArrayList<String>(1);
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
		
    @Override
    public void dispose() {
        super.dispose();
    }    

//    @Override
//    public void checkAlive() {
//        test();
//        // TODO quicker test?
//    }
    
	@Override
	public void test() {
        HttpGet httpGet = new HttpGet(getConfiguration().getServiceAddress()+"/system/ping");
        
        try {
        	String response = callGetRequest(httpGet);
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
 
		/* UID=id, NAME=username
		AttributeInfoBuilder attrIdBuilder = new AttributeInfoBuilder(ATTR_ID);
        objClassBuilder.addAttributeInfo(attrIdBuilder.build());
		AttributeInfoBuilder attrUsernameBuilder = new AttributeInfoBuilder(ATTR_USERNAME);
        objClassBuilder.addAttributeInfo(attrUsernameBuilder.build()); */
        
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
        objClassBuilder.addAttributeInfo(attrCreateAtBuilder.build());
		AttributeInfoBuilder attrUpdateAtBuilder = new AttributeInfoBuilder(ATTR_UPDATE_AT);
		attrUpdateAtBuilder.setType(Long.class);
        objClassBuilder.addAttributeInfo(attrUpdateAtBuilder.build());
		AttributeInfoBuilder attrDeleteAtBuilder = new AttributeInfoBuilder(ATTR_DELETE_AT);
		attrDeleteAtBuilder.setType(Long.class);
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
                    JSONObject user = new JSONObject(callGetRequest(httpGet));
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
                HttpGet httpGet = new HttpGet(getConfiguration().getServiceAddress()+"/users");
                
    			JSONArray users = new JSONArray(callGetRequest(httpGet));
        		for (int i = 0; i < users.length(); ++i) {
        		    JSONObject user = users.getJSONObject(i);
                    ConnectorObject connectorObject = convertUserToConnectorObject(user);
                    handler.handle(connectorObject);
        		}
            	// TODO: paging if required later...
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
		LOG.ok("JSON User as input: \n{0}", user);
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
//        builder.addAttribute(ATTR_PROPS, user.getString(ATTR_PROPS)); //FIXME if we know what is here....
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
        // TODO: user image load if needed
        // https://mattermost.lab.artin.io/api/v4/users/pmk3mhwe5fdmzq7ngy1j4pkjko/image
     
//        boolean enabled = true; //FIXME: are visible/browseable disabled users?
//        addAttr(builder, OperationalAttributes.ENABLE_NAME, enabled);

        ConnectorObject connectorObject = builder.build();
        LOG.ok("convertUserToConnectorObject, user: {0}, \n\tconnectorObject: {1}",
        		id, connectorObject);
        return connectorObject;
	}
	
    protected String callRequest(HttpEntityEnclosingRequestBase request, String body) {
    	request.setHeader("Content-Type", ContentType.APPLICATION_JSON.getMimeType());
        request.setHeader("Accept", ContentType.APPLICATION_JSON.getMimeType());
        if (token != null)
        	request.setHeader("Authorization", "Bearer "+token);

        StringEntity entity = new StringEntity(body, ContentType.APPLICATION_JSON);
        request.setEntity(entity);
        
        // LOG.ok("request: \n{0}", request);// FIXME: never log request, can containts passwords
        CloseableHttpResponse response = execute(request);
        
        // read new token after init() auth
        if (token == null) { 
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
	
    protected String callGetRequest(HttpGet request) {
    	request.setHeader("Content-Type", ContentType.APPLICATION_JSON.getMimeType());
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
    	String result = null;
		try {
			result = EntityUtils.toString(response.getEntity());
		} catch (IOException e) {
			throw new ConnectorIOException("Error when reading response from Mattermost: "+e, e);
		}
        LOG.ok("Result body: {0}", result);
        
    	// super.processResponseErrors(response);
        int statusCode = response.getStatusLine().getStatusCode();
        
        if (statusCode < 200 || statusCode > 299) {
	        String message = "HTTP error " + statusCode + " " + response.getStatusLine().getReasonPhrase() + " : " + result;
	        LOG.error("{0}", message);
	        if (statusCode == 400 || statusCode == 405 || statusCode == 406) {
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
        }
        
        
        // TODO: handle AlreadyExistsException / UnknownUidException
 
    	return result;
    }

	@Override
	public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException();
	}

	@Override
	public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> replaceAttributes, OperationOptions options) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException();
	}

	@Override
	public Uid create(ObjectClass objectClass, Set<Attribute> createAttributes, OperationOptions options) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException();
	}
    
    
}
