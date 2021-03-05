/**
 * Copyright (c) ARTIN solutions
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.artin.idm.connector.mattermost;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.testng.annotations.BeforeClass;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * @author gpalos
 */
public class TestClient {

    private static final Log LOG = Log.getLog(TestClient.class);

    private static MattermostConfiguration conf;
    private static MattermostConnector conn;

    ObjectClass userObjectClass = new ObjectClass(MattermostConnector.OBJECT_CLASS_USER);

    @BeforeClass
    public static void setUp() throws Exception {
    	
        String fileName = "test.properties";
//        System.setProperty("org.apache.http", "DEBUG");

        final Properties properties = new Properties();
        InputStream inputStream = TestClient.class.getClassLoader().getResourceAsStream(fileName);
        if (inputStream == null) {
            throw new IOException("Sorry, unable to find " + fileName);
        }
        properties.load(inputStream);

        conf = new MattermostConfiguration();
        conf.setUsername(properties.getProperty("username"));
        if (properties.containsKey("password"))
        	conf.setPassword(new GuardedString(properties.getProperty("password").toCharArray()));
        conf.setServiceAddress(properties.getProperty("serviceAddress"));
        conf.setAuthMethod(properties.getProperty("authMethod"));
        conf.setTrustAllCertificates(Boolean.parseBoolean(properties.getProperty("trustAllCertificates")));
        conf.setTokenName(properties.getProperty("tokenName"));
        conf.setTokenValue(new GuardedString(properties.getProperty("tokenValue").toCharArray()));
        conf.setDefaultTeamId(properties.getProperty("teamID"));

		conn = new MattermostConnector(); 
		conn.init(conf);
    }  

/*    @Test
    public void testConn() {
    	LOG.info("Starting testConn...");
        conn.test();
    }

    @Test
    public void testSchema() {
        Schema schema = conn.schema();
        LOG.info("schema: " + schema);
    }

    @Test
    public void findByUid() {
        ResultsHandler rh = new ResultsHandler() {
            @Override
            public boolean handle(ConnectorObject connectorObject) {
                LOG.ok("result {0}", connectorObject);
                return true;
            }
        };

        // searchByUId
        MattermostFilter searchByUid = new MattermostFilter();
        searchByUid.byUid = "pmk3mhwe5fdmzq7ngy1j4pkjko";
        LOG.ok("start finding");
        conn.executeQuery(userObjectClass, searchByUid, rh, null);
        LOG.ok("end finding");
    }

    @Test
    public void findByName() {
        ResultsHandler rh = new ResultsHandler() {
            @Override
            public boolean handle(ConnectorObject connectorObject) {
                LOG.ok("result {0}", connectorObject);
                return true;
            }
        };

        // searchByUId
        MattermostFilter searchByUid = new MattermostFilter();
        searchByUid.byName = "admin";
        LOG.ok("start finding");
        conn.executeQuery(userObjectClass, searchByUid, rh, null);
        LOG.ok("end finding");
    }    

    //@Test
    public void findAll() {
        ResultsHandler rh = new ResultsHandler() {
            @Override
            public boolean handle(ConnectorObject connectorObject) {
                LOG.ok("result {0}", connectorObject);
                return true;
            }
        };

        // all
        MattermostFilter filter = new MattermostFilter();
        conn.executeQuery(userObjectClass, filter, rh, null);
    }

//    @Test
    public void create() {
        Set<Attribute> testAttributes = new HashSet<Attribute>();

        String testName = "TestUser_2";
        testAttributes.add(AttributeBuilder.build(Name.NAME, testName));
        testAttributes.add(AttributeBuilder.build(MattermostConnector.ATTR_USERNAME, testName));

        testAttributes.add(AttributeBuilder.build(MattermostConnector.ATTR_EMAIL, "UserName@test.email"));
        testAttributes.add(AttributeBuilder.build(MattermostConnector.ATTR_FIRST_NAME, "string_first_Name"));
        testAttributes.add(AttributeBuilder.build(MattermostConnector.ATTR_LAST_NAME, "string_last_name"));
        testAttributes.add(AttributeBuilder.build(MattermostConnector.ATTR_NICKNAME, "string_nick_name"));
        testAttributes.add(AttributeBuilder.build(MattermostConnector.ATTR_LOCALE, "string_locale"));

        GuardedString gs = new GuardedString("Pass123456789!".toCharArray());
        testAttributes.add(AttributeBuilder.build(OperationalAttributeInfos.PASSWORD.getName(), gs));

        Uid response = conn.create(userObjectClass, testAttributes, null);
    }

//    @Test
    public void update() throws IOException {
        Set<Attribute> updateAttributes = new HashSet<Attribute>();

        String testName = "userName";
        Uid testUid = new Uid("some_value");
        updateAttributes.add(AttributeBuilder.build(Name.NAME, testName));
        updateAttributes.add(AttributeBuilder.build(MattermostConnector.ATTR_ID, testUid.getUidValue()));
        updateAttributes.add(AttributeBuilder.build(MattermostConnector.ATTR_USERNAME, testName));

        updateAttributes.add(AttributeBuilder.build(MattermostConnector.ATTR_EMAIL, "UserName@test.email"));
        updateAttributes.add(AttributeBuilder.build(MattermostConnector.ATTR_CREATE_AT, "0"));

        GuardedString gs = new GuardedString("Pass123456789!".toCharArray());
        updateAttributes.add(AttributeBuilder.build(OperationalAttributeInfos.PASSWORD.getName(), gs));
        updateAttributes.add(AttributeBuilder.build(OperationalAttributeInfos.ENABLE.getName(), true));

        File f = new File("C:\\Users\\...\\test.png");
        byte[] byteTestPhoto = Files.readAllBytes(f.toPath());
        updateAttributes.add(AttributeBuilder.build(MattermostConnector.ATTR_IMAGE, byteTestPhoto));

        Uid response = conn.update(userObjectClass, testUid, updateAttributes, null);

        LOG.ok("Test update response = " + response.getUidValue());
    }

//    @Test
    public void delete() {
        String stringUidToDelete = "some_value";
        Uid uidToDelete = new Uid(stringUidToDelete);
        conn.delete(userObjectClass, uidToDelete, null);
    }

    @Test
    public void handleProfileImage() throws IOException {
        Uid uid = new Uid("some_value");

        File f = new File("C:\\Users\\...\\test.png");
        byte[] byteTestPhoto = Files.readAllBytes(f.toPath());

        Set<Attribute> testAttributes = new HashSet<Attribute>();
        testAttributes.add(AttributeBuilder.build(MattermostConnector.ATTR_IMAGE, byteTestPhoto));
        conn.handleProfileImage(uid, testAttributes);
    }

   // @Test
    public void getUserProfilePicture() throws IOException {
        Uid uid = new Uid("some_value");
//        conn.getUserProfilePicture(uid);
    }*/
}
