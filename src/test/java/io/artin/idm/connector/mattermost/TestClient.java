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

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.Uid;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
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

        final Properties properties = new Properties();
        InputStream inputStream = TestClient.class.getClassLoader().getResourceAsStream(fileName);
        if (inputStream == null) {
            throw new IOException("Sorry, unable to find " + fileName);
        }
        properties.load(inputStream);

        conf = new MattermostConfiguration();
        conf.setUsername(properties.getProperty("username"));
        conf.setPassword(new GuardedString(properties.getProperty("password").toCharArray()));
        conf.setServiceAddress(properties.getProperty("serviceAddress"));
        conf.setAuthMethod(properties.getProperty("authMethod"));
        conf.setTrustAllCertificates(Boolean.parseBoolean(properties.getProperty("trustAllCertificates")));

		conn = new MattermostConnector(); 
		conn.init(conf);
    }  
    
    @Test
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
        searchByUid.byUid = "pmk3mhwe5fdmzq7ngy1j4pkjko"; //"admin";
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
    
    @Test
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

}
