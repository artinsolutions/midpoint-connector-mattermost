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
import org.identityconnectors.framework.spi.ConfigurationProperty;

/**
 * @author gpalos
 *
 */
public class MattermostConfiguration extends AbstractRestConfiguration {
    private String defaultTeamId = null;
    private String[] defaultChannelIds;

    @ConfigurationProperty(
            displayMessageKey = "mattermost.defaultTeamId",
            helpMessageKey = "mattermost.defaultTeamId.help"
    )
    public String getDefaultTeamId() {
        return defaultTeamId;
    }

    public void setDefaultTeamId(String defaultTeamId) {
        this.defaultTeamId = defaultTeamId;
    }

    @ConfigurationProperty(
            displayMessageKey = "mattermost.defaultChannelIds",
            helpMessageKey = "mattermost.defaultChannelIds.help"
    )
    public String[] getDefaultChannelIds() {
        return defaultChannelIds;
    }

    public void setDefaultChannelIds(String[] defaultChannelIds) {
        this.defaultChannelIds = defaultChannelIds;
    }
}
