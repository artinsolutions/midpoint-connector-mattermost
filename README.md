# connector-mattermost

Polygon/ConnId connector for Mattermost

## Description

Connector for [Mattermost](https://mattermost.com/) using [REST API](https://api.mattermost.com/#tag/introduction). 

## Capabilities and Features

* Schema: YES
* Provisioning: YES
* Live Synchronization: No
* Password: YES
* Activation: YES?
* Script execution: No 

Mattermost Connector contains support for USER entity.  

## Build

[Download](https://github.com/artinsolutions/midpoint-connector-mattermost) and build the project with usual:

```
mvn clean install
```

After successful the build, you can find `connector-mattermost-1.0.0.0.jar` in `target` directory.

## Configuring resource

* create user with required permissions or use admin
* inspire by [sample](https://github.com/artinsolutions/midpoint-connector-mattermost/tree/master/sample) to configure your own resource

## License

Licensed under the [Apache License 2.0](/LICENSE).

## Status

Mattermost Connector is intended for production use. Tested with MidPoint version 4.1. The connector was introduced as a contribution to midPoint project by [ARTIN](https://www.artinsolutions.com) and is not officially supported by Evolveum.
If you need support, please contact idm@artinsolutions.com.