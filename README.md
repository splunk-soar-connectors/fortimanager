[comment]: # "Auto-generated SOAR connector documentation"
# FortiManager

Publisher: Splunk  
Connector Version: 1.0.0  
Product Vendor: Fortinet  
Product Name: FortiManager  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 10155.0.0.0  

FortiManager


Replace this text in the app's **readme.html** to contain more detailed information


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a FortiManager asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**host** |  required  | string | Host
**user** |  optional  | string | User
**password** |  optional  | password | Password
**api_key** |  optional  | password | API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[block url](#action-block-url) - Block an URL  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'block url'
Block an URL

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to block | string |  `url` 
**policy** |  optional  | Policy to Update | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.url | string |  `url`  |  
action_result.parameter.policy | string |  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  