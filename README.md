[comment]: # "Auto-generated SOAR connector documentation"
# fortimanager

Publisher: asdf  
Connector Version: 1.0.0  
Product Vendor: asdf  
Product Name: asdf  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.2.0.50  

asdf

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a asdf asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** |  required  | string | Fortimanager Base URL
**username** |  optional  | string | Username
**password** |  optional  | password | Password
**api_key** |  optional  | password | API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[create firewall policy](#action-create-firewall-policy) - Create a firewall policy  
[list firewall policies](#action-list-firewall-policies) - List ADOM or Global firewall policies  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'create firewall policy'
Create a firewall policy

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**level** |  required  | Level type at which to create the firewall policy. Choosing 'ADOM' (Administrative Domain Name) of the FortiManager server allows you to perform against that particular ADOM. Choosing 'Global' allows you to select the type of firewall policy you want to create. | string | 
**adom** |  optional  | ADOM name | string | 
**package** |  optional  | Policy Package full path and name | string | 
**policy** |  optional  | Policy ID | string | 

#### Action Output
No Output  

## action: 'list firewall policies'
List ADOM or Global firewall policies

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**level** |  required  | Level type at which to list the firewall policies | string | 
**adom** |  optional  | ADOM name | string | 
**package** |  required  | Policy Package name | string | 
**package_path** |  optional  | Policy Package folder path | string | 
**policy_type** |  optional  | Policy type. Only for 'Global' Firewall Policies | string | 

#### Action Output
No Output