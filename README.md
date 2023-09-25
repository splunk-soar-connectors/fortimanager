[comment]: # "Auto-generated SOAR connector documentation"
# FortiManager

Publisher: Splunk  
Connector Version: 1.0.1  
Product Vendor: Fortinet  
Product Name: FortiManager  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.0.0  

FortiManager

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2023 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
### Overview

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a FortiManager asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | Base URL of FortiManager instance
**verify_server_cert** |  optional  | boolean | Verify server certificate
**username** |  optional  | string | Username
**password** |  optional  | password | Password
**api_key** |  optional  | password | API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[create firewall policy](#action-create-firewall-policy) - Create an ADOM firewall policy  
[list firewall policies](#action-list-firewall-policies) - List ADOM firewall policies  
[create address](#action-create-address) - Create a firewall address object  
[delete address](#action-delete-address) - Delete firewall address object  
[list addresses](#action-list-addresses) - List firewall address objects  
[update address](#action-update-address) - Update existing firewall address object  
[block ip](#action-block-ip) - Block ADOM level IP addresses  
[unblock ip](#action-unblock-ip) - Unblock ADOM level IP addresses  
[delete firewall policy](#action-delete-firewall-policy) - Delete an ADOM firewall policy  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'create firewall policy'
Create an ADOM firewall policy

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**level** |  required  | Level type at which to create the firewall policy. Choosing 'ADOM' (Administrative Domain Name) of the FortiManager server allows you to perform against that particular ADOM | string | 
**adom** |  optional  | ADOM name | string | 
**package** |  required  | The Policy Package name or full folder path to create the firewall policy within | string | 
**name** |  required  | Policy name to create | string | 
**source_interface** |  required  | Incoming (ingress) interface to specify for the firewall policy. If specifying more than one, enter as a comma-separated list | string | 
**destination_interface** |  required  | Outgoing (egress) interface to specify for the firewall policy. If specifying more than one, enter as a comma-separated list | string | 
**source_address** |  required  | Source IPv4 Address and address group names to specify for the firewall policy. If specifying more than one, enter as a comma-separated list | string | 
**destination_address** |  required  | Destination IPv4 Address and address group names to specify for the firewall policy. If specifying more than one, enter as a comma-separated list | string | 
**action** |  required  | Policy action to specify for the firewall policy. Accept: Allows sessions that match the firewall policy. Deny: Blocks sessions that match the firewall policy. IPSec: Firewall policy becomes a policy-based IPsec VPN policy | string | 
**status** |  required  | 'Enable' or 'Disable' this firewall policy on your FortiManager instance | string | 
**schedule** |  required  | Name for the schedule to be associated with the firewall policy (e.g. always, none) | string | 
**service** |  required  | Service and Service group names to create for the firewall policy. If specifying more than one, enter as a comma-separated list | string | 
**inspection_mode** |  required  | Firewall policy Inspection Mode | string | 
**log_traffic** |  required  | Enables or disables logging of either all sessions or only security profile sessions | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.policyid | numeric |  |   1074741829  10  11 
action_result.status | string |  |   success 
action_result.message | string |  |   Status: Successfully added firewall policy 
action_result.summary.status | string |  |   Successfully added firewall policy 
action_result.parameter.name | string |  |   soar-adom-firewall-policy 
action_result.parameter.level | string |  |   ADOM 
action_result.parameter.action | string |  |   deny 
action_result.parameter.status | string |  |   enable 
action_result.parameter.package | string |  |   default 
action_result.parameter.service | string |  |   ALL 
action_result.parameter.schedule | string |  |   always 
action_result.parameter.log_traffic | string |  |   all 
action_result.parameter.source_address | string |  |   all 
action_result.parameter.inspection_mode | string |  |   flow 
action_result.parameter.source_interface | string |  |   any 
action_result.parameter.destination_address | string |  |   all 
action_result.parameter.destination_interface | string |  |   any 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.parameter.adom | string |  |   root   

## action: 'list firewall policies'
List ADOM firewall policies

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**level** |  required  | Level type at which to list the firewall policies | string | 
**adom** |  optional  | ADOM name. Only required for 'ADOM' Firewall Policies | string | 
**package** |  required  | Policy Package name | string | 
**package_path** |  optional  | The full folder path nested within the policy package | string | 
**policy_name** |  optional  | Specific firewall policy name whose details you want to retrieve | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.fec | numeric |  |   0 
action_result.data.\*.oid | numeric |  |   5105  5142 
action_result.data.\*.tos | string |  |   0x00 
action_result.data.\*.dsri | numeric |  |   0 
action_result.data.\*.name | string |  |   soar-footer-firewall-name 
action_result.data.\*.uuid | string |  |   c33e106e-4117-51ee-1771-7827f531ca41  987cb312-3d16-51ee-a38e-2a5f3b237725  328ee00e-5100-51ee-7bf8-0e865287254f 
action_result.data.\*.wccp | numeric |  |   0 
action_result.data.\*._byte | numeric |  |   0 
action_result.data.\*._pkts | numeric |  |   0 
action_result.data.\*.nat46 | numeric |  |   0 
action_result.data.\*.nat64 | numeric |  |   0 
action_result.data.\*.natip | string |  `ip`  |   0.0.0.0 
action_result.data.\*.action | numeric |  |   0 
action_result.data.\*.status | numeric |  |   1 
action_result.data.\*.cgn-eif | numeric |  |   0 
action_result.data.\*.cgn-eim | numeric |  |   0 
action_result.data.\*.dstaddr | string |  |   all 
action_result.data.\*.dstintf | string |  |   any  1-A10 
action_result.data.\*.obj seq | numeric |  |   1 
action_result.data.\*.rtp-nat | numeric |  |   0 
action_result.data.\*.service | string |  |   ALL 
action_result.data.\*.srcaddr | string |  |   all 
action_result.data.\*.srcintf | string |  |   any  1-A1 
action_result.data.\*.policyid | numeric |  |   1074741825  3  1 
action_result.data.\*.schedule | string |  |   always 
action_result.data.\*.tos-mask | string |  |   0x00 
action_result.data.\*._hitcount | numeric |  |   0 
action_result.data.\*._last_hit | numeric |  |   0 
action_result.data.\*.match-vip | numeric |  |   1 
action_result.data.\*.sgt-check | numeric |  |   0 
action_result.data.\*._first_hit | numeric |  |   0 
action_result.data.\*._sesscount | numeric |  |   0 
action_result.data.\*.logtraffic | numeric |  |   2 
action_result.data.\*.tos-negate | numeric |  |   0 
action_result.data.\*.anti-replay | numeric |  |   1 
action_result.data.\*.geoip-match | numeric |  |   0 
action_result.data.\*.pcp-inbound | numeric |  |   0 
action_result.data.\*.session-ttl | string |  |   0 
action_result.data.\*.ztna-status | numeric |  |   0 
action_result.data.\*._label-color | numeric |  |   0 
action_result.data.\*.pcp-outbound | numeric |  |   0 
action_result.data.\*.profile-type | numeric |  |   0 
action_result.data.\*.vlan-cos-fwd | numeric |  |   255 
action_result.data.\*.vlan-cos-rev | numeric |  |   255 
action_result.data.\*._last_session | numeric |  |   0 
action_result.data.\*.email-collect | numeric |  |   0 
action_result.data.\*.geoip-anycast | numeric |  |   0 
action_result.data.\*.policy-expiry | numeric |  |   0 
action_result.data.\*._first_session | numeric |  |   0 
action_result.data.\*.dstaddr-negate | numeric |  |   0 
action_result.data.\*.match-vip-only | numeric |  |   0 
action_result.data.\*.policy-offload | numeric |  |   1 
action_result.data.\*.service-negate | numeric |  |   0 
action_result.data.\*.srcaddr-negate | numeric |  |   0 
action_result.data.\*.tcp-mss-sender | numeric |  |   0 
action_result.data.\*._global-vpn-tgt | numeric |  |   0 
action_result.data.\*.dstaddr6-negate | numeric |  |   0 
action_result.data.\*.dynamic-shaping | numeric |  |   0 
action_result.data.\*.ip-version-type | string |  |   ipv4 
action_result.data.\*.np-acceleration | numeric |  |   1 
action_result.data.\*.permit-any-host | numeric |  |   0 
action_result.data.\*.srcaddr6-negate | numeric |  |   0 
action_result.data.\*.diffserv-forward | numeric |  |   0 
action_result.data.\*.diffserv-reverse | numeric |  |   0 
action_result.data.\*.internet-service | numeric |  |   0 
action_result.data.\*.logtraffic-start | numeric |  |   0 
action_result.data.\*.schedule-timeout | numeric |  |   0 
action_result.data.\*.send-deny-packet | numeric |  |   0 
action_result.data.\*.tcp-mss-receiver | numeric |  |   0 
action_result.data.\*.cgn-session-quota | numeric |  |   16777215 
action_result.data.\*.internet-service6 | numeric |  |   0 
action_result.data.\*.block-notification | numeric |  |   0 
action_result.data.\*.cgn-resource-quota | numeric |  |   16 
action_result.data.\*.policy-expiry-date | string |  |   0000-00-00 00:00:00 
action_result.data.\*.reputation-minimum | numeric |  |   0 
action_result.data.\*._global-label-color | numeric |  |   0 
action_result.data.\*.reputation-minimum6 | numeric |  |   0 
action_result.data.\*.internet-service-src | numeric |  |   0 
action_result.data.\*.ztna-policy-redirect | numeric |  |   0 
action_result.data.\*.captive-portal-exempt | numeric |  |   0 
action_result.data.\*.delay-tcp-npu-session | numeric |  |   0 
action_result.data.\*.identity-based-policy | string |  |  
action_result.data.\*.internet-service6-src | numeric |  |   0 
action_result.data.\*.policy-behaviour-type | string |  |   standard 
action_result.data.\*.reputation-direction6 | numeric |  |   42 
action_result.data.\*.ztna-device-ownership | numeric |  |   0 
action_result.data.\*.ztna-tags-match-logic | numeric |  |   0 
action_result.data.\*.radius-mac-auth-bypass | numeric |  |   0 
action_result.data.\*.tcp-session-without-syn | numeric |  |   2 
action_result.data.\*.internet-service6-negate | numeric |  |   0 
action_result.data.\*.internet-service6-src-negate | numeric |  |   0 
action_result.status | string |  |   success 
action_result.message | string |  |   Total firewall policies: 1  Total firewall policies: 6 
action_result.summary.total firewall policies | numeric |  |   1  6 
action_result.parameter.level | string |  |   ADOM 
action_result.parameter.package | string |  |   default 
action_result.parameter.policy_name | string |  |   soar-footer-firewall-name 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.vpn_dst_node | string |  |  
action_result.data.\*.vpn_src_node | string |  |  
action_result.parameter.adom | string |  |   root 
action_result.summary.total_firewall_policies | numeric |  |   6  1 
action_result.data.\*.wanopt | numeric |  |   0 
action_result.data.\*.webcache | numeric |  |   0 
action_result.data.\*.disclaimer | numeric |  |   0 
action_result.data.\*.utm-status | numeric |  |   0 
action_result.data.\*.capture-packet | numeric |  |   0 
action_result.data.\*.webcache-https | numeric |  |   0 
action_result.data.\*.ssl-ssh-profile | string |  |   deep-inspection 
action_result.data.\*.timeout-send-rst | numeric |  |   0 
action_result.data.\*.auto-asic-offload | numeric |  |   1 
action_result.data.\*.passive-wan-health-measurement | numeric |  |   0 
action_result.parameter.package_path | string |  |   firewall-policy-path   

## action: 'create address'
Create a firewall address object

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**level** |  required  | Level Type | string | 
**adom** |  optional  | Administrative Domain Name | string | 
**address_type** |  required  | Type of address to create | string | 
**address_name** |  required  | Address name | string |  `fortimanager address name` 
**ip_netmask** |  optional  | IP address or IP address and netmask. Examples of valid formats: 1.1.1.1, 1.1.1.1/32, 1.1.1.1/255.255.255.255 | string |  `ip`  `netmask` 
**fqdn** |  optional  | Fully Qualified Domain Name | string | 
**policy_group_name** |  optional  | Name of policy group to be added to address | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.adom | string |  |   root 
action_result.parameter.ip_netmask | string |  `ip`  `netmask`  |   0.0.0.0 
action_result.parameter.policy_group_name | string |  |   group1 
action_result.data.\*.name | string |  `fortimanager address name`  |   test-fqdn 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Status: Successfully created address object  Object already exists 
action_result.parameter.fqdn | string |  |   gmail.com 
action_result.parameter.level | string |  |   Global  ADOM 
action_result.parameter.address_name | string |  `fortimanager address name`  |   test-fqdn  test-subnet1 
action_result.parameter.address_type | string |  |   FQDN  Subnet 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1  0 
action_result.summary.status | string |  |   Successfully created address object   

## action: 'delete address'
Delete firewall address object

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**level** |  required  | Level type | string | 
**adom** |  optional  | ADOM name | string | 
**address_name** |  required  | Name of address object to delete | string |  `fortimanager address name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.url | string |  |   /pm/config/adom/root/obj/firewall/address/subnet123 
action_result.data.\*.status.code | numeric |  |   0 
action_result.data.\*.status.message | string |  |   OK 
action_result.status | string |  |   success 
action_result.message | string |  |   Successfully deleted address object 
action_result.parameter.adom | string |  |   root 
action_result.parameter.level | string |  |   ADOM 
action_result.parameter.address_name | string |  `fortimanager address name`  |   subnet123 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.summary.status | string |  |   Successfully deleted address object   

## action: 'list addresses'
List firewall address objects

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**level** |  required  | Level type | string | 
**adom** |  optional  | ADOM name | string | 
**address_name** |  optional  | Name of address object to retrieve. If none is specified, this action will return all matching values. | string |  `fortimanager address name` 
**filter_by** |  optional  | Criteria to filter results by. Use the following format to specify filter: [["{attribute}", "==", "{value}"]] | string | 
**limit** |  optional  | Maximum number of addresses to return. Default is 0, which returns all results. | numeric | 
**offset** |  optional  | The starting point of the results to be returned. | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.oid | numeric |  |   5266 
action_result.data.\*.list | string |  |  
action_result.data.\*.name | string |  `fortimanager address name`  |   192.168.1.1 
action_result.data.\*.type | string |  |   ipmask 
action_result.data.\*.uuid | string |  |   827d7880-5599-51ee-0445-701f26e672f1 
action_result.data.\*.color | numeric |  |   0 
action_result.data.\*.dirty | string |  |   dirty 
action_result.data.\*.subnet | string |  `netmask`  `ip`  |   255.255.255.255 
action_result.data.\*.tagging | string |  |  
action_result.data.\*.obj-type | string |  |   ip 
action_result.data.\*.route-tag | numeric |  |   0 
action_result.data.\*.node-ip-only | string |  |   disable 
action_result.data.\*.allow-routing | string |  |   disable 
action_result.data.\*.clearpass-spt | string |  |   unknown 
action_result.data.\*.fabric-object | string |  |   disable 
action_result.data.\*.dynamic_mapping | string |  |  
action_result.data.\*.associated-interface | string |  |   any 
action_result.data.\*.sub-type | string |  |   ems-tag 
action_result.data.\*.comment | string |  |   IPv4 addresses of Fabric Devices. 
action_result.data.\*.end-ip | string |  `ip`  |   10.212.134.210 
action_result.data.\*.start-ip | string |  `ip`  |   10.212.134.200 
action_result.data.\*.fqdn | string |  |   gmail.com 
action_result.data.\*.cache-ttl | numeric |  |   0 
action_result.data.\*.policy-group | string |  |   test-group 
action_result.data.\*.macaddr | string |  |   00:11:22:33:44:58 
action_result.status | string |  |   success 
action_result.message | string |  |   Total address objects: 30 
action_result.summary.total_address_objects | numeric |  |   30 
action_result.parameter.adom | string |  |   root 
action_result.parameter.level | string |  |   ADOM 
action_result.parameter.address_name | string |  `fortimanager address name`  |  
action_result.parameter.filter_by | string |  |  
action_result.parameter.limit | numeric |  |   0 
action_result.parameter.offset | string |  |   0 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'update address'
Update existing firewall address object

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**level** |  required  | Level type | string | 
**adom** |  optional  | ADOM name | string | 
**address_name** |  required  | Name of address object to update | string |  `fortimanager address name` 
**subnet** |  optional  | Updated IP address and netmask (e.g. 0.0.0.0/32) to assign address object | string |  `ip`  `ipmask` 
**fqdn** |  optional  | Updated Fully Qualified Domain Name to assign address object | string | 
**policy_group_name** |  optional  | Name of policy group to be added to address | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.name | string |  `fortimanager address name`  |   test123  gmail 
action_result.status | string |  |   success 
action_result.message | string |  |   Successfully updated addresss object 
action_result.parameter.adom | string |  |   root 
action_result.parameter.level | string |  |   ADOM 
action_result.parameter.subnet | string |  `ip`  `ipmask`  |   1.2.3.4 
action_result.parameter.address_name | string |  `fortimanager address name`  |   test123  gmail 
action_result.parameter.fqdn | string |  |   \*gmail.com 
action_result.parameter.policy_group_name | string |  |   default 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.summary.status | string |  |   Successfully updated addresss object   

## action: 'block ip'
Block ADOM level IP addresses

Type: **contain**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**level** |  required  | Level type at which to block IP addresses | string | 
**adom** |  required  | ADOM name. Only required for 'ADOM' blocking of IP addresses | string | 
**package** |  required  | Policy package name | string | 
**package_path** |  optional  | The full folder path nested within the policy package | string | 
**policy_name** |  required  | Specific firewall policy name for blocking IP addresses | string | 
**address_group_name** |  required  | Specific address group name for for blocking IP addresses | string | 
**ip_addresses** |  required  | Comma-separated list of IP addresses to block | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.ips_blocked | string |  |   192.168.14.0/24 
action_result.data.\*.ips_already_blocked | string |  `ip`  |   192.168.4.4  192.168.20.0/24 
action_result.data.\*.created_address_objects | string |  |   192.168.14.0/24 
action_result.status | string |  |   success 
action_result.message | string |  |   Total ips blocked: 0, Total ips already blocked: 1, Total created address objects: 0, Total address object already exists: 0, Total address object failed: 0 
action_result.summary.total_ips_blocked | numeric |  |   1  0 
action_result.summary.total_ips_already_blocked | numeric |  |   1 
action_result.summary.total_address_object_failed | numeric |  |   0 
action_result.summary.total_created_address_objects | numeric |  |   1  0 
action_result.summary.total_address_object_already_exists | numeric |  |   0 
action_result.parameter.adom | string |  |   root 
action_result.parameter.level | string |  |   ADOM 
action_result.parameter.package | string |  |   example_policy_package 
action_result.parameter.policy_name | string |  |   example-fw_policy 
action_result.parameter.ip_addresses | string |  |   192.168.4.4,192.168.14.0/24  192.168.20.0/24 
action_result.parameter.address_group_name | string |  |   example_test_addr_grp 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.parameter.package_path | string |  |   my_package_folder   

## action: 'unblock ip'
Unblock ADOM level IP addresses

Type: **contain**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**level** |  required  | Level type at which to unblock IP addresses | string | 
**adom** |  required  | ADOM name. Only required for 'ADOM' unblocking of IP addresses | string | 
**package** |  required  | Policy package name | string | 
**package_path** |  optional  | The full folder path nested within the policy package | string | 
**policy_name** |  required  | Specific firewall policy name for unblocking IP addresses | string | 
**address_group_name** |  required  | Specific address group name for for unblocking IP addresses | string | 
**ip_addresses** |  required  | Comma-separated list of IP addresses to unblock | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.ips_unblocked | string |  |   192.168.14.0/24 
action_result.data.\*.ips_already_unblocked | string |  |   192.168.14.0/24 
action_result.status | string |  |   success 
action_result.message | string |  |   Total ips unblocked: 2, Total ips already unblocked: 0 
action_result.summary.total_ips_unblocked | numeric |  |   2  1 
action_result.summary.total_ips_already_unblocked | numeric |  |   0 
action_result.parameter.adom | string |  |   root 
action_result.parameter.level | string |  |   ADOM 
action_result.parameter.package | string |  |   example_policy_package 
action_result.parameter.policy_name | string |  |   example-fw_policy 
action_result.parameter.ip_addresses | string |  |   192.168.4.4,192.168.14.0/24  192.168.20.0/24 
action_result.parameter.address_group_name | string |  |   example_test_addr_grp 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.parameter.package_path | string |  |   my_package_folder   

## action: 'delete firewall policy'
Delete an ADOM firewall policy

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**level** |  required  | Level type at which to create the firewall policy. Choosing 'ADOM' (Administrative Domain Name) of the FortiManager server allows you to perform against that particular ADOM | string | 
**adom** |  optional  | ADOM name | string | 
**package** |  required  | The Policy Package name or full folder path of the firewall policy to delete | string | 
**policy_id** |  required  | Policy ID (can be retrieved from 'List Firewall Policies' action) to delete | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.url | string |  |   /pm/config/adom/root/pkg/default/firewall/policy/28  /pm/config/adom/root/pkg/default/firewall/policy/29 
action_result.data.\*.status.code | numeric |  |   0 
action_result.data.\*.status.message | string |  |   OK 
action_result.status | string |  |   success 
action_result.message | string |  |   Status: Successfully deleted firewall policy ID: 29 
action_result.summary.status | string |  |   Successfully deleted firewall policy ID: 29 
action_result.parameter.level | string |  |   ADOM 
action_result.parameter.package | string |  |   default 
action_result.parameter.policy_id | string |  |   28  29 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.parameter.adom | string |  |   root 