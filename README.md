[comment]: # "Auto-generated SOAR connector documentation"
# FortiManager

Publisher: Splunk  
Connector Version: 1.0.1  
Product Vendor: Fortinet  
Product Name: FortiManager  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.0.0  

FortiManager

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

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**level** |  required  | Level type at which to create the firewall policy. Choosing 'ADOM' (Administrative Domain Name) of the FortiManager server allows you to perform against that particular ADOM | string | 
**adom** |  optional  | ADOM name | string | 
**package** |  required  | The Policy Package name or full folder path to create the firewall policy within | string | 
**name** |  required  | Policy name to create | string | 
**source_interface** |  required  | Incoming (ingress) interface to specify for the firewall policy | string | 
**destination_interface** |  required  | Outgoing (egress) interface to specify for the firewall policy | string | 
**source_address** |  required  | Source IPv4 Address and address group names to specify for the firewall policy | string | 
**destination_address** |  required  | Destination IPv4 Address and address group names to specify for the firewall policy | string | 
**action** |  required  | Policy action to specify for the firewall policy. Accept: Allows sessions that match the firewall policy. Deny: Blocks sessions that match the firewall policy. IPSec: Firewall policy becomes a policy-based IPsec VPN policy | string | 
**status** |  required  | 'Enable' or 'Disable' this firewall policy on your FortiManager instance | string | 
**schedule** |  required  | Name for the schedule to be associated with the firewall policy (e.g. always, none) | string | 
**service** |  required  | Service and Service group names to create for the firewall policy | string | 
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
action_result.data.\*.uuid | string |  |   c33e106e-4117-51ee-1771-7827f531ca41  987cb312-3d16-51ee-a38e-2a5f3b237725 
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
action_result.data.\*.dstintf | string |  |   any 
action_result.data.\*.obj seq | numeric |  |   1 
action_result.data.\*.rtp-nat | numeric |  |   0 
action_result.data.\*.service | string |  |   ALL 
action_result.data.\*.srcaddr | string |  |   all 
action_result.data.\*.srcintf | string |  |   any 
action_result.data.\*.policyid | numeric |  |   1074741825  3 
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
action_result.summary.total_firewall_policies | numeric |  |   6 