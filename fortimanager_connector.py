# File: fortimanager_connector.py
#
# Copyright (c) 2023 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import ipaddress
import json
import re
import traceback

# Phantom App imports
import phantom.app as phantom
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from pyFMG.fortimgr import FortiManager

# Usage of the consts file is recommended
from fortimanager_consts import *


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class FortimanagerConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(FortimanagerConnector, self).__init__()

        self._state = None

        self._base_url = None
        self._verify_server_cert = False
        self._host = None
        self._username = None
        self._password = None

        self._api_key = None

    def _login(self, action_result):
        if self._username and self._password:
            fmg_instance = FortiManager(self._host, self._username, self._password,
                                        debug=False, verify_ssl=self._verify_server_cert, disable_request_warnings=True)
        elif self._api_key:
            fmg_instance = FortiManager(self._host, apikey=self._api_key,
                                        debug=False, verify_ssl=self._verify_server_cert, disable_request_warnings=True)
        else:
            raise Exception("The asset configuration requires either an API key or a username and password.")
        fmg_instance.login()
        return fmg_instance

    def _format_url(self, url):
        if not re.match('(?:http|https)://', url):
            return 'https://{}'.format(url)
        return url

    def _get_error_msg_from_exception(self, e):

        error_code = None
        error_message = ERROR_MSG_UNAVAILABLE

        self.error_print(traceback.format_exc())

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception as e:
            self.error_print("Error occurred while fetching exception information. Details: {}".format(str(e)))

        if not error_code:
            error_text = "Error Message: {}".format(error_message)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_message)

        return error_text

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")
        fmg_instance = None

        try:
            fmg_instance = self._login(action_result)
            self.save_progress("Obtaining system status")
            response_code, response_data = fmg_instance.get('sys/status')
        except Exception as e:
            error_msg = self._get_error_msg_from_exception(e)
            self.save_progress("Test Connectivity Failed.")
            return action_result.set_status(phantom.APP_ERROR, error_msg)
        finally:
            fmg_instance.logout()

        if response_code == 0:
            self.save_progress("Test Connectivity Passed")
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.save_progress("Test Connectivity Failed.")
            return action_result.set_status(phantom.APP_ERROR, "Test Connectivity Failed")

    def _handle_create_firewall_policy(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        fmg_instance = None
        level = param['level']
        pkg = param['package']
        data = {
                    'name': param['name'],
                    'srcintf': self._get_param_list(param['source_interface']),
                    'dstintf': self._get_param_list(param['destination_interface']),
                    'service': self._get_param_list(param['service']),
                    'srcaddr': self._get_param_list(param['source_address']),
                    'dstaddr': self._get_param_list(param['destination_address']),
                    'action': param['action'],
                    'status': param['status'],
                    'inspection-mode': param['inspection_mode'],
                    'logtraffic': param['log_traffic'],
                    'schedule': param['schedule']
                }
        if level == 'ADOM':
            adom = param.get('adom')
            if not adom:
                adom = 'root'
            endpoint = ADOM_FIREWALL_ENDPOINT.format(adom=adom, pkg=pkg)
        # Global Feature TODO
        # elif level == 'Global':
        #     adom = 'global'
        #     policy_type = param['policy_type']
        #     endpoint = GLOBAL_FIREWALL_ENDPOINT.format(pkg=pkg, policy_type=policy_type)

        try:
            fmg_instance = self._login(action_result)
            fmg_instance.lock_adom(adom)
            response_code, response_data = fmg_instance.add(endpoint, **data)
            fmg_instance.commit_changes(adom)
        except Exception as e:
            error_msg = self._get_error_msg_from_exception(e)
            self.save_progress("Create Firewall Policy action failed")
            self.debug_print("Create Firewall Policy action failed: {}".format(error_msg))
            fmg_instance.unlock_adom(adom)
            fmg_instance.logout()
            return action_result.set_status(phantom.APP_ERROR, None)
        fmg_instance.unlock_adom(adom)
        fmg_instance.logout()
        if response_code == 0:
            action_result.add_data(response_data)
            summary = action_result.update_summary({})
            summary['status'] = 'Successfully added firewall policy'
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.save_progress("Failed.")
            if response_data.get('status'):
                error_msg = response_data['status'].get('message', 'Unknown')
            else:
                error_msg = 'Unknown'
            return action_result.set_status(phantom.APP_ERROR, "Failed to create firewall policy. Reason: {}".format(error_msg))

    def _handle_list_firewall_policies(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        fmg_instance = None
        level = param['level']
        pkg = param.get('package')
        package_path = param.get('package_path')
        policy_name = param.get('policy_name')
        if pkg and package_path:
            pkg += '/' + package_path
        if level == 'ADOM':
            adom = param.get('adom')
            if not adom:
                adom = 'root'
            endpoint = LIST_ADOM_FIREWALL_POLICY.format(adom=adom, pkg=pkg)
        # Global Feature TODO
        # elif level == 'Global':
        #     endpoint = LIST_GLOBAL_FIREWALL_POLICY.format(pkg=pkg, policy_type=param.get('policy_type'))

        try:
            fmg_instance = self._login(action_result)
            if policy_name:
                data = {
                    'filter': [
                        [
                            "name", "==", "{}".format(policy_name)
                        ]
                    ]}
                response_code, firewall_policies = fmg_instance.get(endpoint, **data)
            else:
                response_code, firewall_policies = fmg_instance.get(endpoint)
        except Exception as e:
            error_msg = self._get_error_msg_from_exception(e)
            self.save_progress("List Firewall Policies action failed")
            self.debug_print("List Firewall Policies action failed: {}".format(error_msg))
            fmg_instance.logout()
            return action_result.set_status(phantom.APP_ERROR, None)
        fmg_instance.logout()
        if response_code == 0:
            for firewall_policy in firewall_policies:
                if firewall_policy.get('action') == 0:
                    firewall_policy['action'] = 'accept'
                elif firewall_policy.get('action') == 1:
                    firewall_policy['action'] = 'deny'
                elif firewall_policy.get('action') == 2:
                    firewall_policy['action'] = 'IPsec'
                action_result.add_data(firewall_policy)
            summary = action_result.update_summary({})
            summary['total_firewall_policies'] = len(firewall_policies)
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.save_progress("Failed.")
            if firewall_policies.get('status'):
                error_msg = firewall_policies['status'].get('message', 'Unknown')
            else:
                error_msg = 'Unknown'
            return action_result.set_status(phantom.APP_ERROR, "Failed to retrieve firewall policies. Reason: {}".format(error_msg))

    def _handle_delete_firewall_policy(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        fmg_instance = None
        level = param['level']
        pkg = param['package']
        policy_id = param['policy_id']
        if level == 'ADOM':
            adom = param.get('adom')
            if not adom:
                adom = 'root'
            endpoint = ADOM_FIREWALL_ENDPOINT.format(adom=adom, pkg=pkg) + '/' + policy_id
        # Global Feature TODO
        # elif level == 'Global':
        #     adom = 'global'
        #     policy_type = param['policy_type']
        #     endpoint = GLOBAL_FIREWALL_ENDPOINT.format(pkg=pkg, policy_type=policy_type)
        try:
            fmg_instance = self._login(action_result)
            fmg_instance.lock_adom(adom)
            response_code, response_data = fmg_instance.delete(endpoint)
            fmg_instance.commit_changes(adom)
        except Exception as e:
            error_msg = self._get_error_msg_from_exception(e)
            self.save_progress("Delete Firewall Policy action failed")
            self.debug_print("Delete Firewall Policy action failed: {}".format(error_msg))
            fmg_instance.unlock_adom(adom)
            fmg_instance.logout()
            return action_result.set_status(phantom.APP_ERROR, None)
        fmg_instance.unlock_adom(adom)
        fmg_instance.logout()
        if response_code == 0:
            action_result.add_data(response_data)
            summary = action_result.update_summary({})
            summary['status'] = 'Successfully deleted firewall policy ID: {}'.format(policy_id)
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.save_progress("Failed.")
            if response_data.get('status'):
                error_msg = response_data['status'].get('message', 'Unknown')
            else:
                error_msg = 'Unknown'
            return action_result.set_status(phantom.APP_ERROR, "Failed to delete firewall policy. Reason: {}".format(error_msg))

    def _get_param_list(self, param_list):
        # param_list can be a string or a list
        if isinstance(param_list, list):
            pass
        elif isinstance(param_list, str):
            param_list = [x.strip() for x in param_list.split(',')]
        return param_list

    # URLs
    def _handle_list_blocked_urls(self, param):
        pass

    def _handle_block_url(self, param):
        pass

    def _handle_unblock_url(self, param):
        pass

    # Address Objects
    def _handle_list_addresses(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        level = param['level']

        name = param.get('address_name')
        filter_by = param.get('filter_by')
        limit = param.get('limit', 0)
        offset = param.get('offset', 0)

        if level == "ADOM":
            adom = param.get('adom', 'root')
            if name:
                url = SPECIFIC_ADOM_IPV4_ADDRESS_ENDPOINT.format(adom=adom, name=name)
            else:
                url = GENERIC_ADOM_IPV4_ADDRESS_ENDPOINT.format(adom=adom)

        fmg_instance = None
        get_params = {}

        try:
            fmg_instance = self._login(action_result)
            self.save_progress("login successful")

        except Exception as e:
            self.save_progress(CREATE_ADDRESS_FAILED_MSG)
            self.debug_print("{}: {}".format(CREATE_ADDRESS_FAILED_MSG, self._get_error_msg_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, None)

        try:
            if name:
                response_code, response_data = fmg_instance.get(url)
            else:
                get_params['range'] = [offset, limit]

                if filter_by:
                    get_params['filter'] = json.loads(filter_by)

                response_code, response_data = fmg_instance.get(url, **get_params)

        except Exception as e:
            self.save_progress(LIST_ADDRESSES_FAILED_MSG)
            self.debug_print("{}: {}".format(LIST_ADDRESSES_FAILED_MSG, self._get_error_msg_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, self._get_error_msg_from_exception(e))

        finally:
            fmg_instance.logout()

        if response_code == 0:
            if type(response_data) == list:
                for addr in response_data:
                    action_result.add_data(addr)

                summary = {'total_address_objects_returned': len(response_data)}
                action_result.update_summary(summary)
            else:
                action_result.add_data(response_data)
                summary = {'total_address_objects_returned': 1}
                action_result.update_summary(summary)

            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.save_progress(LIST_ADDRESSES_FAILED_MSG)
            return action_result.set_status(phantom.APP_ERROR, response_data['status']['message'])

    def _handle_create_address(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        level = param['level']
        name = param['address_name']
        addr_type = param['address_type']

        policy_group = param.get('policy_group_name')

        if level == "ADOM":
            adom = param.get('adom', 'root')
            url = GENERIC_ADOM_IPV4_ADDRESS_ENDPOINT.format(adom=adom)

        fmg_instance = None
        data = {}

        try:
            fmg_instance = self._login(action_result)
            self.save_progress("login successful")

        except Exception as e:
            self.save_progress(CREATE_ADDRESS_FAILED_MSG)
            self.debug_print("{}: {}".format(CREATE_ADDRESS_FAILED_MSG, self._get_error_msg_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, None)

        # acquire lock
        try:
            lock_code, lock_data = fmg_instance.lock_adom(adom)

            if lock_code == 0:
                self.save_progress(LOCK_SUCCESS_MSG.format(adom=adom))
            else:
                self.save_progress(LOCK_FAILED_MSG.format(adom=adom))
                fmg_instance.logout()
                return action_result.set_status(phantom.APP_ERROR, LOCK_FAILED_MSG.format(adom=adom))

        except Exception as e:
            self.save_progress(CREATE_ADDRESS_FAILED_MSG)
            self.debug_print("{}: {}".format(CREATE_ADDRESS_FAILED_MSG, LOCK_FAILED_MSG.format(adom=adom)))
            fmg_instance.logout()
            return action_result.set_status(phantom.APP_ERROR, self._get_error_msg_from_exception(e))

        # then actually create address
        try:
            data['name'] = name

            if addr_type == 'Subnet':
                ip_addr = param.get('subnet')
                data['subnet'] = ipaddress.IPv4Interface(ip_addr).with_netmask.split('/')
                data['type'] = 'ipmask'

            elif addr_type == 'FQDN':
                data['fqdn'] = param.get('fqdn')
                data['type'] = 'fqdn'

            if policy_group:
                data['policy-group'] = policy_group

            response_code, response_data = fmg_instance.add(url, **data)
            fmg_instance.commit_changes(adom)

        except Exception as e:
            self.save_progress(CREATE_ADDRESS_FAILED_MSG)
            self.debug_print("{}: {}".format(CREATE_ADDRESS_FAILED_MSG, self._get_error_msg_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, self._get_error_msg_from_exception(e))

        finally:
            fmg_instance.unlock_adom(adom)
            fmg_instance.logout()

        if response_code == 0:
            action_result.add_data(response_data)
            return action_result.set_status(phantom.APP_SUCCESS, CREATE_ADDRESS_SUCCESS_MSG)
        else:
            self.save_progress(CREATE_ADDRESS_FAILED_MSG)
            return action_result.set_status(phantom.APP_ERROR, response_data['status']['message'])

    def _handle_update_address(self, param):
        pass

    def _handle_delete_address(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        level = param['level']
        name = param['address_name']

        if level == "ADOM":
            adom = param.get('adom', 'root')
            url = SPECIFIC_ADOM_IPV4_ADDRESS_ENDPOINT.format(adom=adom, name=name)

        fmg_instance = None

        try:
            fmg_instance = self._login(action_result)
            self.save_progress("login successful")

        except Exception as e:
            self.save_progress(DELETE_ADDRESS_FAILED_MSG)
            self.debug_print("{}: {}".format(DELETE_ADDRESS_FAILED_MSG, self._get_error_msg_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, None)

        # acquire lock
        try:
            lock_code, lock_data = fmg_instance.lock_adom(adom)

            if lock_code == 0:
                self.save_progress(LOCK_SUCCESS_MSG.format(adom=adom))
            else:
                self.save_progress(LOCK_FAILED_MSG.format(adom=adom))
                fmg_instance.logout()
                return action_result.set_status(phantom.APP_ERROR, LOCK_FAILED_MSG.format(adom=adom))

        except Exception as e:
            self.save_progress(DELETE_ADDRESS_FAILED_MSG)
            self.debug_print("{}: {}".format(DELETE_ADDRESS_FAILED_MSG, LOCK_FAILED_MSG.format(adom=adom)))
            fmg_instance.logout()
            return action_result.set_status(phantom.APP_ERROR, self._get_error_msg_from_exception(e))

        # then actually delete address
        try:
            response_code, response_data = fmg_instance.delete(url)
            fmg_instance.commit_changes(adom)

        except Exception as e:
            self.save_progress(DELETE_ADDRESS_FAILED_MSG)
            self.debug_print("{}: {}".format(DELETE_ADDRESS_FAILED_MSG, self._get_error_msg_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, self._get_error_msg_from_exception(e))

        finally:
            fmg_instance.unlock_adom(adom)
            fmg_instance.logout()

        if response_code == 0:
            action_result.add_data(response_data)
            summary = {'status': DELETE_ADDRESS_SUCCESS_MSG}
            action_result.update_summary(summary)
            return action_result.set_status(phantom.APP_SUCCESS, DELETE_ADDRESS_SUCCESS_MSG)

        else:
            self.save_progress(DELETE_ADDRESS_FAILED_MSG)
            return action_result.set_status(phantom.APP_ERROR, response_data['status']['message'])

    # Web Filters
    def _handle_list_web_filters(self, param):
        pass

    def _get_ip_list(self, ip_list):
        # IP list can be a string or a list
        if isinstance(ip_list, list):
            pass
        elif isinstance(ip_list, str):
            ip_list = ip_list.strip(' ').split(',')
        return ip_list

    def _get_current_policy_ips(self, fmg_instance, adom, package, policy_name):
        policy_endpoint = ADOM_FIREWALL_ENDPOINT.format(adom=adom, pkg=package)
        filter = ["name", "==", policy_name]

        response_code, response_data = fmg_instance.get(policy_endpoint, filter=filter)
        if response_code == 0 and response_data[0]:
            current_policy = response_data[0]
            if not current_policy:
                return False
            source_block_ips = current_policy.get('srcaddr', [])
            destination_block_ips = current_policy.get('dstaddr', [])
            already_blocked_ips = source_block_ips + destination_block_ips
            return already_blocked_ips
        else:
            return False

    def _get_address_group(self, fmg_instance, address_group_name, adom):
        address_group_endpoint = ADOM_ADDRESS_GROUP_ENDPOINT.format(adom=adom, addrgrp=address_group_name)
        response_code, address_group = fmg_instance.get(address_group_endpoint)
        if response_code == 0:
            return address_group
        else:
            return False

    def _create_address_objects(self, fmg_instance, adom, ip_block_list):
        add_address_endpoint = ADOM_ADD_ADDRESS_ENDPOINT.format(adom=adom)

        result = { 'created_address_objects': [],
                   'address_object_already_exists': [],
                   'address_object_failed': [] }

        for ip in ip_block_list:
            ip_object = vars(ipaddress.IPv4Network(ip))

            ip_address = str(ip_object.get('network_address'))
            ip_netmask = str(ip_object.get('netmask'))
            ip_payload = [{'name': ip, 'subnet': [ip_address, ip_netmask]}]
            data = {"data": ip_payload}

            response_code, response_data = fmg_instance.add(add_address_endpoint, data)
            status_message = None
            if 'status' in response_data:
                status_message = response_data['status'].get('message')

            if response_code == 0:
                result['created_address_objects'].append(ip)
            elif status_message == 'Object already exists':
                result['address_object_already_exists'].append(ip)
            else:
                result['address_object_failed'].append((ip, status_message))

        return result

    def _update_address_group(self, fmg_instance, address_group_name, adom, ip_block_list):
        address_group_endpoint = ADOM_ADDRESS_GROUP_ENDPOINT.format(adom=adom, addrgrp=address_group_name)
        group_payload = {'member': ip_block_list}
        data = group_payload

        response_code, failed_ips = fmg_instance.update(address_group_endpoint, data=data)
        if response_code == 0:
            return failed_ips
        else:
            return False

    def _handle_block_ip(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        level = param['level']
        adom = None

        if level == 'ADOM':
            adom = param.get('adom')
            if not adom:
                adom = 'root'

        package = param['package']
        package_path = param.get('package_path')

        if package and package_path:
            package = '{0}/{1}'.format(package_path, package)

        policy_name = param['policy_name']
        address_group_name = param['address_group_name']
        ip_addresses_to_block = self._get_ip_list(param['ip_addresses'])

        already_blocked_ips = []
        ip_block_list = []

        result = { 'ips_blocked': [],
                   'ips_already_blocked': [] }

        fmg_instance = None

        try:
            fmg_instance = self._login(action_result)
            fmg_instance.lock_adom(adom)

            # get the current policy IP addresses
            already_blocked_ips = self._get_current_policy_ips(fmg_instance, adom, package, policy_name)
            if isinstance(already_blocked_ips, bool):
                return action_result.set_status(phantom.APP_ERROR, 'Policy does not exist')

            if address_group_name not in already_blocked_ips:
                return action_result.set_status(
                    phantom.APP_ERROR, 'Address group {} does not exist in this policy'.format(address_group_name))

            # get the address group
            address_group = self._get_address_group(fmg_instance, address_group_name, adom)
            if isinstance(address_group, bool):
                return action_result.set_status(phantom.APP_ERROR, 'Error retrieving address group {}'.format(address_group_name))

            address_group_members = address_group.get('member')

            # check to see if IPs to block are in the group
            for ip in ip_addresses_to_block:
                if ip not in address_group_members:
                    ip_block_list.append(ip)
                    result['ips_blocked'].append(ip)
                else:
                    result['ips_already_blocked'].append(ip)

            # create the address objects to add
            create_address_objects_result = self._create_address_objects(fmg_instance, adom, ip_block_list)

            # add original members back for update
            ip_block_list.extend(address_group_members)

            # update the address group with new list of ips
            response_data = self._update_address_group(fmg_instance, address_group_name, adom, ip_block_list)
            if isinstance(response_data, bool):
                return action_result.set_status(phantom.APP_ERROR, "Failed to update address group with block IP objects")

            action_result.add_data(result)
            action_result.add_data(create_address_objects_result)

            summary = action_result.update_summary({})
            for key in result:
                summary[key] = result[key]

            fmg_instance.commit_changes(adom)

            return action_result.set_status(phantom.APP_SUCCESS, "Block IP action successful")

        except Exception as e:
            self.save_progress("ADOM level block IP action failed")
            self.debug_print("ADOM level block IP action failed: {}".format(self._get_error_msg_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, self._get_error_msg_from_exception(e))

        finally:
            fmg_instance.unlock_adom(adom)
            fmg_instance.logout()

    def _handle_unblock_ip(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        level = param['level']
        adom = None

        if level == 'ADOM':
            adom = param.get('adom')
            if not adom:
                adom = 'root'

        package = param['package']
        package_path = param.get('package_path')

        if package and package_path:
            package = '{0}/{1}'.format(package_path, package)

        policy_name = param['policy_name']
        address_group_name = param['address_group_name']
        ip_addresses_to_unblock = self._get_ip_list(param['ip_addresses'])

        currently_blocked_ips = []
        ip_unblock_list = []

        result = { 'ips_unblocked': [],
                   'ips_already_unblocked': [] }

        fmg_instance = None

        try:
            fmg_instance = self._login(action_result)
            fmg_instance.lock_adom(adom)

            # first get the current policy IP addresses
            currently_blocked_ips = self._get_current_policy_ips(fmg_instance, adom, package, policy_name)

            if address_group_name not in currently_blocked_ips:
                return action_result.set_status(
                    phantom.APP_ERROR, 'Address group {} does not exist in this policy'.format(address_group_name))

            # get the address group
            address_group = self._get_address_group(fmg_instance, address_group_name, adom)
            if isinstance(address_group, bool):
                return action_result.set_status(phantom.APP_ERROR, 'Error retrieving address group {}'.format(address_group_name))

            address_group_members = address_group.get('member')
            ip_unblock_list.extend(address_group_members)

            # check to see if IPs to unblock are in the group
            for ip in ip_addresses_to_unblock:
                if ip in address_group_members:
                    ip_unblock_list.remove(ip)
                    result['ips_unblocked'].append(ip)
                else:
                    result['ips_already_unblocked'].append(ip)

            # update the address group with new list of ips
            response_data = self._update_address_group(fmg_instance, address_group_name, adom, ip_unblock_list)
            if isinstance(response_data, bool):
                return action_result.set_status(phantom.APP_ERROR, "Failed to update address group with unblock IP objects")

            action_result.add_data(result)

            summary = action_result.update_summary({})
            for key in result:
                summary["total_{}".format(key)] = len(result[key])

            fmg_instance.commit_changes()

            return action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            self.save_progress("ADOM level unblock IP action failed")
            self.debug_print("ADOM level unblock IP action failed: {}".format(self._get_error_msg_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, self._get_error_msg_from_exception(e))

        finally:
            fmg_instance.unlock_adom(adom)
            fmg_instance.logout()

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'create_address':
            ret_val = self._handle_create_address(param)
        elif action_id == 'delete_address':
            ret_val = self._handle_delete_address(param)
        elif action_id == 'create_firewall_policy':
            ret_val = self._handle_create_firewall_policy(param)
        elif action_id == 'list_firewall_policies':
            ret_val = self._handle_list_firewall_policies(param)
        elif action_id == 'block_ip':
            ret_val = self._handle_block_ip(param)
        elif action_id == 'unblock_ip':
            ret_val = self._handle_unblock_ip(param)
        elif action_id == 'delete_firewall_policy':
            ret_val = self._handle_delete_firewall_policy(param)

        return ret_val

    def initialize(self):
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._host = config['url'].replace('http://', '').replace('https://', '')

        self._api_key = config.get('api_key')
        self._username = config.get('username')
        self._password = config.get('password')

        self._base_url = self._format_url(self._host)
        self._verify_server_cert = config.get('verify_server_cert', False)

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = FortimanagerConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = FortimanagerConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':

    import sys

    import pudb

    pudb.set_trace()
    if len(sys.argv) < 2:
        print('No test json specified as input')
        sys.exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = FortimanagerConnector()
        connector.print_progress_message = True
        return_value = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(return_value), indent=4))
    sys.exit(0)