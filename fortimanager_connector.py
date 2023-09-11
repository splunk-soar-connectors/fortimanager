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

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from pyFMG.fortimgr import FortiManager

# Usage of the consts file is recommended
from fortimanager_consts import *
import ipaddress
import re
import requests
import json
import traceback
from bs4 import BeautifulSoup


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
                                        debug=True, use_ssl=self._verify_server_cert, disable_request_warnings=True)
        elif self._api_key:
            fmg_instance = FortiManager(self._host, apikey=self._api_key,
                                        debug=True, use_ssl=self._verify_server_cert, disable_request_warnings=True)
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

    def _handle_create_firewall_policy(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        fmg_instance = None
        level = param['level']
        pkg = param['package']
        data = {
                    'name': param['name'],
                    'srcintf': param['source_interface'],
                    'dstintf': param['destination_interface'],
                    'service': param['service'],
                    'srcaddr': param['source_address'],
                    'dstaddr': param['destination_address'],
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
            error_msg = response_data['status']['message']
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
                action_result.add_data(firewall_policy)
            summary = action_result.update_summary({})
            summary['total_firewall_policies'] = len(firewall_policies)
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.save_progress("Failed.")
            error_msg = firewall_policies['status']['message']
            return action_result.set_status(phantom.APP_ERROR, "Failed to retrieve firewall policies. Reason: {}".format(error_msg))

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")

        fmg_instance = None

        try:
            fmg_instance = self._login(action_result)
            self.save_progress("Login successful")

        except Exception as e:
            self.save_progress("Login failed")
            self.debug_print("Login failed: {}".format(self._get_error_msg_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, "Login failed: {}".format(self._get_error_msg_from_exception(e)))

        try:
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

    # URLs
    def _handle_list_blocked_urls(self, param):
        pass

    def _handle_block_url(self, param):
        pass

    def _handle_unblock_url(self, param):
        pass

    # Address Objects
    def _handle_list_addresses(self, param):
        pass

    def _handle_create_address(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        level = param['level']
        name = param['address_name']
        addr_type = param['address_type']

        adom = param.get('adom', 'root')
        policy_group = param.get('policy_group_name')

        if level == "ADOM":
            url = ADOM_IPV4_ADDRESS_ENDPOINT.format(adom=adom)

        fmg_instance = None
        data = {}

        try:
            fmg_instance = self._login(action_result)
            self.save_progress("login successful")

        except Exception as e:
            self.save_progress(CREATE_ADDRESS_FAILED_MESSAGE)
            self.debug_print("{}: {}".format(CREATE_ADDRESS_FAILED_MESSAGE, self._get_error_msg_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, None)

        try:
            fmg_instance.lock_adom(adom)

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
            self.save_progress(CREATE_ADDRESS_FAILED_MESSAGE)
            self.debug_print("{}: {}".format(CREATE_ADDRESS_FAILED_MESSAGE, self._get_error_msg_from_exception(e)))
            return action_result.set_status(phantom.APP_ERROR, self._get_error_msg_from_exception(e))

        finally:
            fmg_instance.unlock_adom(adom)
            fmg_instance.logout()

        if response_code == 0:
            action_result.add_data(response_data)
            return action_result.set_status(phantom.APP_SUCCESS, CREATE_ADDRESS_SUCCESS_MESSAGE)
        else:
            self.save_progress(CREATE_ADDRESS_FAILED_MESSAGE)
            return action_result.set_status(phantom.APP_ERROR, response_data['status']['message'])

    def _handle_update_address(self, param):
        pass

    def _handle_delete_address(self, param):
        pass

    # Web Filters
    def _handle_list_web_filters(self, param):
        pass

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'list_blocked_urls':
            ret_val = self._handle_list_blocked_urls(param)
        elif action_id == 'block_url':
            ret_val = self._handle_block_url(param)
        elif action_id == 'unblock_url':
            ret_val = self._handle_unblock_url(param)
        elif action_id == 'list_addresses':
            ret_val = self._handle_list_addresses(param)
        elif action_id == 'create_address':
            ret_val = self._handle_create_address(param)
        elif action_id == 'update_address':
            ret_val = self._handle_update_address(param)
        elif action_id == 'delete_address':
            ret_val = self._handle_delete_address(param)
        elif action_id == 'list_web_filters':
            ret_val = self._handle_list_web_filters(param)
        elif action_id == 'create_firewall_policy':
            ret_val = self._handle_create_firewall_policy(param)
        elif action_id == 'list_firewall_policies':
            ret_val = self._handle_list_firewall_policies(param)

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
