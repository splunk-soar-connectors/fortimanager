# File: fortimanager_consts.py
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

# Login information
ACTION_PATH = '/jsonrpc'
LOGIN_URL = '/sys/login/user'
TEST_CONNECTIVITY_URL = '/sys/status'

LOGIN_ERROR_MSG = 'login failed'
ERROR_MSG_UNAVAILABLE = 'Error message unavailable'

# ADOM Firewall Endpoints
ADOM_FIREWALL_ENDPOINT = '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy'
LIST_ADOM_FIREWALL_POLICY = '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy'
# Global Firewall Endpoints TODO
# GLOBAL_FIREWALL_ENDPOINT = '/pm/config/global/pkg/{pkg}/global/{policy_type}/policy'
# LIST_GLOBAL_FIREWALL_POLICY = '/pm/config/global/pkg/{pkg}/global/{policy_type}/policy'

LOCK_SUCCESS_MSG = '{adom} ADOM locked successfully'
LOCK_FAILED_MSG = 'Failed to lock {adom} ADOM'
LOCK_RETRY_FAILED_MSG = 'Failed to lock {adom} ADOM after {retries} retries'

# Firewall addresses
CREATE_ADOM_IPV4_ADDRESS_ENDPOINT = '/pm/config/adom/{adom}/obj/firewall/address'
DELETE_ADOM_IPV4_ADDRESS_ENDPOINT = '/pm/config/adom/{adom}/obj/firewall/address/{name}'

CREATE_ADDRESS_SUCCESS_MSG = 'Successfully created address object'
CREATE_ADDRESS_FAILED_MSG = 'Failed to create address object'
DELETE_ADDRESS_SUCCESS_MSG = 'Successfully deleted address object'
DELETE_ADDRESS_FAILED_MSG = 'Failed to delete address object'

ADDRESS_INVALID_ERROR_MSG = 'The provided address is either invalid or not supported'
FILTER_ADDRESS_ERROR_MSG = 'The provided filter string is malformed. The proper format is \"<field>\" <comparison operator> \"<value>\"'

FILTER_ADDRESS_REGEX = r"^\"(?P<field>[a-z]+)\"\s*(?P<comp>(\=|\>|\<|\>\=|\<\=|\=\=))\s*\"(?P<value>.+)\""
