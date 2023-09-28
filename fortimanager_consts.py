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
LOGIN_SUCCESS_MSG = 'login successful'
ERROR_MSG_UNAVAILABLE = 'Error message unavailable'

# ADOM Firewall Endpoints
ADOM_FIREWALL_ENDPOINT = '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy'
LIST_ADOM_FIREWALL_POLICY = '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy'
ADOM_ADDRESS_GROUP_ENDPOINT = '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}'
ADOM_ADD_ADDRESS_ENDPOINT = '/pm/config/adom/{adom}/obj/firewall/address'
CREATE_FIREWALL_FAILURE_MSG = 'Failed to create firewall policy'
UPDATE_FIREWALL_FAILURE_MSG = 'Failed to update firewall policy'
DELETE_FIREWALL_FAILURE_MSG = 'Failed to delete firewall policy'

# Global Firewall Endpoints TODO
# GLOBAL_FIREWALL_ENDPOINT = '/pm/config/global/pkg/{pkg}/global/{policy_type}/policy'
# LIST_GLOBAL_FIREWALL_POLICY = '/pm/config/global/pkg/{pkg}/global/{policy_type}/policy'

LOCK_SUCCESS_MSG = '{adom} ADOM locked successfully'
LOCK_FAILED_MSG = 'Failed to lock {adom} ADOM'
LOCK_RETRY_FAILED_MSG = 'Failed to lock {adom} ADOM after {retries} retries'

# Firewall addresses
GENERIC_ADOM_IPV4_ADDRESS_ENDPOINT = '/pm/config/adom/{adom}/obj/firewall/address'
SPECIFIC_ADOM_IPV4_ADDRESS_ENDPOINT = '/pm/config/adom/{adom}/obj/firewall/address/{name}'

CREATE_ADDRESS_SUCCESS_MSG = 'Successfully created address object'
CREATE_ADDRESS_FAILED_MSG = 'Failed to create address object'
DELETE_ADDRESS_SUCCESS_MSG = 'Successfully deleted address object'
DELETE_ADDRESS_FAILED_MSG = 'Failed to delete address object'
LIST_ADDRESSES_SUCCESS_MSG = 'Successfully retrieved address object(s)'
LIST_ADDRESSES_FAILED_MSG = 'Failed to retrieve address object(s)'
UPDATE_ADDRESS_SUCCESS_MSG = 'Successfully updated address object'
UPDATE_ADDRESS_FAILED_MSG = 'Failed to update address object'

ADDRESS_INVALID_ERROR_MSG = 'The provided address is either invalid or not supported'
FILTER_ADDRESS_ERROR_MSG = 'The provided filter string is malformed. The proper format is \"<field>\" <comparison operator> \"<value>\"'

FILTER_ADDRESS_REGEX = r"^\"(?P<field>[a-z]+)\"\s*(?P<comp>(\=|\>|\<|\>\=|\<\=|\=\=))\s*\"(?P<value>.+)\""

# Web filter endpoints for block/unblock urls
ADOM_WEB_FILTER_PROFILE_ENDPOINT = '/pm/config/adom/{adom}/obj/webfilter/profile'
ADOM_URL_FILTER_ENDPOINT = '/pm/config/adom/{adom}/obj/webfilter/urlfilter'

# URLs
ADOM_BLOCK_URL_SUCCESS_MSG = 'Successfully blocked URL'
ADOM_BLOCK_URL_FAILED_MSG = 'Failed to block URL'
ADOM_BLOCK_URL_WILDCARD_ERROR_MSG = "Wildcard URL must include a '*'."
ADOM_BLOCK_URL_EXISTS_ERROR_MSG = 'URL already exists in URL filter list'
ADOM_UNBLOCK_URL_SUCCESS_MSG = 'Successfully unblocked URL'
ADOM_UNBLOCK_URL_FAILED_MSG = 'Failed to unblock URL'

ADOM_WEB_FILTER_PROFILE_DNE_ERROR_MSG = 'Web filter profile {web_filter_profile_name} does not exist'
ADOM_WEB_FILTER_PROFILE_MALFORMED_ERROR_MSG = 'Malformed web filter profile'
ADOM_ADD_URL_FILTER_PROFILE_ERROR_MSG = 'Failed to add URL filter profile to web profile'
ADOM_CREATE_URL_FILTER_PROFILE_ERROR_MSG = 'Failed to create a new URL filter profile'
ADOM_URL_DNE_WEB_FILTER_PROFILE_ERROR_MSG = 'URL does not exist in URL filter list'

# Misc Messages
INVALID_LEVEL_ERROR_MSG = 'Invalid level provided. Please select "ADOM" from the dropdown.'