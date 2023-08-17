<<<<<<< HEAD
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
=======
# Define your constants here
>>>>>>> a58d594 (init commit)
