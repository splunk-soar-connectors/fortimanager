
# Login information
ACTION_PATH = '/jsonrpc'
LOGIN_URL = '/sys/login/user'
TEST_CONNECTIVITY_URL = '/sys/status'

LOGIN_ERROR_MSG = 'login failed'
ERROR_MSG_UNAVAILABLE = 'Error message unavailable'

# Firewall Endpoints
ADOM_FIREWALL_ENDPOINT = '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy'
GLOBAL_FIREWALL_ENDPOINT = '/pm/config/global/pkg/{pkg}/global/{policy_type}/policy'
LIST_ADOM_FIREWALL_POLICY = '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy'
LIST_GLOBAL_FIREWALL_POLICY = '/pm/config/global/pkg/{pkg}/global/{policy_type}/policy'
