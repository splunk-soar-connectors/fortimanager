**Unreleased**

* Validate all action parameters interpolated into FortiManager JSON-RPC URL paths.
* Enable TLS certificate verification by default.
* Fail write actions when the FortiManager workspace commit is unsuccessful.
* Install modified firewall policy packages to assigned devices before reporting policy or IP containment success.
* Clarify that URL-filter changes remain staged until the policy package is installed.
* Fail policy installation cleanly when FortiManager does not return a task identifier.
* Stop acquiring an ADOM workspace lock for the read-only list addresses action.
