[comment]: # "File: README.md"
[comment]: # "Copyright (c) 2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
### ADOM Locking/Unlocking
Every write action in this connector performs a lock on the Administrative Domain (ADOM) specified in the action parameters before updating or creating a resource on the FortiManager asset. If the locking attempt fails, then the entire action will fail because a lock on the ADOM could not be obtained. This is either because another user or session is actively holding the lock on the ADOM or the ADOM specified in action parameters may be invalid. FortiManager requires ADOM locking before every write operation to ensure no two administrators can make changes simultaneously.

If the locking attempt is successful, then the API call to FortiManager will execute. Afterwards, as part of the action run, the ADOM lock will be released regardless of whether the action succeeds, fails, or exits on an exception.

If an action run is failing with the following error message:

`Failed to lock ADOM either because an exception occurred, or the ADOM has been locked by another user/session, or the ADOM entered does not exist.`

this means that the lock attempt failed. This most likely occurred because another administrator session is actively locking the ADOM. The solution is to just rerun the action. If on rerun the action is still failing with the message above, you can check the following:

Check that the ADOM name entered is correct and that the ADOM actually exists on he customer's FortiManager asset.
(If customer is willing) If session locking ADOM has been idle for a long time, kill the session via FortiManager CLI
(If customer is willing) Adjust the idle timeout settings and/or maximum number of concurrent admin logins on FortiManager.
To check if an exception occurred, check spawn.log for more info.

### List Addresses: filter_by parameter
The `filter_by` parameter in the `list addresses` action can take multiple filtering criteria. For example, to filter by multiple address types you can use the following: `[["type", "==", "subnet"],["type", "==", "fqdn"]]`.

Note that when using multiple criteria, only one needs to be true in order for the address object to be returned in the results. Therefore, using the previous example, the action will return address objects of both type `subnet` and `FQDN`.

When running the `list addresses` action adhoc, you can directly type in something like `[["type", "==", "subnet"],["type", "==", "fqdn"]]` into the `filter_by` parameter. However, if you are incorporating this action into a Classic Playbook, you must directly edit the action's code block in the playbook code editor and enclose the value in quotes, formatting the value like so: `"[[\"type\", \"==\", \"subnet\"]]"`. This issue does not persist for Modern Playbooks.
