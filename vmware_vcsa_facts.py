#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2018 Christian Kotte <christian.kotte@gmx.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

try:
    import json
except ImportError:
    import simplejson as json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_vcsa import request
from ansible.module_utils.pycompat24 import get_exception


# {
#   "value": {
#     "summary": "Patch for vCenter Server Appliance 6.5 with security fixes for PhotonOS",
#     "install_time": "2017-05-15T10:27:01 UTC",
#     "product": "VMware vCenter Server Appliance",
#     "build": "6671409",
#     "releasedate": "September 21, 2017",
#     "type": "vCenter Server with an external Platform Services Controller",
#     "version": "6.5.0.10100"
#   }
# }


def gather_vcsa_facts(module, vcsa_url, vcsa_username, vcsa_password, validate_certs):
    """Gather server facts"""

    facts = {}

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    try:
        (rc, session_id) = request(url=vcsa_url + "/com/vmware/cis/session", url_username=vcsa_username, url_password=vcsa_password,
                                   validate_certs=validate_certs, headers=headers, method='POST')
    except:
        err = get_exception()
        module.fail_json(msg="Failed to establish a session and authenticate. Error [%s]." % str(err))

    headers.update({'vmware-api-session-id': session_id['value']})

    try:
        (rc, system_version) = request(url=vcsa_url + "/appliance/system/version", url_username=vcsa_username, url_password=vcsa_password,
                                      validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get appliance version. Error [%s]." % str(err))

    facts['vcsa_product'] = system_version['value']['product'].strip()
    facts['vcsa_type'] = system_version['value']['type'].strip()
    facts['vcsa_build'] = system_version['value']['build'].strip()
    facts['vcsa_releasedate'] = system_version['value']['releasedate'].strip()
    facts['vcsa_version'] = system_version['value']['version'].strip()
    facts['vcsa_version_number'] = int(
        system_version['value']['version'].strip().split(".")[0] +
        system_version['value']['version'].strip().split(".")[1] +
        system_version['value']['version'].strip().split(".")[2]
        )
    facts['vcsa_install_time'] = system_version['value']['install_time'].strip()

    module.exit_json(ansible_facts=facts)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(required=True, type='str'),
            username=dict(default='root', type='str'),
            password=dict(required=True, type='str', no_log=True),
            validate_certs=dict(default=True, type='bool')
        ),
        supports_check_mode=True
    )

    vcsa_hostname = module.params['hostname']
    vcsa_username = module.params['username']
    vcsa_password = module.params['password']
    validate_certs = module.params['validate_certs']

    base_url = "/rest"
    vcsa_url = "https://" + vcsa_hostname + base_url

    gather_vcsa_facts(module, vcsa_url, vcsa_username, vcsa_password, validate_certs)


if __name__ == '__main__':
    main()
