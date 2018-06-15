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


# console-based controlled CLI (TTY1): /appliance/access/consolecli
# Direct Console User Interface (DCUI TTY2): /appliance/access/dcui
# SSH-based controlled CLI: /appliance/access/ssh
# access to BASH from within the controlled CLI: /appliance/access/shell


def check_vcsa_access(module, vcsa_url, vcsa_username, vcsa_password, console_access, dcui_access, ssh_access, shell_access, validate_certs):
    """Inform the user what would change if the module were run"""

    would_be_changed = []
    changed_status = False

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

    # console-based controlled CLI (TTY1) access
    try:
        (rc, consolecli) = request(url=vcsa_url + "/appliance/access/consolecli", url_username=vcsa_username, url_password=vcsa_password,
                                      validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get consolecli state. Error [%s]." % str(err))

    if consolecli['value'] != console_access:
        would_be_changed.append('console')
        changed_status = True

    # Direct Console User Interface (DCUI TTY2) access
    try:
        (rc, dcui) = request(url=vcsa_url + "/appliance/access/dcui", url_username=vcsa_username, url_password=vcsa_password,
                                      validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get DCUI state. Error [%s]." % str(err))

    if dcui['value'] != dcui_access:
        would_be_changed.append('dcui')
        changed_status = True

    # SSH-based controlled CLI access
    try:
        (rc, ssh) = request(url=vcsa_url + "/appliance/access/ssh", url_username=vcsa_username, url_password=vcsa_password,
                                      validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get SSH state. Error [%s]." % str(err))

    if ssh['value'] != ssh_access:
        would_be_changed.append('ssh')
        changed_status = True

    # access to BASH from within the controlled CLI
    try:
        (rc, shell) = request(url=vcsa_url + "/appliance/access/shell", url_username=vcsa_username, url_password=vcsa_password,
                                      validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get BASH shell state. Error [%s]." % str(err))

    if shell['value']['enabled'] != shell_access:
        would_be_changed.append('shell')
        changed_status = True

    if changed_status:
        if len(would_be_changed) > 2:
            message = ', '.join(would_be_changed[:-1]) + ', and ' + str(would_be_changed[-1]) + ' would be changed.'
        elif len(would_be_changed) == 2:
            message = ' and '.join(would_be_changed) + ' would be changed.'
        elif len(would_be_changed) == 1:
            message = would_be_changed[0] + ' would be changed.'
    else:
        message = 'all settings are already configured.'

    module.exit_json(changed=changed_status, msg=message)


def configure_vcsa_access(module, vcsa_url, vcsa_username, vcsa_password, console_access, dcui_access, ssh_access, shell_access, validate_certs):
    """Configure vCSA accesss"""

    changed = []
    changed_status = False

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

    # console-based controlled CLI (TTY1) access
    try:
        (rc, consolecli) = request(url=vcsa_url + "/appliance/access/consolecli", url_username=vcsa_username, url_password=vcsa_password,
                                   validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get consolecli state. Error [%s]." % str(err))

    if consolecli['value'] != console_access:
        body = {"enabled": console_access}
        try:
            (rc, response) = request(url=vcsa_url + "/appliance/access/consolecli", url_username=vcsa_username, url_password=vcsa_password,
                                     validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PUT')
        except:
            err = get_exception()
            module.fail_json(msg="Failed to set consolecli. Error [%s]." % str(err))
        changed.append('console')
        changed_status = True

    # Direct Console User Interface (DCUI TTY2) access
    try:
        (rc, dcui) = request(url=vcsa_url + "/appliance/access/dcui", url_username=vcsa_username, url_password=vcsa_password,
                             validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get DCUI state. Error [%s]." % str(err))

    if dcui['value'] != dcui_access:
        body = {"enabled": dcui_access}
        try:
            (rc, response) = request(url=vcsa_url + "/appliance/access/dcui", url_username=vcsa_username, url_password=vcsa_password,
                                     validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PUT')
        except:
            err = get_exception()
            module.fail_json(msg="Failed to set DCUI. Error [%s]." % str(err))
        changed.append('dcui')
        changed_status = True

    # SSH-based controlled CLI access
    try:
        (rc, ssh) = request(url=vcsa_url + "/appliance/access/ssh", url_username=vcsa_username, url_password=vcsa_password,
                            validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get SSH state. Error [%s]." % str(err))

    if ssh['value'] != ssh_access:
        body = {"enabled": ssh_access}
        try:
            (rc, response) = request(url=vcsa_url + "/appliance/access/ssh", url_username=vcsa_username, url_password=vcsa_password,
                                     validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PUT')
        except:
            err = get_exception()
            module.fail_json(msg="Failed to set SSH. Error [%s]." % str(err))
        changed.append('ssh')
        changed_status = True

    # access to BASH from within the controlled CLI
    try:
        (rc, shell) = request(url=vcsa_url + "/appliance/access/shell", url_username=vcsa_username, url_password=vcsa_password,
                              validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get Bash shell state. Error [%s]." % str(err))

    if shell['value']['enabled'] != shell_access:
        body = {"enabled": shell_access}
        try:
            (rc, response) = request(url=vcsa_url + "/appliance/access/ssh", url_username=vcsa_username, url_password=vcsa_password,
                                     validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PUT')
        except:
            err = get_exception()
            module.fail_json(msg="Failed to set Bash shell. Error [%s]." % str(err))
        changed.append('ssh')
        changed_status = True

    if changed_status:
        if len(changed) > 2:
            message = ', '.join(changed[:-1]) + ', and ' + str(changed[-1]) + ' changed.'
        elif len(changed) == 2:
            message = ' and '.join(changed) + ' changed.'
        elif len(changed) == 1:
            message = changed[0] + ' changed.'
    else:
        message = 'all settings are already configured.'

    module.exit_json(changed=changed_status, msg=message)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(required=True, type='str'),
            username=dict(default='root', type='str'),
            password=dict(required=True, type='str', no_log=True),
            console=dict(required=True, type='bool'),
            dcui=dict(required=True, type='bool'),
            ssh=dict(required=True, type='bool'),
            shell=dict(required=True, type='bool'),
            validate_certs=dict(default=True, type='bool')
        ),
        supports_check_mode=True
    )

    vcsa_hostname = module.params['hostname']
    vcsa_username = module.params['username']
    vcsa_password = module.params['password']
    console_access = module.params['console']
    dcui_access = module.params['dcui']
    ssh_access = module.params['ssh']
    shell_access = module.params['shell']
    validate_certs = module.params['validate_certs']

    base_url = "/rest"
    vcsa_url = "https://" + vcsa_hostname + base_url

    if module.check_mode:
        check_vcsa_access(module, vcsa_url, vcsa_username, vcsa_password, console_access, dcui_access, ssh_access, shell_access, validate_certs)

    configure_vcsa_access(module, vcsa_url, vcsa_username, vcsa_password, console_access, dcui_access, ssh_access, shell_access, validate_certs)


if __name__ == '__main__':
    main()
