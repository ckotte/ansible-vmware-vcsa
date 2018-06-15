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


def check_vcsa_accounts(module, vcsa_url, vcsa_username, vcsa_password, account, enabled, full_name, password_expires, valid_days, email, validate_certs):
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

    try:
        (rc, system_version) = request(url=vcsa_url + "/appliance/system/version", url_username=vcsa_username, url_password=vcsa_password,
                                      validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get appliance version. Error [%s]." % str(err))

    appliance_version = system_version['value']['version']
    if appliance_version.startswith('6.7'):
        try:
            (rc, local_account) = request(url=vcsa_url + "/appliance/local-accounts/%s" % account, url_username=vcsa_username, url_password=vcsa_password,
                                          validate_certs=validate_certs, headers=headers)
        except:
            err = get_exception()
            module.fail_json(msg="Failed to get local account %s. Error [%s]." % (account, str(err)))

        # check if account is enabled
        if local_account['value']['enabled'] is not enabled:
            would_be_changed.append('enabled')
            changed_status = True

        # check full name
        if full_name:
            if local_account['value']['fullname'] != full_name:
                would_be_changed.append('full_name')
                changed_status = True
        else:
            if local_account['value']['fullname'] != account:
                would_be_changed.append('full_name')
                changed_status = True

        # check password expiration
        if password_expires:
            # password expiration is disabled
            if local_account['value']['max_days_between_password_change'] in (99999, -1):
                would_be_changed.append('password_expires')
                changed_status = True
            else:
                if local_account['value']['max_days_between_password_change'] is not valid_days:
                    would_be_changed.append('valid_days')
                    changed_status = True
                if local_account['value']['email'] != email:
                    would_be_changed.append('email')
                    changed_status = True
        else:
            # password expiration is not disabled
            if local_account['value']['max_days_between_password_change'] not in (99999, -1):
                would_be_changed.append('password_expires')
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
    else:
        module.fail_json(msg="Appliance version %s not supported!" % appliance_version)


def configure_vcsa_accounts(module, vcsa_url, vcsa_username, vcsa_password, account, enabled, full_name, password_expires, valid_days, email, validate_certs):
    """Configure vCSA accounts"""

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

    try:
        (rc, local_account) = request(url=vcsa_url + "/appliance/local-accounts/%s" % account, url_username=vcsa_username, url_password=vcsa_password,
                                      validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get local account %s. Error [%s]." % (account, str(err)))

    # check if account is enabled
    if local_account['value']['enabled'] is not enabled:
        body = {"config": {"enabled": enabled}}
        try:
            (rc, response) = request(url=vcsa_url + "/appliance/local-accounts/%s" % account, url_username=vcsa_username, url_password=vcsa_password,
                                     validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PATCH')
        except:
            err = get_exception()
            module.fail_json(msg="Failed to enable %s. Error [%s]." % (account, str(err)))
        changed.append('enabled')
        changed_status = True

    # check full name
    if full_name:
        if local_account['value']['fullname'] != full_name:
            body = {"config": {"full_name": full_name}}
            try:
                (rc, response) = request(url=vcsa_url + "/appliance/local-accounts/%s" % account, url_username=vcsa_username, url_password=vcsa_password,
                                         validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PATCH')
            except:
                err = get_exception()
                module.fail_json(msg="Failed to set full_name for %s. Error [%s]." % (account, str(err)))
            changed.append('full_name')
            changed_status = True
    else:
        if local_account['value']['fullname'] != account:
            body = {"config": {"full_name": account}}
            try:
                (rc, response) = request(url=vcsa_url + "/appliance/local-accounts/%s" % account, url_username=vcsa_username, url_password=vcsa_password,
                                         validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PATCH')
            except:
                err = get_exception()
                module.fail_json(msg="Failed to set full_name for %s. Error [%s]." % (account, str(err)))
            changed.append('full_name')
            changed_status = True

    # check password expiration
    if password_expires:
        # password expiration is disabled
        if local_account['value']['max_days_between_password_change'] in (99999, -1):
            body = {"config": {
                "password_expires": password_expires,
                "max_days_between_password_change": valid_days,
                "email": email}
            }
            try:
                (rc, response) = request(url=vcsa_url + "/appliance/local-accounts/%s" % account, url_username=vcsa_username, url_password=vcsa_password,
                                         validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PATCH')
            except:
                err = get_exception()
                module.fail_json(msg="Failed to enable password expiration for %s. Error [%s]." % (account, str(err)))
            changed.append('password_expires')
            changed_status = True
        else:
            if local_account['value']['max_days_between_password_change'] is not valid_days:
                body = {"config": {"max_days_between_password_change": valid_days}}
                try:
                    (rc, response) = request(url=vcsa_url + "/appliance/local-accounts/%s" % account, url_username=vcsa_username, url_password=vcsa_password,
                                             validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PATCH')
                except:
                    err = get_exception()
                    module.fail_json(msg="Failed to set valid_days for %s. Error [%s]." % (account, str(err)))
                changed.append('valid_days')
                changed_status = True
            if local_account['value']['email'] != email:
                body = {"config": {"email": email}}
                try:
                    (rc, response) = request(url=vcsa_url + "/appliance/local-accounts/%s" % account, url_username=vcsa_username, url_password=vcsa_password,
                                             validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PATCH')
                except:
                    err = get_exception()
                    module.fail_json(msg="Failed to set email for %s. Error [%s]." % (account, str(err)))
                changed.append('email')
                changed_status = True
    else:
        # password expiration is not disabled
        if local_account['value']['max_days_between_password_change'] not in (99999, -1):
            body = {"config": {"password_expires": password_expires}}
            try:
                (rc, response) = request(url=vcsa_url + "/appliance/local-accounts/%s" % account, url_username=vcsa_username, url_password=vcsa_password,
                                         validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PATCH')
            except:
                err = get_exception()
                module.fail_json(msg="Failed to disable password expiration for %s. Error [%s]." % (account, str(err)))
            changed.append('password_expires')
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
            account=dict(required=True, type='str'),
            enabled=dict(default=True, type='bool'),
            full_name=dict(required=False, type='str'),
            password_expires=dict(default=False, type='bool'),
            valid_days=dict(required=False, type='int'),
            email=dict(required=False, type='str'),
            validate_certs=dict(default=True, type='bool')
        ),
        supports_check_mode=True
    )

    vcsa_hostname = module.params['hostname']
    vcsa_username = module.params['username']
    vcsa_password = module.params['password']
    account = module.params['account']
    enabled = module.params['enabled']
    full_name = module.params['full_name']
    password_expires = module.params['password_expires']
    valid_days = module.params['valid_days']
    email = module.params['email']
    validate_certs = module.params['validate_certs']

    base_url = "/rest"
    vcsa_url = "https://" + vcsa_hostname + base_url

    if module.check_mode:
        check_vcsa_accounts(module, vcsa_url, vcsa_username, vcsa_password, account, enabled, full_name, password_expires, valid_days, email, validate_certs)

    configure_vcsa_accounts(module, vcsa_url, vcsa_username, vcsa_password, account, enabled, full_name, password_expires, valid_days, email, validate_certs)


if __name__ == '__main__':
    main()
