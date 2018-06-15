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


# def check_vcsa_update(module, vcsa_url, vcsa_username, vcsa_password, auto_stage, day, hour, minute, url, validate_certs):
#     """Inform the user what would change if the module were run"""
#
#     would_be_changed = []
#     changed_status = False
#
#     headers = {
#         "Content-Type": "application/json",
#         "Accept": "application/json",
#     }
#     try:
#         (rc, session_id) = request(url=vcsa_url + "/com/vmware/cis/session", url_username=vcsa_username, url_password=vcsa_password,
#                                    validate_certs=validate_certs, headers=headers, method='POST')
#     except:
#         err = get_exception()
#         module.fail_json(msg="Failed to establish a session and authenticate. Error [%s]." % str(err))
#
#     headers.update({'vmware-api-session-id': session_id['value']})
#
#     try:
#         (rc, system_version) = request(url=vcsa_url + "/appliance/system/version", url_username=vcsa_username, url_password=vcsa_password,
#                                        validate_certs=validate_certs, headers=headers)
#     except:
#         err = get_exception()
#         module.fail_json(msg="Failed to get appliance version. Error [%s]." % str(err))
#
#     appliance_version = system_version['value']['version']
#     if appliance_version.startswith('6.7'):
#         try:
#             (rc, system_update) = request(url=vcsa_url + "/appliance/update/policy", url_username=vcsa_username, url_password=vcsa_password,
#                                           validate_certs=validate_certs, headers=headers)
#         except:
#             err = get_exception()
#             module.fail_json(msg="Failed to get update policy. Error [%s]." % str(err))
#         # check auto staging
#         if system_update['value']['auto_stage'] is not auto_stage:
#             would_be_changed.append('auto_stage')
#             changed_status = True
#         # check automatic check schedule
#         if auto_stage:
#             if not system_update['value']['check_schedule']:
#                 would_be_changed.append('check_schedule')
#                 changed_status = True
#             else:
#                 if system_update['value']['check_schedule'][0]['day'] != day:
#                     would_be_changed.append('check_schedule_day')
#                     changed_status = True
#                 if system_update['value']['check_schedule'][0]['hour'] is not hour:
#                     would_be_changed.append('check_schedule_hour')
#                     changed_status = True
#                 if system_update['value']['check_schedule'][0]['minute'] is not minute:
#                     would_be_changed.append('check_schedule_minute')
#                     changed_status = True
#             # check update URL
#             if url:
#                 if 'custom_URL' in system_update['value']:
#                     if system_update['value']['custom_URL'] != url:
#                         would_be_changed.append('url')
#                         changed_status = True
#                 else:
#                     would_be_changed.append('url')
#                     changed_status = True
#             else:
#                 if 'custom_URL' in system_update['value']:
#                     would_be_changed.append('url')
#                     changed_status = True
#         else:
#             if system_update['value']['check_schedule']:
#                 would_be_changed.append('check_schedule')
#                 changed_status = True
#             if 'custom_URL' in system_update['value']:
#                 would_be_changed.append('url')
#                 changed_status = True
#
#         if changed_status:
#             if len(would_be_changed) > 2:
#                 message = ', '.join(would_be_changed[:-1]) + ', and ' + str(would_be_changed[-1]) + ' would be changed.'
#             elif len(would_be_changed) == 2:
#                 message = ' and '.join(would_be_changed) + ' would be changed.'
#             elif len(would_be_changed) == 1:
#                 message = would_be_changed[0] + ' would be changed.'
#         else:
#             message = 'all settings are already configured.'
#
#         module.exit_json(changed=changed_status, msg=message)
#     else:
#         module.fail_json(msg="Appliance version %s not supported!" % appliance_version)


def configure_vcsa_update(module, vcsa_url, vcsa_username, vcsa_password, auto_stage, day, hour, minute, url, validate_certs):
    """Configure vCSA update"""

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
        (rc, system_version) = request(url=vcsa_url + "/appliance/system/version", url_username=vcsa_username, url_password=vcsa_password,
                                       validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get appliance version. Error [%s]." % str(err))

    appliance_version = system_version['value']['version']
    if appliance_version.startswith('6.7'):
        try:
            (rc, system_update) = request(url=vcsa_url + "/appliance/update/policy", url_username=vcsa_username, url_password=vcsa_password,
                                          validate_certs=validate_certs, headers=headers)
        except:
            err = get_exception()
            module.fail_json(msg="Failed to get update policy. Error [%s]." % str(err))
        body = {}
        body_policy = {}
        # check auto staging
        if system_update['value']['auto_stage'] is not auto_stage:
            body_policy['auto_stage'] = auto_stage
            changed.append('auto_stage')
            changed_status = True
        else:
            body_policy['auto_stage'] = system_update['value']['auto_stage']
        if auto_stage:
            # check automatic check schedule
            if not system_update['value']['check_schedule']:
                body_policy['check_schedule'] = [{"day": day, "hour": hour, "minute": minute}]
                changed.append('check_schedule')
                changed_status = True
            else:
                schedule_changed = False
                if system_update['value']['check_schedule'][0]['day'] != day:
                    body_policy['check_schedule'] = [{"day": day, "hour": hour, "minute": minute}]
                    changed.append('check_schedule_day')
                    changed_status = True
                    schedule_changed = True
                if system_update['value']['check_schedule'][0]['hour'] is not hour:
                    body_policy['check_schedule'] = [{"day": day, "hour": hour, "minute": minute}]
                    changed.append('check_schedule_hour')
                    changed_status = True
                    schedule_changed = True
                if system_update['value']['check_schedule'][0]['minute'] is not minute:
                    body_policy['check_schedule'] = [{"day": day, "hour": hour, "minute": minute}]
                    changed.append('check_schedule_minute')
                    changed_status = True
                    schedule_changed = True
                if not schedule_changed:
                    body_policy['check_schedule'] = [{"day": day, "hour": hour, "minute": minute}]
            # check update URL
            if url:
                if 'custom_URL' in system_update['value']:
                    if system_update['value']['custom_URL'] != url:
                        body_policy['custom_URL'] = url
                        changed.append('url')
                        changed_status = True
                else:
                    body_policy['custom_URL'] = url
                    changed.append('url')
                    changed_status = True
            else:
                if 'custom_URL' in system_update['value']:
                    changed.append('url')
                    changed_status = True
        else:
            if system_update['value']['check_schedule']:
                body_policy['check_schedule'] = []
                changed.append('check_schedule')
                changed_status = True
            if 'custom_URL' in system_update['value']:
                changed.append('url')
                changed_status = True

        if changed_status:
            if module.check_mode:
                changed_message = ' would be changed.'
            else:
                body = {"policy": body_policy}
                try:
                    (rc, response) = request(url=vcsa_url + "/appliance/update/policy", url_username=vcsa_username, url_password=vcsa_password,
                                             validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PUT')
                except:
                    err = get_exception()
                    module.fail_json(msg="Failed to set valid_days for %s. Error [%s]." % (account, str(err)))
                changed_message = ' changed.'
            if len(changed) > 2:
                message = ', '.join(changed[:-1]) + ', and ' + str(changed[-1]) + changed_message
            elif len(changed) == 2:
                message = ' and '.join(changed) + changed_message
            elif len(changed) == 1:
                message = changed[0] + changed_message
        else:
            message = 'all settings are already configured.'

        module.exit_json(changed=changed_status, msg=message)
    else:
        module.fail_json(msg="Appliance version %s not supported!" % appliance_version)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(required=True, type='str'),
            username=dict(default='root', type='str'),
            password=dict(required=True, type='str', no_log=True),
            auto_stage=dict(default=False, type='bool'),
            day=dict(required=True, choices=['Monday', 'Tuesday', 'Friday', 'Wednesday', 'Thursday', 'Saturday', 'Sunday', 'Everyday'], type='str'),
            hour=dict(required=True, type='int'),
            minute=dict(required=True, type='int'),
            url=dict(required=False, type='str'),
            validate_certs=dict(default=True, type='bool')
        ),
        supports_check_mode=True
    )

    vcsa_hostname = module.params['hostname']
    vcsa_username = module.params['username']
    vcsa_password = module.params['password']
    auto_stage = module.params['auto_stage']
    day = module.params['day'].upper()
    hour = module.params['hour']
    minute = module.params['minute']
    url = module.params['url']
    validate_certs = module.params['validate_certs']

    base_url = "/rest"
    vcsa_url = "https://" + vcsa_hostname + base_url

    # if module.check_mode:
    #     check_vcsa_update(module, vcsa_url, vcsa_username, vcsa_password, auto_stage, day, hour, minute, url, validate_certs)

    configure_vcsa_update(module, vcsa_url, vcsa_username, vcsa_password, auto_stage, day, hour, minute, url, validate_certs)


if __name__ == '__main__':
    main()
