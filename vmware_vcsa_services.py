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


def check_vmon_services(module, vcsa_url, vcsa_username, vcsa_password, vcsa_services, vcsa_state, vcsa_startup_type, validate_certs):
    """Inform the user what would change if the module were run"""

    would_be_changed_state = []
    would_be_changed_startup_type = []
    service_state_changed = False
    service_startup_type_changed = False

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
        (rc, vmon_services) = request(url=vcsa_url + "/appliance/vmon/service", url_username=vcsa_username, url_password=vcsa_password,
                                      validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get vmon services. Error [%s]." % str(err))

    for vmon_service in vmon_services['value']:
        for vcsa_service in vcsa_services:
            if vmon_service['key'] == vcsa_service:
                if vcsa_state == 'restarted':
                    would_be_changed_state.append(vmon_service['key'])
                    service_state_changed = True
                else:
                    if (vmon_service['value']['state'].lower() != vcsa_state):
                        would_be_changed_state.append(vmon_service['key'])
                        service_state_changed = True
                if (vmon_service['value']['startup_type'].lower() != vcsa_startup_type):
                    would_be_changed_startup_type.append(vmon_service['key'])
                    service_startup_type_changed = True

    if service_state_changed or service_startup_type_changed:
        message_state = ''
        message_startup_type = ''
        if service_state_changed:
            changed_status = True
            if len(would_be_changed_state) > 2:
                message_state = 'Services '
                message_state = message_state + ', '.join(would_be_changed_state[:-1]) + ', and ' + str(would_be_changed_state[-1]) + ' would be %s.' % vcsa_state
            elif len(would_be_changed_state) == 2:
                message_state = 'Services '
                message_state = message_state + ' and '.join(would_be_changed_state) + ' would be %s.' % vcsa_state
            elif len(would_be_changed_state) == 1:
                message_state = 'Service '
                message_state = message_state + would_be_changed_state[0] + ' would be %s.' % vcsa_state
        if service_startup_type_changed:
            changed_status = True
            if len(would_be_changed_startup_type) > 2:
                message_startup_type = 'Services '
                message_startup_type = message_startup_type + ', '.join(would_be_changed_startup_type[:-1]) + ', and ' + str(would_be_changed_startup_type[-1]) + ' startup type would be set to %s.' % vcsa_startup_type
            elif len(would_be_changed_startup_type) == 2:
                message_startup_type = 'Services '
                message_startup_type = message_startup_type + ' and '.join(would_be_changed_startup_type) + ' startup type would be set to %s.' % vcsa_startup_type
            elif len(would_be_changed_startup_type) == 1:
                message_startup_type = 'Service '
                message_startup_type = message_startup_type + would_be_changed_startup_type[0] + ' startup type would be set to %s.' % vcsa_startup_type
        if message_state != '':
            message = message_state
            if message_startup_type != '':
                message = message + " " + message_startup_type
        elif message_startup_type != '':
            message = message_startup_type
    else:
        changed_status = False
        message = 'Services already %s and startup type set to %s.' % (vcsa_state, vcsa_startup_type)

    module.exit_json(changed=changed_status, msg=message)


def configure_vmon_services(module, vcsa_url, vcsa_username, vcsa_password, vcsa_services, vcsa_state, vcsa_startup_type, validate_certs):
    """Configure vCSA services"""

    changed_state = []
    changed_startup_type = []
    service_state_changed = False
    service_startup_type_changed = False

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
        (rc, vmon_services) = request(url=vcsa_url + "/appliance/vmon/service", url_username=vcsa_username, url_password=vcsa_password,
                                      validate_certs=validate_certs, headers=headers)
    except:
        err = get_exception()
        module.fail_json(msg="Failed to get vmon services. Error [%s]." % str(err))

    for vmon_service in vmon_services['value']:
        for vcsa_service in vcsa_services:
            if vmon_service['key'] == vcsa_service:
                if vcsa_state == 'restarted':
                    try:
                        (rc, response) = request(url=vcsa_url + "/appliance/vmon/service/%s/restart" % vmon_service['key'], url_username=vcsa_username, url_password=vcsa_password,
                                             validate_certs=validate_certs, headers=headers, method='POST')
                    except:
                        err = get_exception()
                        module.fail_json(msg="Failed to restart %s. Error [%s]." % (vmon_service['key'], str(err)))
                    service_state_changed = True
                    changed_state.append(vmon_service['key'])
                else:
                    if (vmon_service['value']['state'].lower() != vcsa_state):
                        if vcsa_state == 'started':
                            type = "start"
                        else:
                            type = "stop"
                        try:
                            (rc, response) = request(url=vcsa_url + "/appliance/vmon/service/%s/%s" % (vmon_service['key'], type), url_username=vcsa_username, url_password=vcsa_password,
                                                           validate_certs=validate_certs, headers=headers, method='POST')
                        except:
                            err = get_exception()
                            module.fail_json(msg="Failed to %s service %s. Error [%s]." % (type, vmon_service['key'], str(err)))
                        service_state_changed = True
                        changed_state.append(vmon_service['key'])
                    if (vmon_service['value']['startup_type'].lower() != vcsa_startup_type):
                        body = {"spec": {"startup_type": vcsa_startup_type.upper()}}
                        try:
                            (rc, response) = request(url=vcsa_url + "/appliance/vmon/service/%s" % vmon_service['key'], url_username=vcsa_username, url_password=vcsa_password,
                                                     validate_certs=validate_certs, headers=headers, data=bytes(json.dumps(body), encoding="utf-8"), method='PATCH')
                        except:
                            err = get_exception()
                            module.fail_json(msg="Failed to set startup type to %s. Error [%s]." % (vcsa_startup_type, str(err)))
                        service_startup_type_changed = True
                        changed_startup_type.append(vmon_service['key'])

    if service_state_changed or service_startup_type_changed:
        message_state = ''
        message_startup_type = ''
        if service_state_changed:
            changed_status = True
            if len(changed_state) > 2:
                message_state = 'Services '
                message_state = message_state + ', '.join(changed_state[:-1]) + ', and ' + str(changed_state[-1]) + ' %s.' % vcsa_state
            elif len(changed_state) == 2:
                message_state = 'Services '
                message_state = message_state + ' and '.join(changed_state) + ' %s.' % vcsa_state
            elif len(changed_state) == 1:
                message_state = 'Service '
                message_state = message_state + changed_state[0] + ' %s.' % vcsa_state
        if service_startup_type_changed:
            changed_status = True
            if len(changed_startup_type) > 2:
                message_startup_type = 'Services '
                message_startup_type = message_startup_type + ', '.join(changed_startup_type[:-1]) + ', and ' + str(changed_startup_type[-1]) + ' startup type set to %s.' % vcsa_startup_type
            elif len(changed_startup_type) == 2:
                message_startup_type = 'Services '
                message_startup_type = message_startup_type + ' and '.join(changed_startup_type) + ' startup type set to %s.' % vcsa_startup_type
            elif len(changed_startup_type) == 1:
                message_startup_type = 'Service '
                message_startup_type = message_startup_type + changed_startup_type[0] + ' startup type set to %s.' % vcsa_startup_type
        if message_state != '':
            message = message_state
            if message_startup_type != '':
                message = message + " " + message_startup_type
        elif message_startup_type != '':
            message = message_startup_type
    else:
        changed_status = False
        message = 'Services already %s and startup type set to %s.' % (vcsa_state, vcsa_startup_type)

    module.exit_json(changed=changed_status, msg=message)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(required=True, type='str'),
            username=dict(default='root', type='str'),
            password=dict(required=True, type='str', no_log=True),
            services=dict(required=True, type='list'),
            state=dict(required=True, choices=['started', 'stopped', 'restarted'], type='str'),
            startup_type=dict(required=True, choices=['automatic', 'manual', 'disabled'], type='str'),
            validate_certs=dict(default=True, type='bool')
        ),
        supports_check_mode=True
    )

    vcsa_hostname = module.params['hostname']
    vcsa_username = module.params['username']
    vcsa_password = module.params['password']
    vcsa_services = module.params['services']
    vcsa_state = module.params['state']
    vcsa_startup_type = module.params['startup_type']
    validate_certs = module.params['validate_certs']

    base_url = "/rest"
    vcsa_url = "https://" + vcsa_hostname + base_url

    if module.check_mode:
        check_vmon_services(module, vcsa_url, vcsa_username, vcsa_password, vcsa_services, vcsa_state, vcsa_startup_type, validate_certs)

    configure_vmon_services(module, vcsa_url, vcsa_username, vcsa_password, vcsa_services, vcsa_state, vcsa_startup_type, validate_certs)


if __name__ == '__main__':
    main()
