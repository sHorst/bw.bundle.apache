from uuid import uuid5, NAMESPACE_URL

defaults = {}

if node.has_bundle("dehydrated"):
    defaults['dehydrated'] = {
        'hooks': {
            'deploy_cert': {
                'apache': [
                    'service apache2 restart',
                ],
            }
        }
    }


def get_used_ports(metadata):
    ports = {}
    for vhost_name in metadata.get('apache/vhosts', {}).keys():
        vhost = 'apache/vhosts/{}'.format(vhost_name)
        for port in metadata.get('{}/ports/http'.format(vhost), [80]):
            ports[port] = 'http'
        for port in metadata.get('{}/ports/https'.format(vhost), [443]):
            ports[port] = 'https'

    return ports


def get_tag_from_port(port, protocoll):
    if protocoll == 'http' and port == 80:
        return 'http'
    elif protocoll == 'https' and port == 443:
        return 'https'
    else:
        return '{}_{}'.format(protocoll, port)


@metadata_reactor
def default_vhost_for_redirects(metadata):
    default_hostname = ''
    for vhost_name, vhost in metadata.get('apache/vhosts', {}).items():
        if vhost.get('default', False):
            default_hostname = vhost_name
            break

    if default_hostname == '':
        default_hostname = metadata.get('apache/vhosts', {}).keys()

    vhosts = {}
    for redirect_from, redirect_to in metadata.get('apache/url_redirects', {}).items():
        vhosts[redirect_from] = \
            {
                'enabled': True,
                'ssl': True,
                'permanent_redirects': {
                    '/.well-known/acme-challenge': f'https://{default_hostname}/.well-known/acme-challenge',
                    '/': redirect_to,
                }
            }

    return {
        'apache': {
            'vhosts': vhosts,
        }
    }


@metadata_reactor
def default_vhost_document_root(metadata):
    vhosts = {}
    for vhost_name, vhost in metadata.get('apache/vhosts', {}).items():
        vhosts[vhost_name] = {}
        if not metadata.get('apache/vhosts/{}/private_root'.format(vhost_name), None):
            vhosts[vhost_name]['private_root'] = '/var/www/{}'.format(vhost_name)
        if not metadata.get('apache/vhosts/{}/public_root'.format(vhost_name), None):
            vhosts[vhost_name]['public_root'] = '/var/www/{}/{}'.format(vhost_name, metadata.get('apache/vhosts/{}/htdocs'.format(vhost_name), 'htdocs'))

        if 'suexec' in vhost and 'public_root' not in vhost:
            old_document_root = vhost.get('document_root', '/var/www/{}'.format(vhost['suexec']['user']))
            vhosts[vhost_name]['private_root'] = '{}/web/htdocs'.format(old_document_root)
            vhosts[vhost_name]['public_root'] = '{}/web/htdocs/public_html'.format(old_document_root)

    return {
        'apache': {
            'vhosts': vhosts,
        }
    }


@metadata_reactor
def add_iptables_rules(metadata):
    if not node.has_bundle("iptables"):
        raise DoNotRunAgain

    ports = get_used_ports(metadata)

    interfaces = ['main_interface']
    interfaces += metadata.get('apache/additional_interfaces', [])

    iptables_rules = {}
    for interface in interfaces:
        for port in ports.keys():
            iptables_rules += repo.libs.iptables.accept(). \
                input(interface). \
                state_new(). \
                tcp(). \
                dest_port(port)

    return iptables_rules


@metadata_reactor
def add_restic_rules(metadata):
    if not node.has_bundle("restic"):
        raise DoNotRunAgain

    add_folders = {'/var/www', }

    # backup /var/www and additional all document roots which are not part of /var/www
    for vhost_name, vhost in metadata.get('apache/vhosts', {}).items():
        if not vhost.get('document_root', '/var/www').startswith('/var/www'):
            add_folders.add(vhost.get('document_root'))

    return {
        'restic': {
            'backup_folders': add_folders
        }
    }


@metadata_reactor
def add_dehydrated_domains(metadata):
    if not node.has_bundle("dehydrated"):
        raise DoNotRunAgain

    domains = set()
    for vhost_name, vhost in metadata.get('apache/vhosts', {}).items():
        if vhost.get('enabled', False) and vhost.get('ssl', False):
            domains.add('{} {}'.format(vhost_name, ' '.join(vhost.get('aliases', []))).strip())

    return {
        'dehydrated': {
            'domains': domains,
        }
    }


@metadata_reactor
def add_yubikey_default_config(metadata):
    vhosts = {}
    if 'authn_yubikey' in metadata.get('apache/modules', {}):
        authn_yubikey_config = metadata.get('apache/modules/authn_yubikey')

        for vhost_name, vhost_config in metadata.get('apache/vhosts', {}).items():
            vhosts[vhost_name] = {
                'additional_config': {
                   '_authz_yubikey': [
                       "<Directory />",
                       '  AuthYubiKeyTimeout {}'.format(authn_yubikey_config.get('AuthYubiKeyTimeout', 3600)),
                       '  AuthYubiKeyRequireSecure {}'.format(
                           'On' if authn_yubikey_config.get('AuthYubiKeyRequireSecure', True)
                                   and vhost_config.get('ssl', False) else 'Off'
                       ),
                       '  AuthYubiKeyExternalErrorPage {}'.format(
                           'On' if authn_yubikey_config.get('AuthYubiKeyExternalErrorPage', False) else 'Off'
                       ),

                       '  AuthYubiKeyServerKeyId {}'.format(authn_yubikey_config.get('AuthYubiKeyServerKeyId', 1)),
                       '  AuthYubiKeyServerKey "{}"'.format(authn_yubikey_config.get('AuthYubiKeyServerKey', 'NOTSET')),

                       '  AuthYubiKeyValidationUrl "{}"'.format(
                           authn_yubikey_config.get('AuthYubiKeyValidationUrl',
                                                    "https://yubico.ultrachaos.de/yubi-tcl/cgi-verify-2.0.tcl"
                                                    )
                       ),
                       "</Directory>",
                   ]
                }
            }
    return {
        'apache': {
            'vhosts': vhosts,
        },
    }


@metadata_reactor
def add_check_mk_tags(metadata):
    if not node.has_bundle('check_mk_agent'):
        raise DoNotRunAgain

    tags = {}
    ports = get_used_ports(metadata)
    for port, protocoll in ports.items():
        tag = get_tag_from_port(port, protocoll)

        if tag not in tags:
            tags[tag] = tag

    # set correct web attribute it does only knows standart http/s ports
    if 'http' in tags and 'https' in tags:
        tags['web'] = 'httpPlus'
    elif 'http' in tags:
        tags['web'] = '_http'
    else:
        tags['web'] = '_https'

    return {
        'check_mk': {
            'tags': tags,
        }
    }


@metadata_reactor
def add_check_mk_test(metadata):
    if not node.has_bundle('check_mk_agent'):
        raise DoNotRunAgain

    active_checks = {
        'http': [],
    }
    for port, protocoll in get_used_ports(metadata).items():
        tag = get_tag_from_port(port, protocoll)
        condition = {'host_tags': {tag: tag}}

        if protocoll == 'http':
            config = {'host': {'virthost': '$HOSTNAME$'},
                      'mode': ('url', {}),
                      'name': 'Webserver'}
            description = 'HTTP Server'
            if port != 80:
                # tag = 'http{port}'.format(port=port)
                # TODO: add port to config
                description += ' on Port {}'.format(port)

            active_checks['http'] += [
                {
                    'id': str(uuid5(NAMESPACE_URL, f'{tag}_connect')),
                    'condition': condition,
                    'options': {'description': description},
                    'value': config,
                },
            ]

        elif protocoll == 'https':
            # TODO: add all vhosts to config
            config = {'host': {'virthost': '$HOSTNAME$'},
                      'mode': ('url', {'ssl': 'auto'}),
                      'name': 'Secure Web Server'}
            cert_config = {'host': {},
                           'mode': ('cert', {'cert_days': (15, 5)}),
                           'name': 'cert Age'}
            description = 'Secure HTTP Server'
            if port != 443:
                # TODO: add port to config
                description += ' on Port {}'.format(port)

            active_checks['http'] += [
                {
                    'id': str(uuid5(NAMESPACE_URL, f'{tag}_connect')),
                    'condition': condition,
                    'options': {'description': description},
                    'value': config,
                },
                {
                    'id': str(uuid5(NAMESPACE_URL, f'{tag}_cert')),
                    'condition': condition,
                    'options': {'description': "Certificate Age for {}".format(description)},
                    'value': cert_config,
                },
            ]

    return {
        'check_mk': {
            'agent': {
                'active_checks': active_checks,
            }
        },
    }


