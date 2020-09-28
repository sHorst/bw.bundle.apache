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
    vhosts = {}
    for redirect_from, redirect_to in metadata.get('apache/url_redirects', {}).items():
        vhosts[redirect_from] = \
            {
                'enabled': True,
                'ssl': True,
                'permanent_redirects': {
                    '/.well-known/acme-challenge': 'https://www.scoutnet.de/.well-known/acme-challenge',
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
            vhosts[vhost_name]['public_root'] = '/var/www/{}/htdocs'.format(vhost_name)

        if 'suexec' in vhost:
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

    add_folders = ['/var/www', ]

    # backup /var/www and additional all document roots which are not part of /var/www
    for vhost_name, vhost in metadata.get('apache/vhosts', {}).items():
        if not vhost.get('document_root', '/var/www').startswith('/var/www'):
            add_folders += [vhost.get('document_root'), ]

    return {
        'restic': {
            'backup_folders': add_folders
        }
    }


@metadata_reactor
def add_dehydrated_domains(metadata):
    if not node.has_bundle("dehydrated"):
        raise DoNotRunAgain

    domains = []
    for vhost_name, vhost in metadata.get('apache/vhosts', {}).items():
        if vhost.get('enabled', False) and vhost.get('ssl', False):
            domains.append('{} {}'.format(vhost_name, ' '.join(vhost.get('aliases', []))).strip())

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
    # TODO: fix this
    raise DoNotRunAgain

    if not node.has_bundle('check_mk_agent'):
        raise DoNotRunAgain

    if not metadata.get('check_mk/servers', []):
        return {}

    ports = get_used_ports(metadata)
    # tag = 'ssh{}'.format(metadata.get('openssl', {}).get('port', ''))
    # port = metadata.get('openssl', {}).get('port', 22)

    for check_mk_server_name in metadata.get('check_mk/servers'):
        check_mk_server = repo.get_node(check_mk_server_name)

        if check_mk_server.partial_metadata == {}:
            return {}

        check_mk_server.partial_metadata. \
            setdefault('check_mk', {}). \
            setdefault('global_rules', {}). \
            setdefault('active_checks', {}). \
            setdefault('http', [])

        used_tags = [
            # TODO: this is not working to full extend
            list(x.get('condition', {}).get('host_tags', {}).keys()) for x in check_mk_server.partial_metadata['check_mk']['global_rules']['active_checks']['http']
        ]

        for port, protocoll in ports.items():
            tag = get_tag_from_port(port, protocoll)

            if [tag, ] not in used_tags:
                condition = {'host_tags': {tag: tag}}

                if protocoll == 'http':
                    config = (u'Webserver', {'virthost': ('$HOSTNAME$', False)})
                    description = 'HTTP Server'
                    if port != 80:
                        # tag = 'http{port}'.format(port=port)
                        # TODO: add port to config
                        description += ' on Port {}'.format(port)

                    check_mk_server.partial_metadata['check_mk']['global_rules']['active_checks']['http'] += [
                        {
                            'condition': condition,
                            'options': {'description': description},
                            'value': config,
                        },
                    ]
                elif protocoll == 'https':
                    # TODO: add all vhosts to config
                    config = ('Secure Web Server', {
                        'ssl': 'auto',
                        'virthost': ('$HOSTNAME$', False),
                        'sni': True
                    })
                    cert_config = (u'cert Age', {'cert_days': (15, 5), 'sni': True})
                    description = 'Secure HTTP Server'
                    if port != 443:
                        # TODO: add port to config
                        description += ' on Port {}'.format(port)

                    check_mk_server.partial_metadata['check_mk']['global_rules']['active_checks']['http'] += [
                        {
                            'condition': condition,
                            'options': {'description': description},
                            'value': config,
                        },
                    ]

                    check_mk_server.partial_metadata['check_mk']['global_rules']['active_checks']['http'] += [
                        {
                            'condition': condition,
                            'options': {'description': "Certificate Age for {}".format(description)},
                            'value': cert_config,
                        },
                    ]

        # generate global host tags for ssh
        # check_mk_server.partial_metadata. \
        #     setdefault('check_mk', {}). \
        #     setdefault('host_tags', {}). \
        #     setdefault('ssh', {
        #     'description': 'Services/SSH Server',
        #     'subtags': {
        #         'None': ('Nein', []),
        #         'ssh': ('Ja', []),
        #     }
        # })
        #
        # if tag not in check_mk_server.partial_metadata['check_mk']['host_tags']['ssh']['subtags']:
        #     check_mk_server.partial_metadata['check_mk']['host_tags']['ssh']['subtags'][tag] = (
        #         'Ja auf Port {}'.format(port), ['ssh', ]
        #     )
        #
        # # SSH Server host_group
        # check_mk_server.partial_metadata. \
        #     setdefault('check_mk', {}). \
        #     setdefault('host_groups', {})
        #
        # check_mk_server.partial_metadata['check_mk']['host_groups']['ssh-servers'] = {
        #     'description': 'SSH Server',
        #     'tags': ['ssh'],
        # }

