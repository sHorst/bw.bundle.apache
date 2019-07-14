def get_used_ports(metadata):
    ports = {}
    for vhost_name in metadata.get('apache', {}).get('vhosts', {}).keys():
        vhost = metadata['apache']['vhosts'][vhost_name]
        for port in vhost.get('ports', {}).get('http', [80]):
            ports[port] = 'http'
        for port in vhost.get('ports', {}).get('https', [443]):
            ports[port] = 'https'

    return ports


def get_tag_from_port(port, protocoll):
    if protocoll == 'http' and port == 80:
        return 'http'
    elif protocoll == 'https' and port == 443:
        return 'https'
    else:
        return '{}_{}'.format(protocoll, port)


@metadata_processor
def default_vhost_document_root(metadata):
    for vhost_name, vhost in metadata.get('apache', {}).get('vhosts', {}).items():
        metadata['apache']['vhosts'][vhost_name].setdefault('private_root', '/var/www/{}'.format(vhost_name))
        metadata['apache']['vhosts'][vhost_name].setdefault('public_root', '/var/www/{}/htdocs'.format(vhost_name))

        if 'suexec' in vhost:
            old_document_root = vhost.get('document_root', '/var/www/{}'.format(vhost['suexec']['user']))
            metadata['apache']['vhosts'][vhost_name]['public_root'] = "{}/web/htdocs/public_html".format(old_document_root)
            metadata['apache']['vhosts'][vhost_name]['private_root'] = "{}/web/htdocs".format(old_document_root)

    return metadata, DONE


@metadata_processor
def add_iptables_rules(metadata):
    if node.has_bundle("iptables"):
        ports = get_used_ports(metadata)

        interfaces = ['main_interface']
        interfaces += metadata.get('apache', {}).get('additional_interfaces', [])

        for interface in interfaces:
            for port in ports.keys():
                metadata += repo.libs.iptables.accept(). \
                    input(interface). \
                    state_new(). \
                    tcp(). \
                    dest_port(port)

    return metadata, DONE


@metadata_processor
def add_restic_rules(metadata):
    if node.has_bundle('restic'):
        backup_folders = ['/var/www', ]

        # backup /var/www and additional all document roots which are not part of /var/www
        for vhost_name, vhost in metadata.get('apache', {}).get('vhosts', {}).items():
            if not vhost.get('document_root', '/var/www').startswith('/var/www'):
                backup_folders += [vhost.get('document_root'), ]

        if 'restic' not in metadata:
            metadata['restic'] = {}

        metadata['restic']['backup_folders'] = metadata['restic'].get('backup_folders', []) + backup_folders

    return metadata, DONE


@metadata_processor
def add_dehydrated_hook(metadata):
    if node.has_bundle('dehydrated'):
        metadata.setdefault('dehydrated', {})\
            .setdefault('hooks', {})\
            .setdefault('deploy_cert', {})

        metadata['dehydrated']['hooks']['deploy_cert']['apache'] = ['service apache2 restart', ]

    return metadata, DONE


@metadata_processor
def add_dehydrated_domains(metadata):
    if node.has_bundle('dehydrated'):
        metadata.setdefault('dehydrated', {}).setdefault('domains', [])
        for vhost_name, vhost in metadata.get('apache', {}).get('vhosts', {}).items():
            if vhost.get('enabled', False) and vhost.get('ssl', False):
                metadata['dehydrated']['domains'].append('{} {}'
                                                         .format(vhost_name, ' '.join(vhost.get('aliases', [])))
                                                         .strip())

    return metadata, DONE


@metadata_processor
def add_yubikey_default_config(metadata):
    if 'authn_yubikey' in metadata.get('apache', {}).get('modules', {}):
        authn_yubikey_config = metadata['apache']['modules']['authn_yubikey']
        for vhost_name in metadata.get('apache', {}).get('vhosts', {}).keys():
            metadata['apache']['vhosts'][vhost_name].setdefault('additional_config', {})
            metadata['apache']['vhosts'][vhost_name]['additional_config']['_authz_yubikey'] = [
                "<Directory />",
                '  AuthYubiKeyTimeout {}'.format(authn_yubikey_config.get('AuthYubiKeyTimeout', 3600)),
                '  AuthYubiKeyRequireSecure {}'.format(
                    'On' if authn_yubikey_config.get('AuthYubiKeyRequireSecure', True) else 'Off'
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
    return metadata, DONE


@metadata_processor
def add_check_mk_tags(metadata):
    if node.has_bundle('check_mk_agent'):
        metadata.setdefault('check_mk', {})
        metadata['check_mk'].setdefault('tags', [])

        ports = get_used_ports(metadata)
        for port, protocoll in ports.items():
            tag = get_tag_from_port(port, protocoll)

            if tag not in metadata['check_mk']['tags']:
                metadata['check_mk']['tags'] += [tag, ]

    return metadata, DONE


@metadata_processor
def add_check_mk_test(metadata):
    if node.has_bundle('check_mk_agent'):
        if not metadata.get('check_mk', {}).get('servers', []):
            return metadata, RUN_ME_AGAIN

        ports = get_used_ports(metadata)
        # tag = 'ssh{}'.format(metadata.get('openssl', {}).get('port', ''))
        # port = metadata.get('openssl', {}).get('port', 22)

        for check_mk_server_name in metadata['check_mk']['servers']:
            check_mk_server = repo.get_node(check_mk_server_name)

            if check_mk_server.partial_metadata == {}:
                return metadata, RUN_ME_AGAIN

            check_mk_server.partial_metadata. \
                setdefault('check_mk', {}). \
                setdefault('global_rules', {}). \
                setdefault('active_checks', {}). \
                setdefault('http', [])

            used_tags = [
                x[1] for x in check_mk_server.partial_metadata['check_mk']['global_rules']['active_checks']['http']
            ]

            for port, protocoll in ports.items():
                tag = get_tag_from_port(port, protocoll)

                if [tag, ] not in used_tags:
                    if protocoll == 'http':
                        config = (u'Webserver', {'virthost': ('$HOSTNAME$', False)})
                        description = 'HTTP Server'
                        if port != 80:
                            # TODO: add port to config
                            config = (u'Webserver', {'virthost': ('$HOSTNAME$', False)})
                            description = 'HTTP Server on Port {}'.format(port)

                        check_mk_server.partial_metadata['check_mk']['global_rules']['active_checks']['http'] += [
                            (config, [tag, ], 'ALL_HOSTS', {'description': description}),
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
                            config = ('Secure Web Server', {
                                'ssl': 'auto',
                                'virthost': ('$HOSTNAME$', False),
                                'sni': True
                            })
                            cert_config = (u'cert Age', {'cert_days': (15, 5), 'sni': True})
                            description = 'Secure HTTP Server on Port {}'.format(port)

                        check_mk_server.partial_metadata['check_mk']['global_rules']['active_checks']['http'] += [
                            (config, [tag, ], 'ALL_HOSTS', {'description': description}),
                        ]

                        check_mk_server.partial_metadata['check_mk']['global_rules']['active_checks']['http'] += [
                            (cert_config, [tag, ], 'ALL_HOSTS', {'description': "Certificate Age for {}".format(description)}),
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

    return metadata, DONE
