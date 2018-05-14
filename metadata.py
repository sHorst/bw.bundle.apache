@metadata_processor
def add_iptables_rules(metadata):
    if node.has_bundle("iptables"):
        ports = {}
        for vhost_name in metadata.get('apache', {}).get('vhosts', {}).keys():
            vhost = metadata['apache']['vhosts'][vhost_name]
            for port in vhost.get('ports', {}).get('http', [80]):
                ports[port] = True
            for port in vhost.get('ports', {}).get('https', [443]):
                ports[port] = True

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
