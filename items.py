from bundlewrap.exceptions import BundleError
from os.path import dirname

# noinspection PyGlobalUndefined
global node

pkg_apt = {
    "apache2": {
        "installed": True,
    }
}

svc_systemd = {
    "apache2": {
        'needs': ['pkg_apt:apache2'],
    }
}

files = {
    '/etc/apache2/conf-available/ocsp_stapling.conf': {
        'content': 'SSLStaplingCache shmcb:/tmp/stapling_cache(128000)',
        'mode': "0640",
        'owner': 'root',
        'group': 'root',
        'needs': [
            "pkg_apt:apache2"
        ],

    }
}
directories = {}
symlinks = {
    '/etc/apache2/conf-enabled/ocsp_stapling.conf': {
        "target": '/etc/apache2/conf-available/ocsp_stapling.conf',
        "group": "root",
        "owner": "root",
        'needs': [
            'file:/etc/apache2/conf-available/ocsp_stapling.conf',
        ],
        'needed_by': [
            "svc_systemd:apache2"
        ],
        'triggers': [
            "svc_systemd:apache2:restart"
        ],
    }
}

actions = {}

if 'apache' in node.metadata:
    for module_name, config in node.metadata['apache'].get('modules', {}).items():
        apt = config.get('apt', None)
        git = config.get('git', None)

        if config.get('enabled', False):
            if apt:
                pkg_apt[apt] = {
                    'installed': True,
                    'needed_by': [
                        'symlink:/etc/apache2/mods-enabled/{}.load'.format(module_name),
                        'symlink:/etc/apache2/mods-enabled/{}.conf'.format(module_name),
                    ]
                }
            elif git:
                actions['git_clone_apache_{}'.format(module_name)] = {
                    'command': 'cd /tmp && rm -rf apache_{name} && git clone {git} apache_{name}'.format(
                        git=git,
                        name=module_name
                    ),
                    "unless": "test -f /etc/apache2/mods-available/{}.load".format(module_name),
                    'needs': [
                        'pkg_apt:git',
                        'file:/etc/sudoers',  # This is needed, so the SSH_AUTH_SOCK is in the env
                    ],
                }

                last_action = 'git_clone_apache_{}'.format(module_name)
                count = 1
                for command in config.get('install_commands', []):
                    new_action = 'apache_{}_action_{}'.format(module_name, count)
                    actions[new_action] = {
                        'command': "cd /tmp/apache_{name} && {command}".format(name=module_name, command=command),
                        'needs': [
                            'action:{}'.format(last_action)
                        ],
                        "unless": "test -f /etc/apache2/mods-available/{}.load".format(module_name),
                    }

                    last_action = new_action
                    count += 1

            symlinks['/etc/apache2/mods-enabled/{}.load'.format(module_name)] = {
                "group": "root",
                "owner": "root",
                "target": "../mods-available/{}.load".format(module_name),
                "unless": "test ! -f /etc/apache2/mods-available/{}.load".format(module_name),
                'needs': [
                    'pkg_apt:apache2',
                ],
                'needed_by': [
                    "svc_systemd:apache2"
                ],
                'triggers': [
                    "svc_systemd:apache2:restart"
                ],
            }
            symlinks['/etc/apache2/mods-enabled/{}.conf'.format(module_name)] = {
                "group": "root",
                "owner": "root",
                "target": "../mods-available/{}.conf".format(module_name),
                "unless": "test ! -f /etc/apache2/mods-available/{}.conf".format(module_name),
                'needs': [
                    'pkg_apt:apache2',
                ],
                'needed_by': [
                    "svc_systemd:apache2"
                ],
                'triggers': [
                    "svc_systemd:apache2:restart"
                ],
            }

            if 'config' in config:
                files['/etc/apache2/mods-available/{}.conf'.format(module_name)] = {
                    'content': "\n".join(config['config']) + "\n",
                    "group": "root",
                    "owner": "root",
                    'mode': '0644',
                    'needed_by': [
                        "svc_systemd:apache2"
                    ],
                    'triggers': [
                        "svc_systemd:apache2:restart"
                    ],
                }

        else:
            files['/etc/apache2/mods-enabled/{}.load'.format(module_name)] = {
                'delete': True,
                'needs': [
                    'pkg_apt:apache2',
                ],
                'needed_by': [
                    "svc_systemd:apache2"
                ],
                'triggers': [
                    "svc_systemd:apache2:restart"
                ],
            }
            files['/etc/apache2/mods-enabled/{}.conf'.format(module_name)] = {
                'delete': True,
                'needs': [
                    'pkg_apt:apache2',
                ],
                'needed_by': [
                    "svc_systemd:apache2"
                ],
                'triggers': [
                    "svc_systemd:apache2:restart"
                ],
            }

    for vhost_name in node.metadata['apache'].get('vhosts', {}):
        vhost = node.metadata['apache']['vhosts'][vhost_name]

        # TODO: set ports also in apache config otherwise apache does not listen on those ports
        protocols = {'http': vhost.get('ports', {}).get('http', [80])}
        if vhost.get('ssl', False):
            if not vhost.get('ssl_crt', False) or not vhost.get('ssl_key', False):
                raise BundleError("ssl_crt or ssl_key not set but ssl is enabled for vhost {}".format(vhost_name))

            protocols['https'] = vhost.get('ports', {}).get('https', [443])

            directory_crt = dirname(vhost.get('ssl_crt'))
            directory_key = dirname(vhost.get('ssl_key'))

            directories[directory_crt] = {
                'mode': '755',
                'owner': 'root',
                'group': 'root',
            }

            needed_by_action = ["pkg_apt:openssl", 'directory:{}'.format(directory_crt)]

            if directory_key != directory_crt:
                directories[directory_key] = {
                    'mode': '755',
                    'owner': 'root',
                    'group': 'root',
                }

                needed_by_action += 'diroctory:{}'.format(directory_key)

            actions['generate_sneakoil_{}'.format(vhost_name)] = {
                'command': 'openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 '
                           '-subj "{}" -keyout {} -out {}'.format(
                                "/C=DE/ST=NRW/L=Aachen/O=ScoutNet/CN={}".format(vhost_name),
                                vhost.get('ssl_key'),
                                vhost.get('ssl_crt'),
                            ),
                'unless': 'test -f {} && test -f {}'.format(vhost.get('ssl_key'), vhost.get('ssl_crt')),
                'needs': needed_by_action,
                'cascade_skip': False,
                'needed_by': [
                    "svc_systemd:apache2"
                ],
            }

        # change document root if we use suexec
        if 'suexec' in vhost:
            vhost['document_root'] = "{}/web/htdocs/public_html".format(
                vhost.get(
                    'document_root', '/var/www/{}'.format(vhost['suexec']['user'])
                )
            )

            pkg_apt['apache2-suexec-custom'] = {
                'installed': True,
                'needed_by': ["svc_systemd:apache2"],
            }
            pkg_apt['libapache2-mod-fcgid'] = {
                'installed': True,
                'needed_by': ["svc_systemd:apache2"],
            }

        additional_configs = []

        for additional_config_name, additional_config in sorted(
                vhost.get('additional_config', {}).items(),
                key=lambda x: x[0]
        ):
            additional_configs += additional_config

        files['/etc/apache2/sites-available/{}.conf'.format(vhost_name)] = {
            'source': "template.conf",
            'content_type': 'jinja2',
            'mode': "0640",
            'owner': 'root',
            'group': 'root',
            'context': {
                'vhost_name': vhost_name,
                'vhost': vhost,
                'protocols': protocols,
                'additional_config': additional_configs,
            },
            'triggers': [
                "svc_systemd:apache2:restart"
            ],
        }

        if vhost.get('default', False):
            symlink_name = '001-{}.conf'.format(vhost_name)
            deleted_symlink_name = '{}.conf'.format(vhost_name)
        else:
            symlink_name = '{}.conf'.format(vhost_name)
            deleted_symlink_name = '001-{}.conf'.format(vhost_name)

        if vhost.get('enabled', False):
            symlinks['/etc/apache2/sites-enabled/{}'.format(symlink_name)] = {
                "group": "root",
                "owner": "root",
                "target": "../sites-available/{}.conf".format(vhost_name),
                'needs': ['file:/etc/apache2/sites-available/{}.conf'.format(vhost_name)],
                'triggers': [
                    "svc_systemd:apache2:restart"
                ],
            }
        else:
            files['/etc/apache2/sites-enabled/{}'.format(symlink_name)] = {
                'delete': True,
                'triggers': [
                    "svc_systemd:apache2:restart"
                ],
            }

        # delete the other filename 001-vhost_name.conf or vhost_name.conf
        files['/etc/apache2/sites-enabled/{}'.format(deleted_symlink_name)] = {
            'delete': True,
            'triggers': [
                "svc_systemd:apache2:restart"
            ],
        }

    # delete the default symlink
    files['/etc/apache2/sites-enabled/000-default.conf'] = {
        'delete': True,
        'triggers': [
            "svc_systemd:apache2:restart"
        ],
    }
