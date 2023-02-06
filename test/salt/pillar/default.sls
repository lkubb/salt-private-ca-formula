# vim: ft=yaml
---
pca:
  lookup:
    master: template-master
    # Just for testing purposes
    winner: lookup
    added_in_lookup: lookup_value
    pkg:
      name: python3-cryptography
    ca_bundle_path: /etc/pki/ca-trust/source/anchors
    ca_bundle_update_cmd: update-ca-trust
    ca_name: salt_ca
    pip:
      cryptography: cryptography
      pkg: python3-pip
    pki_dir: /etc/pki
  ca:
    extra_info: {}
    key_algo: rsa
    keysize: 4096
    name: ''
    self_signed: true
    self_signed_valid: 3655
  upgrade_cryptography: false

  tofs:
    # The files_switch key serves as a selector for alternative
    # directories under the formula files directory. See TOFS pattern
    # doc for more info.
    # Note: Any value not evaluated by `config.get` will be used literally.
    # This can be used to set custom paths, as many levels deep as required.
    files_switch:
      - any/path/can/be/used/here
      - id
      - roles
      - osfinger
      - os
      - os_family
    # All aspects of path/file resolution are customisable using the options below.
    # This is unnecessary in most cases; there are sensible defaults.
    # Default path: salt://< path_prefix >/< dirs.files >/< dirs.default >
    #         I.e.: salt://pca/files/default
    # path_prefix: template_alt
    # dirs:
    #   files: files_alt
    #   default: default_alt
    # The entries under `source_files` are prepended to the default source files
    # given for the state
    # source_files:
    #   pca-config-file-file-managed:
    #     - 'example_alt.tmpl'
    #     - 'example_alt.tmpl.jinja'

    # For testing purposes
    source_files:
      pca-config-file-file-managed:
        - 'example.tmpl.jinja'

  # Just for testing purposes
  winner: pillar
  added_in_pillar: pillar_value
