# vim: ft=sls

{#-
    Configures a certificate authority:

    * creates a root certificate or a CSR, if not ``ca:self_signed``
    * if not ``ca:self_signed``, saves the configured root certificate
    * publishes the root certificate to the mine
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_base = tplroot ~ ".base" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pca with context %}

include:
  - {{ sls_base }}


Ensure CA certs dir exists with correct perms:
  file.directory:
    - name: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "issued_certs") }}
    - mode: '0700'
    - user: root
    - group: {{ pca.lookup.rootgroup }}
    - require:
      - sls: {{ sls_base }}

Manage CA singing key:
  x509.private_key_managed:
    - name: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "salt_ca.key") }}
    - algo: {{ pca.ca.key_algo }}
    - keysize: {{ pca.ca.keysize if pca.ca.key_algo in ["rsa", "ec"] else "null" }}
    - user: root
    - group: {{ pca.lookup.rootgroup }}
    - mode: '0400'
    - require:
      - Ensure CA certs dir exists with correct perms

{%- if pca.ca.self_signed %}

Manage self-signed root CA cert:
  x509.certificate_managed:
    - name: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "salt_ca.crt") }}
    - signing_private_key: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "salt_ca.key") }}
    - CN: {{ pca.ca.name or grains["id"] }}
    - basicConstraints: "critical, CA:true"
    - keyUsage: "critical, cRLSign, keyCertSign"
    - subjectKeyIdentifier: hash
    - authorityKeyIdentifier: keyid:always
    - days_valid: {{ pca.ca.self_signed_valid }}
    - days_remaining: 0
{%-   for var, val in pca.ca.extra_info.items() %}
    - {{ var }}: {{ val }}
{%-   endfor %}
    - require:
      - Manage CA singing key
  # ensure the minions can access it as salt_ca_root
  file.symlink:
    - name: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "salt_ca_root.crt") }}
    - target: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "salt_ca.crt") }}
    - require:
      - x509: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "salt_ca.crt") }}
{%- else %}

Manage certificate signing request for intermediate CA:
  x509.csr_managed:
    - name: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "salt_ca.csr") }}
    - private_key: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "salt_ca.key") }}
    - CN: {{ pca.ca.name or grains["id"] }}
    - basicConstraints: "critical, CA:true"
    - keyUsage: "critical, cRLSign, keyCertSign"
    - subjectKeyIdentifier: hash
{%-   for var, val in pca.ca.extra_info.items() %}
    - {{ var }}: {{ val }}
{%-   endfor %}
    - require:
      - Manage CA singing key

CA root cert is managed:
  # this does not need to ensure trust, only keep track of the root cert
  x509.pem_managed:
    - name: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "salt_ca_root.crt") }}
    - text: {{ pca.ca.root_crt | json }}
    - makedirs: true
    - mode: '0644'
    - dir_mode: '0755'
    - user: root
    - group: {{ pca.lookup.rootgroup }}
    - require:
      - sls: {{ sls_base }}
{%- endif %}

Publish CA root certificate to the mine:
  module.run:
    - mine.send:
      - name: salt_ca_root
      - mine_function: x509.get_pem_entry
      - text: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "salt_ca_root.crt") }}
    - onchanges:
      - x509: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "salt_ca.crt" if pca.ca.self_signed else "salt_ca_root.crt") }}

{%- if not pca.ca.self_signed %}

Publish CA intermediate certificate to the mine:
  module.run:
    - mine.send:
      - name: salt_ca_intermediate
      - mine_function: x509.get_pem_entry
      - text: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name, "salt_ca.crt") }}
{%- endif %}
# This intentionally does not manage minion config
# (x509_signing_policies/mine_functions)
# x509_signing_policies can be set in pillar
