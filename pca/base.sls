# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pca with context %}

{%- set ca_root = (salt["mine.get"](pca.ca.minion_id, "salt_ca_root").get(pca.ca.minion_id, {}).values() | list or [false]) | first %}

Install prerequisites for x509_v2 module:
  pkg.installed:
    - name: {{ pca.lookup.pkg.name }}
    - reload_modules: True

{%- if pca.upgrade_cryptography %}

Install pip for pca:
  pkg.installed:
    - name: {{ pca.lookup.pip.pkg }}
    - reload_modules: True

Upgrade cryptography for pca:
  pip.installed:
    - name: {{ pca.lookup.pip.cryptography }}
    - upgrade: true
    - reload_modules: True
{%- endif %}

Ensure PKI dir exists with correct perms:
  file.directory:
    - name: {{ pca.lookup.pki_dir }}
    - mode: '0600'
    - user: root
    - group: {{ pca.lookup.rootgroup }}
    - makedirs: true

{%- if ca_root %}

Trust CA root cert:
{%-   if "ca_bundle_file" in pca.lookup %}
  x509_v2.pem_managed:
    - name: {{ salt["file.dirname"](ca_bundle_file) | path_join("salt_ca_root.crt") }}
    - text: {{ ca_root | json }}
    - require:
      - Install prerequisites for x509 module
  # OpenBSD only needs append
  file.append:
    - name: {{ pca.lookup.ca_bundle_file }}
    - source: {{ salt["file.dirname"](ca_bundle_file) | path_join("salt_ca_root.crt") }}
    - require:
      - x509_v2: {{ salt["file.dirname"](ca_bundle_file) | path_join("salt_ca_root.crt") }}
{%-   else %}
  file.directory:
    - name: {{ pca.lookup.ca_bundle_path }}
    - user: root
    - group: {{ pca.lookup.rootgroup }}
    - mode: '0755'
    - makedirs: true
  x509_v2.pem_managed:
    - name: {{ pca.lookup.ca_bundle_path | path_join("salt_ca_root.crt") }}
    - text: {{ ca_root | json }}
    - require:
      - file: {{ pca.lookup.ca_bundle_path }}
  cmd.run:
    - name: {{ pca.lookup.ca_bundle_update_cmd }}
    - onchanges:
      - x509_v2: {{ pca.lookup.ca_bundle_path | path_join("salt_ca_root.crt") }}
{%-   endif %}
{%- endif %}
