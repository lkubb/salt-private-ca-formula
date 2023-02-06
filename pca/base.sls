# vim: ft=sls

{#-
    Ensures an existing Salt CA is trusted.
    Pulls the root certificate to trust from the mine.
    Also upgrades ``cryptography``, if configured.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pca with context %}

{%- set ca_root = salt["mine.get"](pca.ca.minion_id, "salt_ca_root").get(pca.ca.minion_id, false) %}

{%- if pca.upgrade_cryptography %}
{%-   set onedir = grains["pythonexecutable"].endswith("/run") %}

{%-   if not onedir %}

Ensure pip is installed for pca formula:
  pkg.installed:
    - name: {{ pca.lookup.pip.pkg }}
    - reload_modules: True
{%-   endif %}

# Salt ships with cryptography by default, but its version
# is usually outdated.
Upgrade cryptography for pca formula:
  pip.installed:
    - name: {{ pca.lookup.pip.cryptography }}
    - upgrade: true
    - reload_modules: True
{%-   if not onedir %}
    - require:
      - pkg: {{ pca.lookup.pip.pkg }}
{%-   endif %}
{%- endif %}

Ensure PKI dir exists with correct perms:
  file.directory:
    - name: {{ pca.lookup.pki_dir }}
    - mode: '0644'
    - user: root
    - group: {{ pca.lookup.rootgroup }}
    - makedirs: true

Ensure CA dir exists with correct perms:
  file.directory:
    - name: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name) }}
    - mode: '0600'
    - user: root
    - group: {{ pca.lookup.rootgroup }}
    - require:
      - file: {{ pca.lookup.pki_dir }}

{%- if ca_root %}

Trust CA root cert:
{%-   if "ca_bundle_file" in pca.lookup %}
  x509.pem_managed:
    - name: {{ salt["file.dirname"](ca_bundle_file) | path_join("salt_ca_root.crt") }}
    - text: {{ ca_root | json }}
    - require:
      - Install prerequisites for x509 module
  # OpenBSD only needs append
  file.append:
    - name: {{ pca.lookup.ca_bundle_file }}
    - source: {{ salt["file.dirname"](ca_bundle_file) | path_join("salt_ca_root.crt") }}
    - require:
      - x509: {{ salt["file.dirname"](ca_bundle_file) | path_join("salt_ca_root.crt") }}
{%-   else %}
  file.directory:
    - name: {{ pca.lookup.ca_bundle_path }}
    - user: root
    - group: {{ pca.lookup.rootgroup }}
    - mode: '0755'
    - makedirs: true
  x509.pem_managed:
    - name: {{ pca.lookup.ca_bundle_path | path_join("salt_ca_root.crt") }}
    - text: {{ ca_root | json }}
    - require:
      - file: {{ pca.lookup.ca_bundle_path }}
  cmd.run:
    - name: {{ pca.lookup.ca_bundle_update_cmd }}
    - onchanges:
      - x509: {{ pca.lookup.ca_bundle_path | path_join("salt_ca_root.crt") }}
{%-   endif %}
{%- endif %}
