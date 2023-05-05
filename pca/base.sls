# vim: ft=sls

{#-
    Ensures an existing Salt CA is trusted.
    Pulls the root certificate to trust from the mine.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pca with context %}

{%- set ca_root = salt["mine.get"](pca.ca.minion_id, "salt_ca_root").get(pca.ca.minion_id, false) %}

Ensure PKI dir exists with correct perms:
  file.directory:
    - name: {{ pca.lookup.pki_dir }}
    - mode: '0755'
    - user: root
    - group: {{ pca.lookup.rootgroup }}
    - makedirs: true

Ensure CA dir exists with correct perms:
  file.directory:
    - name: {{ pca.lookup.pki_dir | path_join(pca.lookup.ca_name) }}
    - mode: '0700'
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
