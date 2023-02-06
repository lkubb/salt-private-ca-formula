# vim: ft=sls

{#-
    Always ensures the Salt CA is present in the system's CA bundle
    and thus trusted.

    If the configured CA minion's ID matches this minion's ID,
    includes `pca.ca`_ as well.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pca with context %}

include:
  - .base
{%- if pca.ca.minion_id == grains["id"] %}
  - .ca
{%- endif %}
