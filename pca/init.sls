# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pca with context %}

include:
  - .base
{%- if pca.ca.minion_id == grains["id"] %}
  - .ca
{%- endif %}
