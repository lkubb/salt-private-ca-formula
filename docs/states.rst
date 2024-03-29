Available states
----------------

The following states are found in this formula:

.. contents::
   :local:


``pca``
^^^^^^^
Always ensures the Salt CA is present in the system's CA bundle
and thus trusted.

If the configured CA minion's ID matches this minion's ID,
includes `pca.ca`_ as well.


``pca.base``
^^^^^^^^^^^^
Ensures an existing Salt CA is trusted.
Pulls the root certificate to trust from the mine.

Should work for Linux/BSD and MacOS. For the latter,
this requires the `macprofile module <https://github.com/lkubb/salt-tool-macos-formula>`_,
which will install the necessary profile interactively.


``pca.ca``
^^^^^^^^^^
Configures a certificate authority:

* creates a root certificate or a CSR, if not ``ca:self_signed``
* if not ``ca:self_signed``, saves the configured root certificate
* publishes the root certificate to the mine


``pca.clean``
^^^^^^^^^^^^^
Does nothing currently.


