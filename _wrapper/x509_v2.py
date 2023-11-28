"""
Manage X.509 certificates
=========================

Configuration instructions and general remarks are documented
in the :ref:`execution module docs <x509-setup>`.

Configuration
-------------
Explicit activation
~~~~~~~~~~~~~~~~~~~
Since this module uses the same virtualname as the previous ``x509`` modules,
but is incompatible with them, it needs to be explicitly activated on each
SSH minion **and the master itself** (the latter one is a technical limitation/
bordering a bug: The wrapper modules are loaded with the master opts the first time
and only those that were registered successfully will be reloaded with the
merged opts after).

.. code-block:: yaml

    # /etc/salt/master.d/x509.conf

    features:
      x509_v2: true
    ssh_minion_opts:
      features:
        x509_v2: true
"""
import base64
import copy
import logging
import time
from pathlib import Path

try:
    import x509util

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

import salt.utils.dictupdate
import salt.utils.files
import salt.utils.stringutils
from salt.exceptions import CommandExecutionError, SaltInvocationError

log = logging.getLogger(__name__)


__virtualname__ = "x509"


def __virtual__():
    if not HAS_CRYPTOGRAPHY:
        return (False, "Could not load cryptography")
    # salt.features appears to not be setup when invoked via peer publishing
    if not __opts__.get("features", {}).get("x509_v2"):
        return (
            False,
            "x509_v2 needs to be explicitly enabled by setting `x509_v2: true` "
            "in the minion configuration value `features` until Salt 3008 (Argon).",
        )
    return __virtualname__


def create_certificate(
    ca_server=None,
    signing_policy=None,
    encoding="pem",
    append_certs=None,
    pkcs12_passphrase=None,
    pkcs12_encryption_compat=False,
    pkcs12_friendlyname=None,
    path=None,
    overwrite=True,
    raw=False,
    **kwargs,
):
    """
    Create an X.509 certificate and return an encoded version of it.

    .. note::

        All parameters that take a public key, private key or certificate
        can be specified either as a PEM/hex/base64 string or a path to a
        local file encoded in all supported formats for the type.

    CLI Example:

    .. code-block:: bash

        salt '*' x509.create_certificate signing_private_key='/etc/pki/myca.key' csr='/etc/pki/my.csr'

    ca_server
        Request a remotely signed certificate from ca_server. For this to
        work, a ``signing_policy`` must be specified, and that same policy
        must be configured on the ca_server. See `Signing policies`_ for
        details. Also, the Salt master must permit peers to call the
        ``sign_remote_certificate`` function, see `Peer communication`_.

    signing_policy
        The name of a configured signing policy. Parameters specified in there
        are hardcoded and cannot be overridden. This is required for remote signing,
        otherwise optional. See `Signing policies`_ for details.

    encoding
        Specify the encoding of the resulting certificate. It can be returned
        as a ``pem`` (or ``pkcs7_pem``) string or several (base64-encoded)
        binary formats (``der``, ``pkcs7_der``, ``pkcs12``). Defaults to ``pem``.

    append_certs
        A list of additional certificates to append to the new one, e.g. to create a CA chain.

        .. note::

            Mind that when ``der`` encoding is in use, appending certificatees is prohibited.

    copypath
        Create a copy of the issued certificate in PEM format in this directory.
        The file will be named ``<serial_number>.crt`` if prepend_cn is False.

    prepend_cn
        When ``copypath`` is set, prepend the common name of the certificate to
        the file name like so: ``<CN>-<serial_number>.crt``. Defaults to false.

    pkcs12_passphrase
        When encoding a certificate as ``pkcs12``, encrypt it with this passphrase.

        .. note::

            PKCS12 encryption is very weak and `should not be relied on for security <https://cryptography.io/en/stable/hazmat/primitives/asymmetric/serialization/#cryptography.hazmat.primitives.serialization.pkcs12.serialize_key_and_certificates>`_.

    pkcs12_encryption_compat
        OpenSSL 3 and cryptography v37 switched to a much more secure default
        encryption for PKCS12, which might be incompatible with some systems.
        This forces the legacy encryption. Defaults to False.

    pkcs12_friendlyname
        When encoding a certificate as ``pkcs12``, a name for the certificate can be included.

    path
        Instead of returning the certificate, write it to this file path.

    overwrite
        If ``path`` is specified and the file exists, overwrite it.
        Defaults to true.

    raw
        Return the encoded raw bytes instead of a string. Defaults to false.

    digest
        The hashing algorithm to use for the signature. Valid values are:
        sha1, sha224, sha256, sha384, sha512, sha512_224, sha512_256, sha3_224,
        sha3_256, sha3_384, sha3_512. Defaults to ``sha256``.
        This will be ignored for ``ed25519`` and ``ed448`` key types.

    private_key
        The private key corresponding to the public key the certificate should
        be issued for. This is one way of specifying the public key that will
        be included in the certificate, the other ones being ``public_key`` and ``csr``.

    private_key_passphrase
        If ``private_key`` is specified and encrypted, the passphrase to decrypt it.

    public_key
        The public key the certificate should be issued for. Other ways of passing
        the required information are ``private_key`` and ``csr``. If neither are set,
        the public key of the ``signing_private_key`` will be included, i.e.
        a self-signed certificate is generated.

    csr
        A certificate signing request to use as a base for generating the certificate.
        The following information will be respected, depending on configuration:
        * public key
        * extensions, if not otherwise specified (arguments, signing_policy)

    signing_cert
        The CA certificate to be used for signing the issued certificate.

    signing_private_key
        The private key corresponding to the public key in ``signing_cert``. Required.

    signing_private_key_passphrase
        If ``signing_private_key`` is encrypted, the passphrase to decrypt it.

    serial_number
        A serial number to be embedded in the certificate. If unspecified, will
        autogenerate one. This should be an integer, either in decimal or
        hexadecimal notation.

    not_before
        Set a specific date the certificate should not be valid before.
        The format should follow ``%Y-%m-%d %H:%M:%S`` and will be interpreted as GMT/UTC.
        Defaults to the time of issuance.

    not_after
        Set a specific date the certificate should not be valid after.
        The format should follow ``%Y-%m-%d %H:%M:%S`` and will be interpreted as GMT/UTC.
        If unspecified, defaults to the current time plus ``days_valid`` days.

    days_valid
        If ``not_after`` is unspecified, the number of days from the time of issuance
        the certificate should be valid for. Defaults to ``30``.

    subject
        The subject's distinguished name embedded in the certificate. This is one way of
        passing this information (see ``kwargs`` below for the other).
        This argument will be preferred and allows to control the order of RDNs in the DN
        as well as to embed RDNs with multiple attributes.
        This can be specified as an RFC4514-encoded string (``CN=example.com,O=Example Inc,C=US``,
        mind that the rendered order is reversed from what is embedded), a list
        of RDNs encoded as in RFC4514 (``["C=US", "O=Example Inc", "CN=example.com"]``)
        or a dictionary (``{"CN": "example.com", "C": "US", "O": "Example Inc"}``,
        default ordering).
        Multiple name attributes per RDN are concatenated with a ``+``.

        .. note::

            Parsing of RFC4514 strings requires at least cryptography release 37.

    kwargs
        Embedded X.509v3 extensions and the subject's distinguished name can be
        controlled via supplemental keyword arguments. See the following for an overview.

    Subject properties in kwargs
        C, ST, L, STREET, O, OU, CN, MAIL, SN, GN, UID, SERIALNUMBER

    X.509v3 extensions in kwargs
        Most extensions can be configured using the same string format as OpenSSL,
        while some require adjustments. In general, since the strings are
        parsed to dicts/lists, you can always use the latter formats directly.
        Marking an extension as critical is done by including it at the beginning
        of the configuration string, in the list or as a key in the dictionary
        with the value ``true``.

        Examples (some showcase dict/list correspondance):

        basicConstraints
            ``critical, CA:TRUE, pathlen:1`` or

            .. code-block:: yaml

                - basicConstraints:
                    critical: true
                    ca: true
                    pathlen: 1

        keyUsage
            ``critical, cRLSign, keyCertSign`` or

            .. code-block:: yaml

                - keyUsage:
                    - critical
                    - cRLSign
                    - keyCertSign

        subjectKeyIdentifier
            This can be an explicit value or ``hash``, in which case the value
            will be set to the SHA1 hash of some encoding of the associated public key,
            depending on the underlying algorithm (RSA/ECDSA/EdDSA).

        authorityKeyIdentifier
            ``keyid:always, issuer``

        subjectAltName
            There is support for all OpenSSL-defined types except ``otherName``.

            ``email:me@example.com,DNS:example.com`` or

            .. code-block:: yaml

                # mind this being a list, not a dict
                - subjectAltName:
                    - email:me@example.com
                    - DNS:example.com

        issuerAltName
            The syntax is the same as for ``subjectAltName``, except that the additional
            value ``issuer:copy`` is supported, which will copy the values of
            ``subjectAltName`` in the issuer's certificate.

        authorityInfoAccess
            ``OCSP;URI:http://ocsp.example.com/,caIssuers;URI:http://myca.example.com/ca.cer``

        crlDistributionPoints
            When set to a string value, items are interpreted as fullnames:

            ``URI:http://example.com/myca.crl, URI:http://example.org/my.crl``

            There is also support for more attributes using the full form:

            .. code-block:: yaml

                - crlDistributionPoints:
                    - fullname: URI:http://example.com/myca.crl
                      crlissuer: DNS:example.org
                      reasons:
                        - keyCompromise
                    - URI:http://example.org/my.crl

        certificatePolicies
            ``critical, 1.2.4.5, 1.1.3.4``

            Again, there is support for more attributes using the full form:

            .. code-block:: yaml

                - certificatePolicies:
                    critical: true
                    1.2.3.4.5: https://my.ca.com/pratice_statement
                    1.2.4.5.6:
                      - https://my.ca.com/pratice_statement
                      - organization: myorg
                        noticeNumbers: [1, 2, 3]
                        text: mytext

        policyConstraints
            ``requireExplicitPolicy:3,inhibitPolicyMapping:1``

        inhibitAnyPolicy
            The value is just an integer: ``- inhibitAnyPolicy: 1``

        nameConstraints
            ``critical,permitted;IP:192.168.0.0/255.255.0.0,permitted;email:.example.com,excluded;email:.com``

            .. code-block:: yaml

                - nameConstraints:
                    critical: true
                    permitted:
                      - IP:192.168.0.0/24
                      - email:.example.com
                    excluded:
                      - email:.com
        noCheck
            This extension does not take any values, except ``critical``. Just the presence
            in the keyword args will include it.

        tlsfeature
            ``status_request``

        For more information, visit the `OpenSSL docs <https://www.openssl.org/docs/man3.0/man5/x509v3_config.html>`_.
    """
    if raw:
        # returns are json-serialized, which does not support bytes
        raise SaltInvocationError("salt-ssh does not support the `raw` parameter")

    kwargs = {k: v for k, v in kwargs.items() if not k.startswith("_")}

    if not ca_server:
        return _check_ret(
            __salt__["x509.create_certificate_ssh"](
                signing_policy=signing_policy,
                encoding=encoding,
                append_certs=append_certs,
                pkcs12_passphrase=pkcs12_passphrase,
                pkcs12_encryption_compat=pkcs12_encryption_compat,
                pkcs12_friendlyname=pkcs12_friendlyname,
                path=path,
                overwrite=overwrite,
                raw=raw,
                **kwargs,
            )
        )

    # Deprecation checks vs the old x509 module
    if "algorithm" in kwargs:
        salt.utils.versions.warn_until(
            "Potassium",
            "`algorithm` has been renamed to `digest`. Please update your code.",
        )
        kwargs["digest"] = kwargs.pop("algorithm")

    ignored_params = {"text", "version", "serial_bits"}.intersection(
        kwargs
    )  # path, overwrite
    if ignored_params:
        salt.utils.versions.kwargs_warn_until(ignored_params, "Potassium")
    kwargs = x509util.ensure_cert_kwargs_compat(kwargs)

    if "days_valid" not in kwargs and "not_after" not in kwargs:
        try:
            salt.utils.versions.warn_until(
                "Potassium",
                "The default value for `days_valid` will change to 30. Please adapt your code accordingly.",
            )
            kwargs["days_valid"] = 365
        except RuntimeError:
            pass

    if encoding not in ["der", "pem", "pkcs7_der", "pkcs7_pem", "pkcs12"]:
        raise CommandExecutionError(
            f"Invalid value '{encoding}' for encoding. Valid: "
            "der, pem, pkcs7_der, pkcs7_pem, pkcs12"
        )
    if kwargs.get("digest", "sha256").lower() not in [
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha512_224",
        "sha512_256",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
    ]:
        raise CommandExecutionError(
            f"Invalid value '{kwargs['digest']}' for digest. Valid: sha1, sha224, "
            "sha256, sha384, sha512, sha512_224, sha512_256, sha3_224, sha3_256, "
            "sha3_384, sha3_512"
        )
    if encoding == "der" and append_certs:
        raise SaltInvocationError("Cannot encode a certificate chain in DER")
    if encoding == "pkcs12" and "private_key" not in kwargs:
        # The creation will work, but it will be listed in additional certs, not
        # as the main certificate. This might confuse other parts of the code.
        raise SaltInvocationError(
            "Creating a PKCS12-encoded certificate without embedded private key "
            "is unsupported"
        )

    if path and not overwrite and _check_ret(__salt__["file.file_exists"](path)):
        return f"The file at {path} exists and overwrite was set to false"
    if signing_policy is None:
        raise SaltInvocationError(
            "signing_policy must be specified to request a certificate from "
            "a remote ca_server"
        )
    cert, private_key_loaded = _create_certificate_remote(
        ca_server, signing_policy, **kwargs
    )

    if encoding == "pkcs12":
        out = _check_ret(
            __salt__["x509.encode_certificate"](
                x509util.to_pem(cert).decode(),
                append_certs=append_certs,
                encoding=encoding,
                private_key=private_key_loaded,
                pkcs12_passphrase=pkcs12_passphrase,
                pkcs12_encryption_compat=pkcs12_encryption_compat,
                pkcs12_friendlyname=pkcs12_friendlyname,
                raw=False,
            )
        )
    else:
        out = _check_ret(
            __salt__["x509.encode_certificate"](
                x509util.to_pem(cert).decode(),
                append_certs=append_certs,
                encoding=encoding,
                raw=False,
            )
        )

    if path is None:
        return out

    if encoding == "pem":
        return _check_ret(
            __salt__["x509.write_pem"](
                out, path, overwrite=overwrite, pem_type="CERTIFICATE"
            )
        )
    _check_ret(__salt__["hashutil.base64_decodefile"](out, path))
    return f"Certificate written to {path}"


def _query_remote(ca_server, signing_policy, kwargs, get_signing_policy_only=False):
    result = publish(
        ca_server,
        "x509.sign_remote_certificate",
        arg=[signing_policy, kwargs, get_signing_policy_only],
    )

    if not result:
        raise SaltInvocationError(
            "ca_server did not respond."
            " Salt master must permit peers to"
            " call the sign_remote_certificate function."
        )
    result = result[next(iter(result))]
    if not isinstance(result, dict) or "data" not in result:
        log.error(f"Received invalid return value from ca_server: {result}")
        raise CommandExecutionError(
            "Received invalid return value from ca_server. See minion log for details"
        )
    if result.get("errors"):
        raise CommandExecutionError(
            "ca_server reported errors:\n" + "\n".join(result["errors"])
        )
    return result["data"]


def _create_certificate_remote(
    ca_server, signing_policy, private_key=None, private_key_passphrase=None, **kwargs
):
    private_key_loaded = None
    if private_key:
        kwargs["public_key"] = _check_ret(
            __salt__["x509.get_public_key"](
                private_key, passphrase=private_key_passphrase
            )
        )
    elif kwargs.get("public_key"):
        kwargs["public_key"] = _check_ret(
            __salt__["x509.get_public_key"](kwargs["public_key"])
        )

    if kwargs.get("csr"):
        try:
            # Check if the data can be interpreted as a Path at all
            Path(kwargs["csr"])
        except TypeError:
            pass
        else:
            if _check_ret(__salt__["file.file_exists"](kwargs["csr"])):
                kwargs["csr"] = base64.b64decode(
                    _check_ret(__salt__["hashutil.base64_encodefile"](kwargs["csr"]))
                )

    result = _query_remote(ca_server, signing_policy, kwargs)
    try:
        return x509util.load_cert(result), private_key_loaded
    except (CommandExecutionError, SaltInvocationError) as err:
        raise CommandExecutionError(
            f"ca_server did not return a certificate: {result}"
        ) from err


def get_signing_policy(signing_policy, ca_server=None):
    """
    Returns the specified named signing policy.

    CLI Example:

    .. code-block:: bash

        salt '*' x509.get_signing_policy www

    signing_policy
        The name of the signing policy to return.

    ca_server
        If this is set, the CA server will be queried for the
        signing policy instead of looking it up locally.
    """
    if ca_server is None:
        policy = _get_signing_policy(signing_policy)
    else:
        # Cache signing policies from remote during this run
        # to reduce unnecessary resource usage.
        ckey = "_x509_policies"
        if ckey not in __context__:
            __context__[ckey] = {}
        if ca_server not in __context__[ckey]:
            __context__[ckey][ca_server] = {}
        if signing_policy not in __context__[ckey][ca_server]:
            policy_ = _query_remote(
                ca_server, signing_policy, {}, get_signing_policy_only=True
            )
            if "signing_cert" in policy_:
                policy_["signing_cert"] = x509util.to_pem(
                    x509util.load_cert(policy_["signing_cert"])
                ).decode()
            __context__[ckey][ca_server][signing_policy] = policy_
        # only hand out copies of the cached policy
        policy = copy.deepcopy(__context__[ckey][ca_server][signing_policy])

    # Don't immediately break for the long form of name attributes
    for name, long_names in x509util.NAME_ATTRS_ALT_NAMES.items():
        for long_name in long_names:
            if long_name in policy:
                salt.utils.versions.warn_until(
                    "Potassium",
                    f"Found {long_name} in {signing_policy}. Please migrate to the short name: {name}",
                )
                policy[name] = policy.pop(long_name)

    # Don't immediately break for the long form of extensions
    for extname, long_names in x509util.EXTENSIONS_ALT_NAMES.items():
        for long_name in long_names:
            if long_name in policy:
                salt.utils.versions.warn_until(
                    "Potassium",
                    f"Found {long_name} in {signing_policy}. Please migrate to the short name: {extname}",
                )
                policy[extname] = policy.pop(long_name)
    return policy


def _get_signing_policy(name):
    if name is None:
        return {}
    policies = __salt__["pillar.get"]("x509_signing_policies", {}).get(name)
    policies = policies or __salt__["config.get"]("x509_signing_policies", {}).get(name)
    if isinstance(policies, list):
        dict_ = {}
        for item in policies:
            dict_.update(item)
        policies = dict_
    return policies or {}


def _check_ret(ret):
    # Failing unwrapped calls to the minion always return a result dict
    # and do not throw exceptions currently.
    if isinstance(ret, dict) and ret.get("stderr"):
        raise CommandExecutionError(ret["stderr"])
    return ret


# The publish wrapper currently only publishes to SSH minions
# TODO: Add this to the wrapper - ssh_minions=[bool] and regular_minions=[bool]
def _publish(
    tgt,
    fun,
    arg=None,
    tgt_type="glob",
    returner="",
    timeout=5,
    form="clean",
    wait=False,
    via_master=None,
):
    masterapi = salt.daemons.masterapi.RemoteFuncs(__opts__["__master_opts__"])

    log.info("Publishing '%s'", fun)
    load = {
        "cmd": "minion_pub",
        "fun": fun,
        "arg": arg,
        "tgt": tgt,
        "tgt_type": tgt_type,
        "ret": returner,
        "tmo": timeout,
        "form": form,
        "id": __opts__["id"],
        "no_parse": __opts__.get("no_parse", []),
    }
    peer_data = masterapi.minion_pub(load)
    if not peer_data:
        return {}
    # CLI args are passed as strings, re-cast to keep time.sleep happy
    if wait:
        loop_interval = 0.3
        matched_minions = set(peer_data["minions"])
        returned_minions = set()
        loop_counter = 0
        while returned_minions ^ matched_minions:
            load = {
                "cmd": "pub_ret",
                "id": __opts__["id"],
                "jid": peer_data["jid"],
            }
            ret = masterapi.pub_ret(load)
            returned_minions = set(ret.keys())

            end_loop = False
            if returned_minions >= matched_minions:
                end_loop = True
            elif (loop_interval * loop_counter) > timeout:
                if not returned_minions:
                    return {}
                end_loop = True

            if end_loop:
                if form == "clean":
                    cret = {}
                    for host in ret:
                        cret[host] = ret[host]["ret"]
                    return cret
                else:
                    return ret
            loop_counter = loop_counter + 1
            time.sleep(loop_interval)
    else:
        time.sleep(float(timeout))
        load = {
            "cmd": "pub_ret",
            "id": __opts__["id"],
            "jid": peer_data["jid"],
        }
        ret = masterapi.pub_ret(load)
        if form == "clean":
            cret = {}
            for host in ret:
                cret[host] = ret[host]["ret"]
            return cret
        else:
            return ret
    return ret


def publish(
    tgt, fun, arg=None, tgt_type="glob", returner="", timeout=5, via_master=None
):
    """
    Publish a command from the minion out to other minions.

    Publications need to be enabled on the Salt master and the minion
    needs to have permission to publish the command. The Salt master
    will also prevent a recursive publication loop, this means that a
    minion cannot command another minion to command another minion as
    that would create an infinite command loop.

    The ``tgt_type`` argument is used to pass a target other than a glob into
    the execution, the available options are:

    - glob
    - pcre
    - grain
    - grain_pcre
    - pillar
    - pillar_pcre
    - ipcidr
    - range
    - compound

    .. versionchanged:: 2017.7.0
        The ``expr_form`` argument has been renamed to ``tgt_type``, earlier
        releases must use ``expr_form``.

    Note that for pillar matches must be exact, both in the pillar matcher
    and the compound matcher. No globbing is supported.

    The arguments sent to the minion publish function are separated with
    commas. This means that for a minion executing a command with multiple
    args it will look like this:

    .. code-block:: bash

        salt system.example.com publish.publish '*' user.add 'foo,1020,1020'
        salt system.example.com publish.publish 'os:Fedora' network.interfaces '' grain

    CLI Example:

    .. code-block:: bash

        salt system.example.com publish.publish '*' cmd.run 'ls -la /tmp'


    .. admonition:: Attention

        If you need to pass a value to a function argument and that value
        contains an equal sign, you **must** include the argument name.
        For example:

        .. code-block:: bash

            salt '*' publish.publish test.kwarg arg='cheese=spam'

        Multiple keyword arguments should be passed as a list.

        .. code-block:: bash

            salt '*' publish.publish test.kwarg arg="['cheese=spam','spam=cheese']"


    When running via salt-call, the `via_master` flag may be set to specific which
    master the publication should be sent to. Only one master may be specified. If
    unset, the publication will be sent only to the first master in minion configuration.
    """
    return _publish(
        tgt,
        fun,
        arg=arg,
        tgt_type=tgt_type,
        returner=returner,
        timeout=timeout,
        form="clean",
        wait=True,
        via_master=via_master,
    )
