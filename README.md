# NDNCERT: NDN Certificate Management Protocol

![Language](https://img.shields.io/badge/C%2B%2B-17-blue)
[![CI](https://github.com/named-data/ndncert/actions/workflows/ci.yml/badge.svg)](https://github.com/named-data/ndncert/actions/workflows/ci.yml)

The NDN certificate management protocol (**NDNCERT**) enables automatic certificate management
in NDN. In Named Data Networking (NDN), every entity should have a corresponding identity
(namespace) and the corresponding certificate for this namespace. Moreover, entities need simple
mechanisms to manage sub-identities and their certificates. NDNCERT provides flexible mechanisms
to request certificates from a certificate authority (CA) and, as soon as the certificate is
obtained, mechanisms to issue and manage certificates in the designated namespace. Note that
NDNCERT does not impose any specific trust model or trust anchors. While the primary use case of
this protocol is to manage NDN testbed certificates, it can be used with any other set of global
and local trust anchors.

See [our GitHub wiki](https://github.com/named-data/ndncert/wiki) for more details.

## Reporting bugs

Please submit any bug reports or feature requests to the
[NDNCERT issue tracker](https://redmine.named-data.net/projects/ndncert/issues).

## Contributing

We greatly appreciate contributions to the NDNCERT code base, provided that they are
licensed under the GNU GPL version 3 or a compatible license.
If you are new to the NDN software community, please read our [Contributor's Guide](
https://github.com/named-data/.github/blob/main/CONTRIBUTING.md) to get started.

## License

NDNCERT is free software distributed under the GNU General Public License version 3.
See [`COPYING.md`](COPYING.md) for details.
