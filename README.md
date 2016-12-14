NDN Certificate Management Protocol (NDNCERT)
=============================================

NDN certificate management protocol (NDNCERT) enables automatic certificate management in
NDN. In Named Data Networking (NDN), every entity should have corresponding identity
(namespace) and the corresponding certificate for this namespace. Moreover, entities need
simple mechanisms to manage sub-identities and their certificates. NDNCERT provides flexible
mechanisms to request certificate from a certificate authority(CA) and, as soon as certificate
is obtained, mechanisms to issue and manage certificates in the designated namespace. Note that
NDNCERT does not impose any specific trust model or trust anchors.  While the primary use case
of the developed protocol is to manage NDN testbed certificates, it can be used with any other
set of global and local trust anchors.

This specification provides details and packet formats to request certificates, create
certificates after one of the validation mechanism, and how the issued certificate is retrieved
by the original requester.

[See detail on our github wiki page.](https://github.com/named-data/ndncert/wiki/NDN-Certificate-Management-Protocol)
