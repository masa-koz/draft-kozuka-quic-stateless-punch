%%%
title = "Stateless Server-Assisted Hole Punching for QUIC"
abbrev = "QUIC Stateless Punch"
ipr = "trust200902"
area = "Web and Internet Transport"
workgroup = "QUIC"
keyword = ["QUIC", "NAT traversal", "hole punching", "connection migration"]
submissiontype = "IETF"
date = 2026-11-07T00:00:00Z

[seriesInfo]
name = "Internet-Draft"
value = "draft-kozuka-quic-stateless-punch-latest"
stream = "IETF"
status = "standard"

[[author]]
initials = "M."
surname = "Kozuka"
fullname = "Masahiro Kozuka"
organization = "Okayama University"
  [author.address]
  email = "kozuka@okayama-u.ac.jp"
%%%

.# Abstract

This document specifies a QUIC extension that lets two endpoints
connected through a relay establish a direct path between them when one
or both are behind Network Address Translators (NATs). The client asks
the server, over the existing connection, to send a single small "punch"
packet toward one of the client's address candidates. The server keeps
no per-attempt state and does not initiate validation of candidate
paths. After a short delay, the client validates the direct path using ordinary
client-initiated path validation as defined in RFC 9000, or ordinary
path creation as defined in RFC 10069 when QUIC multipath is in use,
and can then migrate the connection to it.

{mainmatter}

# Introduction

Two QUIC endpoints that are both behind NATs often cannot reach each
other directly, but they can establish a connection through a relay,
for example a proxy that supports
[@?I-D.ietf-masque-connect-udp-listen], or a proxy that pairs two
authenticated clients as defined in
[@?I-D.seemann-masque-connect-udp-rendezvous]. Once such a relayed
connection exists, it can carry application data immediately and also
serve as the signaling channel for discovering a direct path. If a
direct path is found, the connection can migrate to it
([@!RFC9000, section 9]); otherwise, the endpoints keep using the
relayed path.

[@?I-D.seemann-quic-nat-traversal] defines an extension for this
purpose. In its current form, the server takes an active part in every
traversal attempt: it accepts grants and requests, sends PATH_CHALLENGE
probes on unvalidated paths, issues dedicated "punching" connection IDs,
and reports the result of each attempt.

This document specifies a smaller alternative for the probing step,
based on a design suggested by Christian Huitema in the discussion of
that draft [@?ISSUE20]. The server's only extension-specific action is
to send one small, opaque packet per request. This packet creates the
binding in the server-side NAT or firewall; it is not expected to be
processed by the client. Validation of each candidate path is initiated
by the client and follows [@!RFC9000] (or [@!RFC10069]) without
modification. The only path validation the server performs is the
ordinary validation of the client's address when the client migrates
to a validated path ((#migration)).

The design has the following properties:

* The server keeps no per-attempt state.
* The server never sends PATH_CHALLENGE frames on a path before the
  client has validated that path, and each punch packet is no larger
  than the packet carrying the request that caused it.
* No new type of connection ID is introduced, and no special handling
  is needed when QUIC multipath is used.
* Only one new frame is defined.

The cost is additional latency: the client waits roughly one round-trip
time of the relayed path before sending its first probe.

Address candidates are advertised using the ALTERNATIVE_ADDRESS frame
defined in [@!I-D.munizaga-quic-alternative-server-address], as in
[@?I-D.seemann-quic-nat-traversal]. The authors' intention is that this
document serve as input to the discussion of that draft. If the
approach described here is adopted there, this document need not
proceed further.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all
capitals, as shown here.

This document uses the following terms:

Address candidate:
: A transport address (IP address and UDP port) at which an endpoint
  might be reachable, as in [@!RFC8445].

Sending base:
: The local sending context used for an address candidate, such as a
  UDP socket on a particular network interface or a tunnel. This term
  is borrowed from [@?I-D.seemann-quic-nat-traversal].

Punch request:
: A PUNCH_ME_NOW frame ((#frame)) sent by the client on a validated
  path, asking the server to send a punch packet.

Punch packet:
: A small, opaque UDP datagram that the server sends in response to a
  punch request ((#punch-packet)). Its purpose is to create a binding
  in NATs and firewalls on the server side.

Attempt:
: The sequence consisting of one punch request, the resulting punch
  packet, and the client's subsequent path validation for one pair of
  address candidates.

# Overview {#overview}

The client and server first establish a QUIC connection over a relayed
path and negotiate this extension ((#negotiation)). The server
advertises its address candidates using ALTERNATIVE_ADDRESS frames.
The client pairs them with its own candidates and, for each pair it
wants to try, performs an attempt:

1. The client sends a PUNCH_ME_NOW frame on the relayed path, naming
   its own candidate (C) and the server candidate (S).

2. The server sends one punch packet from the sending base associated
   with S to C. The server creates no path and keeps no state for the
   attempt. The punch packet creates a binding in the server-side NAT
   or firewall. It most likely does not reach the client, because the
   client-side NAT has no matching binding yet.

3. After a delay, the client sends a PATH_CHALLENGE from the base
   associated with C to S. This packet creates a binding in the
   client-side NAT and, because the server-side binding now exists,
   reaches the server.

4. The server answers with PATH_RESPONSE as it would for any
   client-initiated path validation. The response passes through both
   bindings, and the path is validated. The client can then migrate
   the connection to this path, or use it as an additional path when
   QUIC multipath is in use ((#migration)).

~~~ ascii-art
 Client        Client      Relay      Server        Server
 (base C)        NAT                    NAT        (base S)
   |              |          |           |             |
   |-- PUNCH_ME_NOW(C, S) -->|------------------------>|
   |              |          |           |             |
   |              x<-------------------- punch packet -|
   |        (no binding:     |      (binding           |
   |          dropped)       |       created)          |
   |              |          |           |             |
   |  ... client waits ~ smoothed RTT of relayed path ...
   |              |          |           |             |
   |-- PATH_CHALLENGE (to S) ------------------------->|
   |      (binding created)  |       (passes)          |
   |              |          |           |             |
   |<------------------------------- PATH_RESPONSE ----|
   |              |          |           |             |
~~~
Figure: An attempt in which both endpoints are behind NATs

This works when both NATs use endpoint-independent mapping
([@?RFC4787, section 4.1]), regardless of their filtering behavior.
NATs with endpoint-dependent mapping are discussed in (#open-issues).

# Address Candidates {#candidates}

The gathering of address candidates is out of scope for this document.
Endpoints MAY use the logic described in Sections 5.1.1 and 5.2 of
[@!RFC8445], or they MAY use address candidates provided by the
application.

The server advertises its candidates using ALTERNATIVE_ADDRESS frames
[@!I-D.munizaga-quic-alternative-server-address]. The server records
the sending base associated with each advertised address. A given
address and port appear at most once in an ALTERNATIVE_ADDRESS frame,
and in the common case each advertised address corresponds to a single
sending base. Different sending bases can, however, share an
advertised address, for example with overlapping address spaces
(Appendix B.2 of [@!RFC8445]). How the server chooses a sending base in
that case is an open issue ((#open-issues)).

The client never advertises its candidates to the server. Instead, it
names one of its candidates in each punch request. The address the
client names is the one at which it expects the server's packets to
arrive, for example a server-reflexive address in the terminology of
[@!RFC8445].

The client pairs server candidates with its own candidates. Section 5.1
of [@!RFC8445] describes one algorithm for forming and prioritizing
candidate pairs. Since pairing happens only at the client, the
endpoints do not need to agree on an algorithm.

When this extension has been negotiated, the client SHOULD NOT send a
PATH_CHALLENGE to an advertised address for which it has not sent a
punch request. The guidance in
[@!I-D.munizaga-quic-alternative-server-address] to validate
higher-priority addresses promptly still applies, but validation of
each address is preceded by a punch request.

# Punch Requests {#requests}

To start an attempt, the client sends a PUNCH_ME_NOW frame
((#frame)) on a validated path. The frame contains the client
candidate and the server candidate of the pair.

The client SHOULD send punch requests as soon as candidate pairs become
available. It MAY delay requests in order to prioritize pairs or to
limit the number of attempts in progress.

On receiving a PUNCH_ME_NOW frame, the server looks up the server
address and port among the IPv4 and IPv6 entries it has advertised in
its most recent ALTERNATIVE_ADDRESS frame.

* If there is no matching entry, the server MUST ignore the frame. This
  can happen legitimately, because the client's request might have
  been sent before it processed an ALTERNATIVE_ADDRESS frame that
  withdrew the address. The server MUST NOT treat this as a connection
  error.

* Otherwise, the server sends one punch packet ((#punch-packet)) from
  the sending base associated with the entry to the client address
  and port in the frame, subject to the limits in (#limits).

After sending the punch packet, or after ignoring the frame, the server
retains no state related to the request. In particular, the server does
not create a path, does not allocate a connection ID, and does not
report the result of the attempt.

A server MAY decline to send a punch packet for any reason, for example
because of the limits in (#limits) or local policy about acceptable
client addresses. The client learns of this only because its path
validation fails.

## Limits {#limits}

A punch request causes the server to send a packet to an address chosen
by the client, before that address has been validated. To prevent the
extension from being used for amplification, the server MUST NOT send
more than one punch packet in response to a single received packet,
regardless of how many PUNCH_ME_NOW frames that packet contains. If a
packet contains more than one PUNCH_ME_NOW frame, the server processes
at most one of them and ignores the others as described in
(#requests). Together with the size limit in (#punch-packet), this
ensures that neither the number of packets nor the number of bytes the
server sends in punch packets exceeds what it received in the
corresponding requests. Because the limit applies to each received
packet, a client cannot accumulate an allowance and later release it as
a burst.

A client SHOULD therefore send each PUNCH_ME_NOW frame, including a
retransmitted one, in a separate packet.

The server MUST additionally limit the rate at which it sends punch
packets on a connection, for example using a token bucket with a small
burst size. Each punch packet creates a binding in the server-side NAT,
and an unbounded number of requests could exhaust its mapping table and
disrupt unrelated flows. Requests that exceed the limit are ignored as
described in (#requests).

The server MUST NOT send a punch packet to an address that it would not
use as the destination of a QUIC packet, such as a multicast,
broadcast, or unspecified address.

Because the client chooses both the destination address and the
destination port, punch requests can be used for request forgery
([@!RFC9000, section 21.5]). The server SHOULD NOT send a punch packet
to a loopback or link-local address, or to an address that is reachable
only from the server's own network (for example, a private address
reachable through a sending base that is not behind a NAT), unless
local policy explicitly permits it. The server MAY also refuse to send
punch packets to destination ports that it considers sensitive, applying
the countermeasures in [@!RFC9000, section 21.5.6].

# Punch Packets {#punch-packet}

A punch packet is a UDP datagram sent by the server from the selected
sending base to the client address and port given in the punch
request. Its only purpose is to create a binding in NATs and firewalls
on the server side. The client is not expected to receive or process
it.

A server MUST NOT send more than one punch packet in response to a
single PUNCH_ME_NOW frame, nor more than one in response to a single
received packet ((#limits)). Punch packets are never retransmitted. If a
punch packet is lost, the attempt fails, and the client can start a new
attempt with a new request ((#validation)).

A punch packet SHOULD be formatted as a QUIC packet with a short
header, so that it is treated as part of a QUIC flow by middleboxes on
the path. The Destination Connection ID MUST be a random value chosen
by the server for this packet. It MUST NOT be a connection ID issued by
the client, so that the punch packet cannot be linked to other paths of
the connection ([@!RFC9000, section 9.5]) and cannot be accepted by the
client as a packet of the connection. The remainder of the packet is
opaque. The server MAY construct it as a 1-RTT packet of the connection
containing a single PING frame, or MAY fill it with random bytes.

If the server constructs the punch packet as a protected 1-RTT packet,
the packet MUST be long enough for header protection to be applied
([@!RFC9001, section 5.4.2]): at least 4 bytes must follow the start of
the Packet Number field in addition to the 16-byte sample. With a
single PING frame and a short packet number encoding, this requires
adding PADDING frames or using a longer packet number encoding.

A punch packet SHOULD be as small as the server can make it, and MUST
NOT be larger than the packet in which the corresponding PUNCH_ME_NOW
frame was received. It does not need to be expanded to 1200 bytes: the
path MTU is verified later by the client's PATH_CHALLENGE, which is
subject to the datagram size requirements of [@!RFC9000, section 8.2.1].

If the server constructs the punch packet using the connection's packet
protection, it takes the packet number from the application data
packet number space of the path on which the PUNCH_ME_NOW frame was
received; with QUIC multipath, this is the packet number space of that
path's Path ID, which is also used to form the nonce
([@!RFC10069, section 2.4]). The packet number
is consumed: the server MUST NOT use it for any other packet, as reusing
a packet number with the same key and Path ID would reuse the AEAD
nonce. The packet number MUST NOT be tracked for loss recovery or
congestion control. The punch packet is not expected to be
acknowledged, and declaring it lost would cause a spurious congestion
response on the relayed path. From the peer's point of view the number
is skipped, which is permitted ([@!RFC9000, section 21.4]).

## Receiving a Punch Packet

If a punch packet reaches the client, the client cannot associate it
with a connection, because its Destination Connection ID was never
issued. The client handles it as any packet with an unknown connection
ID ([@!RFC9000, section 5.2]): the packet is discarded.

A client that uses zero-length connection IDs associates packets with
connections by local address and port ([@!RFC9000, section 5.2.1]), and
might therefore attempt to process a punch packet that arrives on the
base associated with its candidate. The punch packet cannot be
authenticated by the client, because the client parses the header
differently from how the server constructed it, or because the packet
consists of random bytes. The client discards it as it would any packet
that fails authentication. Such a failure counts toward the integrity
limit of the connection's keys ([@!RFC9001, section 6.6]); this is
negligible, as the number of punch packets is small.

The client might respond with a Stateless Reset
([@!RFC9000, section 10.3]). This is harmless. Its size is bounded by
the rules in [@!RFC9000, section 10.3]: it is normally smaller than the
punch packet ([@!RFC9000, section 10.3.3]) and is never three or more
times larger. It cannot match a stateless reset token issued for the
connection, and it is sent toward an address the server has advertised
and from which the server sent the punch packet. Endpoints SHOULD NOT treat the receipt of a punch packet
as an error, and implementations are encouraged not to log it at a
level that suggests a fault.

# Client-Initiated Path Validation {#validation}

After sending a PUNCH_ME_NOW frame, the client waits before probing the
path, so that the server's punch packet has time to create the
server-side binding. If the client's PATH_CHALLENGE reaches the server
side first, the server-side NAT is likely to drop it.

The relayed request needs roughly one one-way delay of the relayed
path to reach the server. It is RECOMMENDED that the client wait for
the smoothed RTT ([@!RFC9002, section 5.3]) of the path on which it
sent the PUNCH_ME_NOW frame. This leaves a margin of approximately one
further one-way delay. A client MAY use a shorter delay if it has
better information.

The client then validates the path from the base associated with the
client candidate to the server candidate.

* Without QUIC multipath, the client follows
  [@!RFC9000, section 8.2], using a connection ID issued by the server
  that has not been used on any other path.

* With QUIC multipath [@!RFC10069], the client opens a new path using
  an unused Path ID, as for any other new path.

The server responds as it would to any client-initiated path validation
or new path; no behavior specific to this extension is required on the
server for this step.

The client sends PATH_CHALLENGE frames, and handles validation timeout,
as described in [@!RFC9000, section 8.2.4]. A PATH_CHALLENGE that is
dropped because it arrived before the server-side binding existed is
handled like a lost packet; a subsequent PATH_CHALLENGE for the same
validation can still succeed.

If validation fails, the client abandons the attempt:

* Without QUIC multipath, the client retires the connection ID it used
  for the attempt with a RETIRE_CONNECTION_ID frame. The server issues
  a replacement using NEW_CONNECTION_ID as usual.

* With QUIC multipath, the client closes the path with PATH_ABANDON,
  which also retires its connection IDs.

The client MAY then start a new attempt for the same pair by sending a
new PUNCH_ME_NOW frame. Each attempt consumes a fresh server-issued
connection ID, as required by [@!RFC9000, section 9.5].

Without QUIC multipath, failed attempts release their connection IDs,
so the number of connection IDs needed is bounded by the number of
attempts in progress at the same time, not by the total number of
attempts. The client controls this number through its
active_connection_id_limit transport parameter.

With QUIC multipath, a Path ID cannot be reused once its path has been
abandoned ([@!RFC10069, section 3.4]), because the Path ID is part of
the nonce calculation ([@!RFC10069, section 2.4]). Each attempt
therefore consumes a Path ID permanently. Opening a path requires
connection IDs for the same Path ID from both endpoints, so the number
of attempts is bounded by the maximum Path ID limits of both endpoints
([@!RFC10069, section 3.2.1]). When this extension and QUIC multipath
are both in use, each endpoint SHOULD increase its maximum Path ID
using MAX_PATH_ID frames ([@!RFC10069, section 4.6]) as paths are
abandoned, and SHOULD issue connection IDs for the newly allowed Path
IDs using PATH_NEW_CONNECTION_ID frames, so that failed attempts do not
prevent further attempts. A client that cannot start an attempt follows
[@!RFC10069, section 3.2.1]: it sends a PATHS_BLOCKED frame if it has
no unused Path ID, or a PATH_CIDS_BLOCKED frame if it has no connection
ID for an unused Path ID ([@!RFC10069, section 4.7]).

# Migration {#migration}

Once a direct path has been validated, the client can migrate the
connection to it ([@!RFC9000, section 9]) or, when QUIC multipath is
used, send application data on it. How the client chooses among
validated paths, and whether it keeps the relayed path, is out of scope
for this document.

The client's path validation verifies only the server's address. When
the client migrates by sending non-probing frames on the new path, the
server validates the client's address as required by
[@!RFC9000, section 9.3]; with QUIC multipath, the server likewise
validates the new path before using it. This is ordinary server
behavior, not part of this extension, and takes place only after the
client has validated the path, so both NAT bindings already exist and
the validation is expected to succeed. Until it completes, the server
is limited by the anti-amplification limit
([@!RFC9000, section 8]), which can add up to one round trip of the
direct path before the server can send at full rate.

Because all new paths are initiated by the client, this extension does
not require the server to migrate the connection, consistent with
[@!RFC9000, section 9].

# Extension Negotiation {#negotiation}

Endpoints advertise support for this extension by sending the
stateless_punch transport parameter ([@!RFC9000, section 7.4]) with an
empty value. An endpoint that understands this transport parameter MUST
treat receipt of a non-empty value as a connection error of type
TRANSPORT_PARAMETER_ERROR.

The extension is in use on a connection only if both endpoints sent the
transport parameter. A client that sends stateless_punch MUST also send
the alternative_address transport parameter defined in
[@!I-D.munizaga-quic-alternative-server-address]. A server that
understands stateless_punch MUST treat receipt of stateless_punch
without alternative_address as a connection error of type
TRANSPORT_PARAMETER_ERROR.

This transport parameter MUST NOT be remembered for use in 0-RTT. The
PUNCH_ME_NOW frame MUST only be sent in 1-RTT packets.

# PUNCH_ME_NOW Frame {#frame}

~~~
PUNCH_ME_NOW Frame {
  Type (i) = 0x5eea90..0x5eea91,
  Client Address (32/128),
  Client Port (16),
  Server Address (32/128),
  Server Port (16),
}
~~~
Figure: PUNCH_ME_NOW Frame Format

The least significant bit of the frame type selects the address
family: 0x5eea90 indicates IPv4, in which case both address fields are
32 bits long; 0x5eea91 indicates IPv6, in which case both address
fields are 128 bits long.

Client Address and Client Port:
: The client's address candidate to which the server sends the punch
  packet.

Server Address and Server Port:
: The server candidate, which MUST be equal to an IPv4 or IPv6 entry
  that the client received in an ALTERNATIVE_ADDRESS frame.

PUNCH_ME_NOW frames are ack-eliciting and are not probing frames
([@!RFC9000, section 9.1]); they are sent on a validated path. A lost
PUNCH_ME_NOW frame SHOULD be retransmitted unless the client has given
up on the attempt. Because the server keeps no state, each received
frame, including a retransmission, is processed independently and can
result in a punch packet, subject to (#limits).

This frame is only sent by the client. A client MUST treat receipt of
a PUNCH_ME_NOW frame as a connection error of type PROTOCOL_VIOLATION.

# Security Considerations

This extension allows a client to cause the server to send a packet to
an address of the client's choosing before that address has been
validated. This is similar to the request forgery risk discussed in
[@!RFC9000, section 21.5]. The following properties limit the
exposure:

* The server sends at most one punch packet per received packet,
  however many requests that packet contains, and the punch packet is
  no larger than the packet carrying the request ((#limits)). The
  extension therefore provides no amplification, in either packets or
  bytes, and unused allowance cannot be accumulated into a burst.

* Punch packets are not retransmitted and their contents are not chosen
  by the client. However, the client chooses the destination address
  and port, so a punch packet could reach a service, or create state in
  a firewall, that an off-path attacker could not reach directly. The
  restrictions on destinations in (#limits) address this.

* The server does not send PATH_CHALLENGE frames or any other frames of
  the connection on unvalidated paths as part of this extension. All
  traffic on a new path beyond the punch packet is sent in response to
  packets received from the client on that path, and is therefore
  subject to the anti-amplification limits of
  [@!RFC9000, section 8].

Each punch packet creates a binding in NATs on the server side. A
client sending many requests could exhaust the mapping table of the
server's NAT, affecting other flows. Servers rate-limit punch packets
for this reason ((#limits)).

A punch packet can elicit a Stateless Reset from the client's endpoint.
Its size is bounded relative to the punch packet as described in
[@!RFC9000, section 10.3], and it is sent toward the server's own
sending base.

Punch requests are carried inside an authenticated QUIC connection and
cannot be forged by an off-path attacker.

The Destination Connection ID of a punch packet is random and is not
used on any other path, so punch packets cannot be correlated with
other packets of the connection by an observer
([@!RFC9000, section 9.5]). A punch packet reveals the server's
advertised address to the network at the client's candidate address;
the server has already advertised this address to the client.

# IANA Considerations

## QUIC Transport Parameter

This document registers the following value in the "QUIC Transport
Parameters" registry maintained at
[](https://www.iana.org/assignments/quic).

Value:
: 0x5eea9e7a (provisional, to be assigned)

Parameter Name:
: stateless_punch

Status:
: provisional

Specification:
: This document

## QUIC Frame Types

This document registers the following values in the "QUIC Frame Types"
registry maintained at [](https://www.iana.org/assignments/quic).

| Value               | Frame Name   | Status      | Specification |
|:--------------------|:-------------|:------------|:--------------|
| 0x5eea90 - 0x5eea91 | PUNCH_ME_NOW | provisional | This document |
Table: Frame type registrations

{backmatter}

# Comparison with draft-seemann-quic-nat-traversal-04 {#comparison}

This appendix explains how the design in this document relates to
[@?I-D.seemann-quic-nat-traversal]. Both documents share the overall
approach (a relayed connection, server candidates advertised with
ALTERNATIVE_ADDRESS, client-side pairing, migration to a direct path)
and differ only in how probing is coordinated.

| Aspect                         | seemann-04                                   | This document                         |
|:-------------------------------|:---------------------------------------------|:--------------------------------------|
| Server-initiated validation of candidate paths | Yes                                          | No                                    |
| Server state per attempt       | Grant, two punching CIDs, status             | None                                  |
| Server packets before validation | PATH_CHALLENGE probes, retransmitted until timeout | One small punch packet         |
| New frames                     | 4 (PUNCH_GRANT, MAX_PUNCH_GRANTS, PUNCH_REQUEST, PUNCH_DONE) | 1 (PUNCH_ME_NOW) |
| New connection ID type         | Punching connection IDs                      | None                                  |
| Multipath special handling     | Reserved Path ID 0xffffffff                  | None (ordinary path creation)         |
| Server candidate reference     | Advertisement sequence number and entry index | Address and port                     |
| Added latency                  | None                                         | About one relayed smoothed RTT        |
Table: Comparison of the two approaches

Several mechanisms in [@?I-D.seemann-quic-nat-traversal] follow from
the server taking part in path validation for each attempt:

* Punching connection IDs are needed because the server sends packets
  of the connection on each candidate path, and the number of
  concurrent attempts would otherwise be limited by
  active_connection_id_limit. In this document, the server sends no
  packet of the connection on an unvalidated path, and the client's
  validation uses ordinary connection IDs whose consumption is bounded
  by the number of concurrent attempts, or, with QUIC multipath, by the
  Path IDs that both endpoints make available ((#validation)).

* PUNCH_DONE is needed so that both endpoints can release per-attempt
  state. A stateless server has nothing to release.

* PUNCH_REQUEST is sent both on the established path and inside each
  probe, because a direct probe from the client can overtake the
  relayed request. In this document, the client probes only after a
  delay, so the request always arrives first in normal operation, and
  a PATH_CHALLENGE that arrives too early is simply retransmitted.

* A reserved Path ID is needed for multipath because punching
  connection IDs are not associated with ordinary paths. Here, every
  new path is an ordinary path created by the client.

* Grants and MAX_PUNCH_GRANTS let both endpoints bound the work per
  connection. Here, the server bounds its work with a local rate limit,
  and the existing connection ID and Path ID limits bound the number of
  concurrent attempts.

* Referencing server candidates by advertisement sequence number and
  entry index requires rules for keeping entries stable across
  advertisements and a status for stale references. Naming the address
  directly removes these rules; a request naming a withdrawn address is
  ignored.

The main cost of this document's approach is latency: the client's
first probe is delayed by about one relayed smoothed RTT. In addition,
if the single punch packet is lost, a new attempt costs one more
relayed round trip. The server could mitigate the latter by sending a
small, fixed number of punch packets without keeping state (see
(#open-issues)).

# Implementation Status {#implementation}

> Note to RFC Editor: please remove this section before publication.

This section records the status of known implementations of the
protocol defined by this specification at the time of posting of this
Internet-Draft, and is based on a proposal described in [@?RFC7942].

## SEERA MsQuic

Organization:
: SEERA Networks

Description:
: A fork of MsQuic that migrates connections carried over a MASQUE
  relay to a direct path. The server processes punch requests without
  keeping per-attempt state and sends a single punch packet, formatted
  as a short-header packet protected with the connection's 1-RTT keys,
  with a random Destination Connection ID and a single PING frame,
  without padding. The client starts path validation after the smoothed
  RTT of the relayed path.

Differences from this document:
: The implementation predates this document. It identifies the server
  candidate by the sequence number of an ADD_ADDRESS frame as defined
  in draft-seemann-quic-nat-traversal-02, carries an additional Round
  field, and uses the frame types 0x3d7e92 and 0x3d7e93.

Maturity:
: Used in a relay service operated by SEERA Networks in trial
  deployment.

Licensing:
: MIT

Repository:
: [](https://github.com/seera-networks/msquic)

Contact:
: Masahiro Kozuka (kozuka@okayama-u.ac.jp)

# Open Issues {#open-issues}

> Note to RFC Editor: please remove this section before publication.

Redundant punch packets:
: Should the server be allowed to send a small, fixed number of punch
  packets per request, spaced in time, to tolerate loss without keeping
  state beyond a timer? This trades a bounded increase in traffic for
  fewer re-requests.

Multiple bases with the same advertised address:
: When candidates with different sending bases share an advertised
  address (for example with overlapping address spaces, see Appendix B.2
  of [@!RFC8445]), the server cannot tell from the address alone which
  base to use. Should the server send one punch packet from each such
  base, or should requests carry a disambiguator?

Endpoint-dependent mapping:
: When a NAT uses endpoint-dependent mapping, the external port used
  for the punch packet differs from the advertised one. Port prediction
  techniques could be layered on top of this extension, at the cost of
  more NAT bindings.

Delay selection:
: Is the smoothed RTT of the relayed path the right default, or should
  the client probe earlier and rely on PATH_CHALLENGE retransmission?

{numbered="false"}
# Acknowledgments

This document builds on the work of Marten Seemann and Eric Kinnear in
[@?I-D.seemann-quic-nat-traversal]. The stateless approach was suggested
by Christian Huitema in [@?ISSUE20].

<reference anchor="RFC2119" target="https://www.rfc-editor.org/info/rfc2119">
  <front>
    <title>Key words for use in RFCs to Indicate Requirement Levels</title>
    <author initials="S." surname="Bradner" fullname="S. Bradner"/>
    <date year="1997" month="March"/>
  </front>
  <seriesInfo name="BCP" value="14"/>
  <seriesInfo name="RFC" value="2119"/>
  <seriesInfo name="DOI" value="10.17487/RFC2119"/>
</reference>

<reference anchor="RFC8174" target="https://www.rfc-editor.org/info/rfc8174">
  <front>
    <title>Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words</title>
    <author initials="B." surname="Leiba" fullname="B. Leiba"/>
    <date year="2017" month="May"/>
  </front>
  <seriesInfo name="BCP" value="14"/>
  <seriesInfo name="RFC" value="8174"/>
  <seriesInfo name="DOI" value="10.17487/RFC8174"/>
</reference>

<reference anchor="RFC9000" target="https://www.rfc-editor.org/info/rfc9000">
  <front>
    <title>QUIC: A UDP-Based Multiplexed and Secure Transport</title>
    <author initials="J." surname="Iyengar" fullname="J. Iyengar" role="editor"/>
    <author initials="M." surname="Thomson" fullname="M. Thomson" role="editor"/>
    <date year="2021" month="May"/>
  </front>
  <seriesInfo name="RFC" value="9000"/>
  <seriesInfo name="DOI" value="10.17487/RFC9000"/>
</reference>

<reference anchor="RFC9001" target="https://www.rfc-editor.org/info/rfc9001">
  <front>
    <title>Using TLS to Secure QUIC</title>
    <author initials="M." surname="Thomson" fullname="M. Thomson" role="editor"/>
    <author initials="S." surname="Turner" fullname="S. Turner" role="editor"/>
    <date year="2021" month="May"/>
  </front>
  <seriesInfo name="RFC" value="9001"/>
  <seriesInfo name="DOI" value="10.17487/RFC9001"/>
</reference>

<reference anchor="RFC9002" target="https://www.rfc-editor.org/info/rfc9002">
  <front>
    <title>QUIC Loss Detection and Congestion Control</title>
    <author initials="J." surname="Iyengar" fullname="J. Iyengar" role="editor"/>
    <author initials="I." surname="Swett" fullname="I. Swett" role="editor"/>
    <date year="2021" month="May"/>
  </front>
  <seriesInfo name="RFC" value="9002"/>
  <seriesInfo name="DOI" value="10.17487/RFC9002"/>
</reference>

<reference anchor="RFC10069" target="https://www.rfc-editor.org/info/rfc10069">
  <front>
    <title>Managing Multiple Paths for a QUIC Connection</title>
    <author initials="Y." surname="Liu" fullname="Y. Liu" role="editor"/>
    <author initials="Y." surname="Ma" fullname="Y. Ma"/>
    <author initials="Q." surname="De Coninck" fullname="Q. De Coninck" role="editor"/>
    <author initials="O." surname="Bonaventure" fullname="O. Bonaventure"/>
    <author initials="C." surname="Huitema" fullname="C. Huitema"/>
    <author initials="M." surname="Kühlewind" fullname="M. Kühlewind" role="editor"/>
    <date year="2026" month="November"/>
  </front>
  <seriesInfo name="RFC" value="10069"/>
  <seriesInfo name="DOI" value="10.17487/RFC10069"/>
</reference>

<reference anchor="RFC8445" target="https://www.rfc-editor.org/info/rfc8445">
  <front>
    <title>Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal</title>
    <author initials="A." surname="Keranen" fullname="A. Keranen"/>
    <author initials="C." surname="Holmberg" fullname="C. Holmberg"/>
    <author initials="J." surname="Rosenberg" fullname="J. Rosenberg"/>
    <date year="2018" month="July"/>
  </front>
  <seriesInfo name="RFC" value="8445"/>
  <seriesInfo name="DOI" value="10.17487/RFC8445"/>
</reference>

<reference anchor="RFC4787" target="https://www.rfc-editor.org/info/rfc4787">
  <front>
    <title>Network Address Translation (NAT) Behavioral Requirements for Unicast UDP</title>
    <author initials="F." surname="Audet" fullname="F. Audet" role="editor"/>
    <author initials="C." surname="Jennings" fullname="C. Jennings"/>
    <date year="2007" month="January"/>
  </front>
  <seriesInfo name="BCP" value="127"/>
  <seriesInfo name="RFC" value="4787"/>
  <seriesInfo name="DOI" value="10.17487/RFC4787"/>
</reference>

<reference anchor="RFC7942" target="https://www.rfc-editor.org/info/rfc7942">
  <front>
    <title>Improving Awareness of Running Code: The Implementation Status Section</title>
    <author initials="Y." surname="Sheffer" fullname="Y. Sheffer"/>
    <author initials="A." surname="Farrel" fullname="A. Farrel"/>
    <date year="2016" month="July"/>
  </front>
  <seriesInfo name="BCP" value="205"/>
  <seriesInfo name="RFC" value="7942"/>
  <seriesInfo name="DOI" value="10.17487/RFC7942"/>
</reference>

<reference anchor="I-D.ietf-masque-connect-udp-listen" target="https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-udp-listen-16">
  <front>
    <title>Proxying Bound UDP in HTTP</title>
    <author initials="D." surname="Schinazi" fullname="David Schinazi"/>
    <author initials="A." surname="Singh" fullname="Abhi Singh"/>
    <date year="2026" month="August" day="24"/>
  </front>
  <seriesInfo name="Internet-Draft" value="draft-ietf-masque-connect-udp-listen-16"/>
</reference>

<reference anchor="I-D.munizaga-quic-alternative-server-address" target="https://datatracker.ietf.org/doc/html/draft-munizaga-quic-alternative-server-address-02">
  <front>
    <title>QUIC Alternative Server Address Frames</title>
    <author initials="M." surname="Munizaga" fullname="M. Munizaga"/>
    <author initials="M." surname="Seemann" fullname="M. Seemann"/>
    <date year="2026" month="September" day="25"/>
  </front>
  <seriesInfo name="Internet-Draft" value="draft-munizaga-quic-alternative-server-address-02"/>
</reference>

<reference anchor="I-D.seemann-masque-connect-udp-rendezvous" target="https://datatracker.ietf.org/doc/html/draft-seemann-masque-connect-udp-rendezvous-00">
  <front>
    <title>UDP Rendezvous over HTTP</title>
    <author initials="M." surname="Seemann" fullname="M. Seemann"/>
    <date year="2026" month="August" day="16"/>
  </front>
  <seriesInfo name="Internet-Draft" value="draft-seemann-masque-connect-udp-rendezvous-00"/>
</reference>

<reference anchor="I-D.seemann-quic-nat-traversal" target="https://datatracker.ietf.org/doc/html/draft-seemann-quic-nat-traversal-04">
  <front>
    <title>Using QUIC to traverse NATs</title>
    <author initials="M." surname="Seemann" fullname="M. Seemann"/>
    <author initials="E." surname="Kinnear" fullname="E. Kinnear"/>
    <date year="2026" month="November" day="2"/>
  </front>
  <seriesInfo name="Internet-Draft" value="draft-seemann-quic-nat-traversal-04"/>
</reference>

<reference anchor="ISSUE20" target="https://github.com/marten-seemann/draft-seemann-quic-nat-traversal/issues/20">
  <front>
    <title>consider allowing probe packets to be smaller than 1200 bytes</title>
    <author/>
    <date year="2023" month="October"/>
  </front>
  <refcontent>draft-seemann-quic-nat-traversal issue #20</refcontent>
</reference>
