# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for a vulnerability. Use GitHub's private vulnerability
reporting for this repository ("Security" tab → "Report a vulnerability"). Include what is
affected (the MAC's security framing, the nRF91 port, the reference backend), how to reproduce
it, and its impact. You will get an answer within a week; fixes are released as soon as they are
ready and credited unless you prefer otherwise.

## Scope

- **In scope**: the MAC's link-security framing (`src/`: packet layout, nonces, AAD, sessions,
  key switches, freshness and replay checks, the deny list), memory safety of the decoders and
  of everything that handles received packets, and the nRF91 port.
- **Reference backend** (`port/sec_ref/`, `CONFIG_TDMA_SEC_REF`): a software AES-CCM with keys in
  RAM, not constant time, meant for the simulator and bring-up. Weaknesses that follow from that
  design (timing side channels, keys readable from RAM) are known and out of scope; do not use
  it in products.
- **Out of scope**: key management and provisioning (the application's), the modem firmware and
  the PHY, jamming.

## Design notes

The security design is in [docs/mac-design.md](docs/mac-design.md#link-security): AES-128-CCM
per PHY packet with a 4-byte MIC by default (`CONFIG_TDMA_MAC_SEC_MIC_LEN` 4, 6 or 8), implicit
13-byte nonces (transmitter rd id, frame, subslot), session keys per FT session, sealed beacons,
and an alarm on bursts of MIC failures. A 4-byte tag relies on that failure monitoring (NIST SP
800-38C Appendix B); choose 8 bytes if your threat model needs it.
