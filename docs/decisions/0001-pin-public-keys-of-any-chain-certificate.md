# 1. Pin the public key of any certificate in the chain

Status: accepted

## Context

An interception proxy presents a certificate for the same name, signed by a different CA. A pin has to notice that, and must not fire on every routine renewal.

Hashing the whole leaf certificate changes at each renewal. Hashing the leaf's public key survives renewals only if the key pair is reused, which good practice discourages. Pinning only the CA would miss a change of key at the leaf.

## Decision

A pin is the SHA-256 of a certificate's SubjectPublicKeyInfo, written `sha256:<hex>`. A target matches when any certificate in the presented chain carries any configured pin. Several pins per target are allowed.

- Pin an intermediate CA to survive leaf renewals and still catch re-signing by another CA.
- Pin the leaf key as well for the strictest reading, and add the next key before a planned rotation.

## Consequences

- The `learn` command prints every certificate in the chain with its pin and says which kind each is.
- A deliberate change of CA at the endpoint will alert. That is intended; the runbook is to add the new pin first, rotate, then remove the old one.
- The root is usually not in the presented chain, so it cannot be pinned this way.
