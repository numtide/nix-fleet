# nix-fleet

Manage partially off-line fleets for NixOS deployments

This project aims to build robust and user-friendly device management tooling, specifically tailored for asynchronously managing a fleet of devices that are capable of and intended to run NixOS. These requirements were identified as unlocking NixOS adoption in small and medium business and educational organizations.

Upon successful completion of this first phase, the tooling will provide a centralized management system offering access control, fleet oversight, streamlined machine enrollment, and clear feedback on deployment status.

## Repository Layout

The code is grouped by language or framework name.

### Nix

This repository uses the [blueprint](https://github.com/numtide/blueprint) structure.

```
/flake.nix
/flake.lock
/nix/ # blueprint set up underneath here.
```

### Rust

```
/Cargo.toml
/Cargo.lock
/rust/ # all rust code lives here.
/rust/common/Cargo.toml
/rust/common/src/lib.rs
```

---

This project was funded through the NGI Fediversity Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme, as a pilot programme under the aegis of DG Communications Networks, Content and Technology. NGI Fediversity is part of the Horizon Europe research and innovation programme under grant agreement No. 101136078.
