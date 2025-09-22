# nix-fleet

Nix(OS) fleet management solution for organizations.

This project aims to build robust and user-friendly device management tooling, specifically tailored for asynchronously managing a fleet of devices that are capable of and intended to run NixOS. These requirements were identified as unlocking NixOS adoption in small and medium business and educational organizations.

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

---

### Funding


#### [NLnet Grant][nlnet-grant-1]

This project [is currently funded][nlnet-grant-1] through [NGI Fediversity Fund](https://nlnet.nl/fediversity), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/Agent-based-deployment).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)


[nlnet-grant-1]: https://nlnet.nl/project/Agent-based-deployment
