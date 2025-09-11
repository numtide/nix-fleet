# rust workspace template

This is an experiment to contain the code for all components in a single repository, also known as a monorepository.

## Repository Layout

The code is grouped by language or framework name.

### Nix

```
/flake.nix
/flake.lock
/nix/ /* [blueprint](https://github.com/numtide/blueprint)  set up underneath here. */
```

### Rust

```
/Cargo.toml
/Cargo.lock
/rust/ # all rust code lives here
/rust/common/Cargo.toml
/rust/common/src/lib.rs
```
