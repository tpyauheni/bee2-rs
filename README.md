# Rust bindings for Bee2
[![Rust](https://github.com/tpyauheni/bee2-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/tpyauheni/bee2-rs/actions/workflows/rust.yml)

[Original repository](https://github.com/agievich/bee2)

## Supported modules (WIP)
- [ ] Bake
- [x] Bash (not to be confused with *Bourne Again SHell*)
- [ ] Bels
- [x] Belt
- [x] Bign
- [ ] Bign96
- [ ] Botp
- [ ] Bpki
- [x] Brng
- [ ] Btok
- [ ] Dstu
- [ ] Pfok
- [ ] Stb99

## Build
1. Clone this repository
2. [Install rust](https://www.rust-lang.org/learn/get-started)
3. Run `cargo build` in a directory of the cloned repository
4. (optional) Run `cargo test`

## Using in a project
Add following line as a dependency in your `Cargo.toml`:
```toml
bee2-rs = "0.2"
```

## License
Bee2-rs is distributed under the Apache License version 2.0. See [Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [LICENSE](https://github.com/tpyauheni/bee2-rs/blob/master/LICENSE) for details.
