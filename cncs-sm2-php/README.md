# cncs-sm2-php

* [Cargo package](https://crates.io/crates/cncs-sm2-php)

# Dev

Ref https://davidcole1340.github.io/ext-php-rs/

```
sudo pacman -S php clang

cargo install cargo-php
```

```
cargo build --release -p cncs-sm2-php

php -dextension=../target/release/libcncs_sm2_php.so test.php
```
