## 📦 `rsa-rust`

**`rsa-rust`** is a minimal and educational implementation of the RSA encryption algorithm written in pure Rust. Designed for learning and experimentation, it provides basic functionality for key generation, encryption, and decryption, using big integer arithmetic without dependencies on heavy crypto crates.

---

### 🚀 Features

* Key generation with configurable bit length
* Message encryption and decryption
* Export and import of keys via `(BigUint, BigUint)` tuples
* No unsafe code or heavy dependencies

---

### 🛠️ Installation

Add this crate as a dependency in your `Cargo.toml`:

```toml
[dependencies]
rsa-rust = { path = "../rsa-rust" }
```

> Replace the path accordingly if using as a local module. Alternatively, you can publish and use it via crates.io.

---

### 📚 Usage

```rust
use rsa_rust::RSA;

fn main() {
    let rsa = RSA::new(2048);

    let message = b"Hello RSA!";
    let ciphertext = rsa.encrypt(message);
    let decrypted = rsa.decrypt(&ciphertext);

    println!("Decrypted message: {}", String::from_utf8(decrypted).unwrap());
}
```

---

### 🔐 Key Structure

```rust
pub struct RSA {
    pub public_key: (BigUint, BigUint),  // (e, n)
    pub private_key: (BigUint, BigUint), // (d, n)
}
```

You can serialize/deserialize keys manually using `serde` + `BigUint` with the `serde` feature enabled in `num-bigint`.

---

### 📂 Structure

* `src/lib.rs` – Core implementation
* `tests/` – Basic tests for encryption/decryption

---

### 📌 Notes

* This library is not meant for production use or secure communications.
* No padding is used. Use for learning purposes only.

---

### 📄 License

MIT

