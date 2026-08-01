//! Nor may a consumer add the missing trait itself.

use apogee_secrets::Secret;

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret")
    }
}

fn main() {}
