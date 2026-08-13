//! A secret must not dereference to its bytes. `Deref<Target = [u8]>` would hand back every slice
//! method, `to_vec` among them, and would put `{:?}` within reach of anything holding one: the
//! target is `[u8]`, which is `Debug`. The nine cases beside this one pin the traits `Secret` must
//! not have; this pins that it must not borrow its way into one.

use apogee_secrets::Secret;

fn main() {
    let secret = Secret::new(b"marker".to_vec());
    println!("{:?}", *secret);
}
