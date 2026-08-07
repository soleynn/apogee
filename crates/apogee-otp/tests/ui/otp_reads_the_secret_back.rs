//! The handle reads the store and hands back a code. It does not hand back what it read, and holding
//! one is not a way to reach an account's shared secret.

use apogee_otp::Otp;
use uuid::Uuid;

fn read_the_secret(otp: &Otp, account: Uuid) {
    let _ = otp.secret(account);
    let _ = otp.params(account);
    let _ = otp.store();
}

fn main() {
    let _ = read_the_secret;
}
