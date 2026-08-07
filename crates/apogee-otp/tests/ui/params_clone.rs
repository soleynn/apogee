//! A profile holds the decoded key. A clone is a second copy of it with its own lifetime, erased
//! whenever that copy happens to drop rather than when the profile does.

use apogee_otp::TotpParams;

fn duplicate(params: &TotpParams) -> TotpParams {
    params.clone()
}

fn main() {
    let _ = duplicate;
}
