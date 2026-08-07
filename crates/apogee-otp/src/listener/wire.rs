//! The three answers this endpoint can give, as bytes.
//!
//! Constants rather than anything formatted, so the hostile path allocates nothing and so no value
//! derived from a request can reach a response even by accident.

/// The reference launcher's answer, byte for byte, bare line feeds included.
///
/// `HTTP/1.0`, line feeds rather than carriage-return pairs, no `Content-Length`, the space after the
/// comma inside the object, and no trailing newline are all reproduced rather than corrected. Each is
/// what shipping XIVLauncher emits and therefore what the client population this endpoint exists for
/// has always been answered with; carriage-return pairs and `HTTP/1.1` are guesses, and a guess
/// against an unmeasured client parser is a compatibility risk taken for tidiness. Under `HTTP/1.0`
/// the body is delimited by the close, which is what happens here.
///
/// The body carries no request-derived content of any kind: not the target, not the code, not the
/// peer, not an error detail. That is the whole defence against a page that re-resolves its own name
/// to this host so as to become same-origin and read the response; what it gets is a constant, so it
/// learns that a launcher is awaiting a code, which the open port already told it. The version is a
/// fixed string rather than this build's, because a precise build string is a fingerprint readable
/// under exactly that attack and nothing measured says the app reads the field at all.
pub(crate) const RESPONSE_OK: &[u8] = b"HTTP/1.0 200 OK\n\
    Content-Type: application/json; charset=UTF-8\n\
    \n\
    {\"app\":\"XIVLauncher\", \"version\":\"1.0.0.0\"}";

/// Answered to everything the grammar refused, whatever the reason.
///
/// One status for every rule, so the answer says nothing about which rule was broken and there is one
/// rejection path to test. No body, so nothing derived from the request can appear in one.
/// `Content-Length: 0` rather than nothing, because with an empty body the close-delimits-the-body
/// rule is ambiguous to a client that is waiting; the reference never emits a 400, so there is no
/// compatibility baseline to break here.
pub(crate) const RESPONSE_BAD_REQUEST: &[u8] = b"HTTP/1.0 400 Bad Request\n\
    Content-Length: 0\n\
    \n";

/// Answered to a source past its attempt budget, written without reading a byte from it.
///
/// `Retry-After` is the window the budget is measured over, which is the honest number and costs
/// nothing to say.
pub(crate) const RESPONSE_TOO_MANY: &[u8] = b"HTTP/1.0 429 Too Many Requests\n\
    Retry-After: 60\n\
    Content-Length: 0\n\
    \n";
