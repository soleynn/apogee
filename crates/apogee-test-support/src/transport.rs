//! A fixture [`Transport`].
//!
//! Replays scripted responses in call order, records every request it receives, and renders a request
//! to a canonical text form so a test can assert request fidelity against a golden: the drift alarm
//! that fails loudly when a surface changes the bytes it sends to SE.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use sqex_proto::{ProtoRequest, ProtoResponse, Transport, TransportError};

/// A scripted transport for driving `sqex-proto` surfaces without a network.
pub struct FixtureTransport {
    outcomes: Mutex<VecDeque<Result<ProtoResponse, TransportError>>>,
    recorded: Mutex<Vec<ProtoRequest>>,
}

impl FixtureTransport {
    /// A transport that returns `responses` in order, one per `execute` call.
    #[must_use]
    pub fn new(responses: impl IntoIterator<Item = ProtoResponse>) -> Self {
        Self {
            outcomes: Mutex::new(responses.into_iter().map(Ok).collect()),
            recorded: Mutex::new(Vec::new()),
        }
    }

    /// A transport whose single `execute` returns `response`.
    #[must_use]
    pub fn once(response: ProtoResponse) -> Self {
        Self::new([response])
    }

    /// A transport whose next `execute` fails at the transport layer.
    #[must_use]
    pub fn failing(error: TransportError) -> Self {
        Self {
            outcomes: Mutex::new(VecDeque::from([Err(error)])),
            recorded: Mutex::new(Vec::new()),
        }
    }

    /// The requests received so far, in call order.
    #[must_use]
    pub fn recorded(&self) -> Vec<ProtoRequest> {
        self.recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait::async_trait]
impl Transport for FixtureTransport {
    async fn execute(&self, req: ProtoRequest) -> Result<ProtoResponse, TransportError> {
        self.recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(req);
        let next = self
            .outcomes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front();
        next.unwrap_or_else(|| {
            Err(TransportError::new(
                "fixture transport exhausted: no scripted response for this request",
            ))
        })
    }
}

/// Render a request to a canonical text form for golden comparison: the method and URL on the first
/// line, each header as `name: value` in order, then a blank line and the body if present. Header
/// order is preserved so a reordering shows up as a diff.
#[must_use]
pub fn canonical_request(req: &ProtoRequest) -> String {
    let mut s = String::new();
    s.push_str(req.method.as_str());
    s.push(' ');
    s.push_str(req.url.as_str());
    s.push('\n');
    for (name, value) in &req.headers {
        s.push_str(name.as_str());
        s.push_str(": ");
        push_escaped(&mut s, value.as_bytes());
        s.push('\n');
    }
    if let Some(body) = &req.body {
        s.push('\n');
        push_escaped(&mut s, body.as_bytes());
    }
    s
}

/// Append `bytes` to `out` as text, escaping anything that is not valid UTF-8 as `\xNN`.
///
/// This backs a golden comparison whose whole claim is that the request bytes match exactly, so the
/// rendering has to be injective: a lossy decode maps every invalid sequence to one replacement
/// character, and two different wrong bodies would then render identically and pass. The backslash is
/// escaped as well, or a body containing the literal text `\xNN` would collide with a real escape.
///
/// Header values allow bytes outside UTF-8 too, so they go through the same path as the body.
fn push_escaped(out: &mut String, bytes: &[u8]) {
    let mut rest = bytes;
    loop {
        let (valid, invalid) = match std::str::from_utf8(rest) {
            Ok(text) => (text, &[][..]),
            Err(error) => {
                let (head, tail) = rest.split_at(error.valid_up_to());
                // `valid_up_to` is a UTF-8 boundary by definition, so the head decodes; an unexpected
                // end of input has no error length and ends the run.
                let text = std::str::from_utf8(head).unwrap_or_default();
                let bad = error.error_len().unwrap_or(tail.len());
                (text, &tail[..bad])
            }
        };
        for c in valid.chars() {
            if c == '\\' {
                out.push('\\');
            }
            out.push(c);
        }
        if invalid.is_empty() {
            return;
        }
        for byte in invalid {
            out.push_str(&format!("\\x{byte:02X}"));
        }
        rest = &rest[valid.len() + invalid.len()..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rt::block_on;
    use http::{HeaderName, HeaderValue, Method};
    use url::Url;

    fn get(path: &str) -> ProtoRequest {
        let url = Url::parse(&format!("http://patch.example.invalid/{path}")).unwrap();
        ProtoRequest::new(Method::GET, url).header(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("FFXIV PATCH CLIENT"),
        )
    }

    #[test]
    fn replays_in_order_and_records_requests() {
        let transport = FixtureTransport::new([
            ProtoResponse::new(200, b"first".to_vec()),
            ProtoResponse::new(204, Vec::new()),
        ]);

        let a = block_on(transport.execute(get("a"))).unwrap();
        let b = block_on(transport.execute(get("b"))).unwrap();

        assert_eq!(a.status, 200);
        assert_eq!(a.body, b"first");
        assert_eq!(b.status, 204);

        let recorded = transport.recorded();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].url.path(), "/a");
        assert_eq!(recorded[1].url.path(), "/b");
    }

    #[test]
    fn exhaustion_is_a_transport_error_not_a_crash() {
        let transport = FixtureTransport::once(ProtoResponse::new(200, Vec::new()));
        let _ = block_on(transport.execute(get("a"))).unwrap();
        let second = block_on(transport.execute(get("b")));
        assert!(second.is_err());
    }

    #[test]
    fn canonical_render_pins_line_and_header_order() {
        let rendered = canonical_request(&get("http/win32/x/?time=2024-01-02-03-40"));
        assert_eq!(
            rendered,
            "GET http://patch.example.invalid/http/win32/x/?time=2024-01-02-03-40\n\
             user-agent: FFXIV PATCH CLIENT\n"
        );
    }

    /// The comparison this helper backs claims the request bytes match exactly, so two different
    /// wrong bodies must not render the same. A lossy decode folds every invalid sequence onto one
    /// replacement character and would pass all four of these against each other.
    #[test]
    fn two_different_invalid_bodies_do_not_render_alike() {
        let render = |body: &[u8]| {
            canonical_request(&get("x").body(sqex_proto::RequestBody::new(body.to_vec())))
        };

        let renderings = [
            render(&[0xFF]),
            render(&[0xFE]),
            render(&[0xFF, 0xFE]),
            // The replacement character a lossy decode would have produced for any of the above.
            render("\u{FFFD}".as_bytes()),
            // And the literal text of an escape, which is why the backslash is escaped too.
            render(br"\xFF"),
        ];

        for (i, left) in renderings.iter().enumerate() {
            for right in &renderings[i + 1..] {
                assert_ne!(left, right);
            }
        }
    }

    /// Valid text still renders verbatim: the escaping must not disturb the goldens it backs.
    #[test]
    fn valid_text_is_unchanged_by_the_escaping() {
        let rendered = canonical_request(
            &get("x").body(sqex_proto::RequestBody::new(
                "_STORED_=blob&sqexid=user&password=hünter2"
                    .as_bytes()
                    .to_vec(),
            )),
        );
        assert!(
            rendered.ends_with("\n\n_STORED_=blob&sqexid=user&password=hünter2"),
            "{rendered}"
        );
    }
}
