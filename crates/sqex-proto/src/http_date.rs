// The Date response header, read back into the instant it names. Fixed-position matching over the
// two forms whose meaning is settled by their own text: the IMF-fixdate every current server sends
// (the login server among them) and the obsolete asctime form. The third form HTTP lists carries a
// two-digit year, which names an instant only against a clock, and this crate holds none; it is
// refused rather than resolved against a guess. A refusal costs a caller the reading and never the
// request, because an unreadable stamp answers the same as an absent one.
//
// Each field is range-checked before the calendar arithmetic runs. The civil-to-days map normalises
// instead of validating, so `31 Feb` reaches it as a well-formed date and comes back out as `3 Mar`
// with nothing to say it was never a day -- the range check in front is what actually refuses it.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

const DAY_NAMES: [&[u8; 3]; 7] = [b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat", b"Sun"];

#[must_use]
pub fn parse_http_date(value: &str) -> Option<SystemTime> {
    let text = value.as_bytes().trim_ascii();
    let civil = match text.len() {
        29 => imf_fixdate(text),
        24 => asctime(text),
        _ => None,
    }?;
    civil.instant()
}

struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

impl Civil {
    fn instant(self) -> Option<SystemTime> {
        if self.day < 1 || self.day > days_in_month(self.year, self.month) {
            return None;
        }
        if self.hour > 23 || self.minute > 59 || self.second > 60 {
            return None;
        }
        let second = self.second.min(59);
        let seconds = days_from_civil(self.year, self.month, self.day)
            .checked_mul(86_400)?
            .checked_add(i64::from(self.hour) * 3_600 + i64::from(self.minute) * 60)?
            .checked_add(i64::from(second))?;
        let offset = Duration::from_secs(seconds.unsigned_abs());
        if seconds >= 0 {
            UNIX_EPOCH.checked_add(offset)
        } else {
            UNIX_EPOCH.checked_sub(offset)
        }
    }
}

fn imf_fixdate(text: &[u8]) -> Option<Civil> {
    //                     0         1         2
    //                     0123456789012345678901234567 8
    let text: &[u8; 29] = text.try_into().ok()?; // Sun, 06 Nov 1994 08:49:37 GMT
    let punctuation = [
        text[3], text[4], text[7], text[11], text[16], text[19], text[22], text[25],
    ];
    if punctuation != *b",    :: " || [text[26], text[27], text[28]] != *b"GMT" {
        return None;
    }
    day_name(&[text[0], text[1], text[2]])?;
    Some(Civil {
        year: i64::from(two(text[12], text[13])?) * 100 + i64::from(two(text[14], text[15])?),
        month: month(&[text[8], text[9], text[10]])?,
        day: two(text[5], text[6])?,
        hour: two(text[17], text[18])?,
        minute: two(text[20], text[21])?,
        second: two(text[23], text[24])?,
    })
}

fn asctime(text: &[u8]) -> Option<Civil> {
    //                     0         1         2
    //                     012345678901234567890123
    let text: &[u8; 24] = text.try_into().ok()?; // Sun Nov  6 08:49:37 1994
    let punctuation = [text[3], text[7], text[10], text[13], text[16], text[19]];
    if punctuation != *b"   :: " {
        return None;
    }
    day_name(&[text[0], text[1], text[2]])?;
    // The one field that is not fixed-width: a single-digit day is padded with a space, not a zero.
    let day = if text[8] == b' ' {
        u32::from(digit(text[9])?)
    } else {
        two(text[8], text[9])?
    };
    Some(Civil {
        year: i64::from(two(text[20], text[21])?) * 100 + i64::from(two(text[22], text[23])?),
        month: month(&[text[4], text[5], text[6]])?,
        day,
        hour: two(text[11], text[12])?,
        minute: two(text[14], text[15])?,
        second: two(text[17], text[18])?,
    })
}

fn month(name: &[u8; 3]) -> Option<u32> {
    let index = MONTHS.iter().position(|known| *known == name)?;
    u32::try_from(index + 1).ok()
}

fn day_name(name: &[u8; 3]) -> Option<()> {
    DAY_NAMES.contains(&name).then_some(())
}

fn two(hi: u8, lo: u8) -> Option<u32> {
    Some(u32::from(digit(hi)?) * 10 + u32::from(digit(lo)?))
}

fn digit(byte: u8) -> Option<u8> {
    byte.checked_sub(b'0').filter(|value| *value <= 9)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted = if month > 2 {
        i64::from(month) - 3
    } else {
        i64::from(month) + 9
    };
    let day_of_year = (153 * shifted + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix(value: &str) -> Option<i64> {
        let parsed = parse_http_date(value)?;
        Some(match parsed.duration_since(UNIX_EPOCH) {
            Ok(after) => i64::try_from(after.as_secs()).ok()?,
            Err(before) => -i64::try_from(before.duration().as_secs()).ok()?,
        })
    }

    #[test]
    fn the_form_the_login_server_sends_reads_back() {
        assert_eq!(unix("Thu, 06 Aug 2026 21:15:56 GMT"), Some(1_786_050_956));
        assert_eq!(unix("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
    }

    #[test]
    fn the_asctime_form_reads_back_including_its_padded_day() {
        assert_eq!(unix("Sun Nov  6 08:49:37 1994"), Some(784_111_777));
        assert_eq!(unix("Sat Nov 26 08:49:37 1994"), Some(785_839_777));
    }

    #[test]
    fn the_two_digit_year_form_is_refused() {
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06-Nov-94 08:49:37 GMT"), None);
    }

    #[test]
    fn a_day_its_month_does_not_have_is_refused() {
        assert_eq!(parse_http_date("Fri, 31 Feb 2025 12:00:00 GMT"), None);
        assert_eq!(parse_http_date("Sun, 31 Apr 2024 12:00:00 GMT"), None);
        assert_eq!(parse_http_date("Sun, 00 Apr 2024 12:00:00 GMT"), None);
        assert_eq!(unix("Thu, 29 Feb 2024 00:00:00 GMT"), Some(1_709_164_800));
        assert_eq!(parse_http_date("Sat, 29 Feb 2025 00:00:00 GMT"), None);
    }

    #[test]
    fn the_century_leap_rule_holds_both_ways() {
        assert!(parse_http_date("Tue, 29 Feb 2000 00:00:00 GMT").is_some());
        assert_eq!(parse_http_date("Wed, 29 Feb 1900 00:00:00 GMT"), None);
    }

    #[test]
    fn an_impossible_time_of_day_is_refused() {
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 24:00:00 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:60:00 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:61 GMT"), None);
    }

    #[test]
    fn a_leap_second_reads_as_the_second_before_it() {
        assert_eq!(
            unix("Sun, 31 Dec 2016 23:59:60 GMT"),
            unix("Sun, 31 Dec 2016 23:59:59 GMT")
        );
    }

    #[test]
    fn a_zone_that_is_not_gmt_is_refused() {
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 UTC"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 EST"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 +02"), None);
    }

    #[test]
    fn the_names_are_matched_case_sensitively() {
        assert_eq!(parse_http_date("Sun, 06 nov 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("SUN, 06 Nov 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 NOV 1994 08:49:37 gmt"), None);
    }

    #[test]
    fn a_digit_position_holding_something_else_is_refused() {
        for hostile in [
            "Sun, !6 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 199. 08:49:37 GMT",
            "Sun, 06 Nov 1994 /8:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:3\u{7f} GMT",
            "Sun, 0X Nov 1994 08:49:37 GMT",
            "Sun Nov  \u{1} 08:49:37 1994",
            "Sun Nov  6 08:49:37 19-4",
        ] {
            assert_eq!(parse_http_date(hostile), None, "{hostile:?}");
        }
    }

    #[test]
    fn no_byte_at_any_position_takes_the_parser_down() {
        for well_formed in ["Sun, 06 Nov 1994 08:49:37 GMT", "Sun Nov  6 08:49:37 1994"] {
            for position in 0..well_formed.len() {
                for byte in 0..=u8::MAX {
                    let mut text = well_formed.as_bytes().to_vec();
                    text[position] = byte;
                    let _ = parse_http_date(&String::from_utf8_lossy(&text));
                }
            }
        }
    }

    #[test]
    fn a_name_outside_the_tables_is_refused() {
        assert_eq!(parse_http_date("Xyz, 06 Nov 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Foo 1994 08:49:37 GMT"), None);
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_the_value() {
        assert_eq!(unix("  Sun, 06 Nov 1994 08:49:37 GMT\t"), Some(784_111_777));
        assert_eq!(parse_http_date("Sun,  06 Nov 1994 08:49:37 GMT"), None);
    }

    #[test]
    fn text_of_the_right_length_in_the_wrong_shape_is_refused() {
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GM7"), None);
        assert_eq!(parse_http_date("Sun. 06 Nov 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 0X Nov 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 199X 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 19X4"), None);
        assert_eq!(parse_http_date(""), None);
    }

    #[test]
    fn an_instant_before_the_epoch_keeps_its_sign() {
        assert_eq!(unix("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(unix("Wed, 31 Dec 1969 23:59:59 GMT"), Some(-1));
        assert_eq!(unix("Fri, 06 May 1995 12:00:00 GMT"), Some(799_761_600));
    }

    #[test]
    fn the_calendar_arithmetic_walks_an_era_one_day_at_a_time() {
        let mut expected = days_from_civil(1600, 1, 1);
        let start = expected;
        for year in 1600..2000 {
            for month in 1..=12 {
                for day in 1..=days_in_month(year, month) {
                    assert_eq!(
                        days_from_civil(year, month, day),
                        expected,
                        "{year}-{month}-{day}"
                    );
                    expected += 1;
                }
            }
        }
        assert_eq!(expected - start, 146_097);
    }
}
