//! Bounded whole-path percent interpretations, with source offsets.
//!
//! Decoding is independent of structural classes. Every enabled interpretation is
//! scanned and routed, including invalid UTF-8. Source offsets let structural
//! analysis conservatively anchor in the original request without mixing buffers.

use std::borrow::Cow;

/// One possible whole-path interpretation. Offsets always refer to the original input.
pub(crate) struct Interpretation<'a> {
    pub(crate) bytes: Cow<'a, [u8]>,
    origins: Option<Vec<usize>>,
    original: &'a [u8],
}

impl<'a> Interpretation<'a> {
    pub(crate) fn original(path: &'a [u8]) -> Self {
        Self {
            bytes: Cow::Borrowed(path),
            origins: None,
            original: path,
        }
    }

    pub(crate) fn source_offset(&self, offset: usize) -> usize {
        self.origins
            .as_ref()
            .map_or(offset, |origins| origins.get(offset).copied().unwrap_or(0))
    }

    pub(crate) fn escaped(&self, offset: usize) -> bool {
        self.origins.is_some() && self.original.get(self.source_offset(offset)) == Some(&b'%')
    }

    pub(crate) fn is_original(&self) -> bool {
        self.origins.is_none()
    }

    fn decode(&self) -> Option<Self> {
        // Malformed escapes are a fixed point: do not allocate buffers for them.
        (0..self.bytes.len()).find(|&i| byte_at(&self.bytes, i).is_some())?;
        let mut out = Vec::with_capacity(self.bytes.len());
        let mut origins = Vec::with_capacity(self.bytes.len());
        let mut i = 0;
        while let Some(&byte) = self.bytes.get(i) {
            let decoded = byte_at(&self.bytes, i);
            out.push(decoded.unwrap_or(byte));
            origins.push(self.source_offset(i));
            i += if decoded.is_some() { 3 } else { 1 };
        }
        Some(Self {
            bytes: Cow::Owned(out),
            origins: Some(origins),
            original: self.original,
        })
    }
}

/// Calls the same analysis for the raw path and each permitted complete decode.
/// Stops when decoding cannot change the path; malformed escapes are left literal.
pub(crate) fn interpretations(
    path: &[u8],
    up_to_two: bool,
    mut visit: impl FnMut(&Interpretation<'_>),
) {
    let mut view = Interpretation::original(path);
    visit(&view);
    for _ in 0..if up_to_two { 2 } else { 1 } {
        if !view.bytes.contains(&b'%') {
            break;
        }
        let Some(next) = view.decode() else {
            break;
        };
        view = next;
        visit(&view);
    }
}

/// Decode one hex digit (`0`–`9`, `a`–`f`, `A`–`F`) to its value, or `None`.
pub(crate) fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode the byte of a single `%XX` escape at `b[i]`, or `None` if `b[i]` does not
/// begin a complete escape (not a `%`, or fewer than two hex digits follow).
pub(crate) fn byte_at(b: &[u8], i: usize) -> Option<u8> {
    if b.get(i)? != &b'%' {
        return None;
    }
    let hi = hex_val(*b.get(i + 1)?)?;
    let lo = hex_val(*b.get(i + 2)?)?;
    Some(hi * 16 + lo)
}

/// Recognize raw overlong UTF-8 bytes encoding `/` or `.`, after percent decoding.
/// Returns the ASCII byte and the number of bytes consumed (2, 3, or 4).
pub(crate) fn overlong_at(b: &[u8], i: usize) -> Option<(u8, usize)> {
    let lead = *b.get(i)?;
    let seq_len: usize = match lead {
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => return None,
    };
    let mut cp = u32::from(lead & (0x7Fu8 >> seq_len));
    for k in 1..seq_len {
        let cont = *b.get(i + k)?;
        if cont & 0xC0 != 0x80 {
            return None;
        }
        cp = (cp << 6) | u32::from(cont & 0x3F);
    }
    let decoded = u8::try_from(cp).ok()?;
    (decoded == b'/' || decoded == b'.').then_some((decoded, seq_len))
}

/// Recognize raw UTF-8 fullwidth structural characters after percent decoding.
/// Returns the folded ASCII byte and the number of bytes consumed.
pub(crate) fn fullwidth_at(b: &[u8], i: usize) -> Option<(u8, usize)> {
    fn folded(third: u8) -> Option<u8> {
        match third {
            0x8F => Some(b'/'),
            0x8E => Some(b'.'),
            0x9B => Some(b';'),
            0xBC => Some(b'\\'),
            _ => None,
        }
    }
    // Raw UTF-8 `EF BC xx`.
    if b.get(i) == Some(&0xEF)
        && b.get(i + 1) == Some(&0xBC)
        && let Some(&third) = b.get(i + 2)
    {
        return folded(third).map(|a| (a, 3));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_interpretations_preserve_source_offsets_and_invalid_bytes() {
        let path = b"/ab%25%32%66%FF";
        let mut views = Vec::new();
        interpretations(path, true, |view| {
            views.push((
                view.bytes.to_vec(),
                (0..view.bytes.len())
                    .map(|i| view.source_offset(i))
                    .collect::<Vec<_>>(),
            ));
        });
        assert_eq!(views.len(), 3);
        assert_eq!(
            views[1],
            (b"/ab%2f\xff".to_vec(), vec![0, 1, 2, 3, 6, 9, 12])
        );
        assert_eq!(views[2], (b"/ab/\xff".to_vec(), vec![0, 1, 2, 3, 12]));
        let mut count = 0;
        interpretations(path, false, |_| count += 1);
        assert_eq!(count, 2);
    }

    #[test]
    fn decoding_stops_at_a_fixed_point() {
        for path in [b"/plain".as_slice(), b"/%", b"/%2", b"/%GG"] {
            let mut count = 0;
            interpretations(path, true, |view| {
                assert_eq!(view.bytes.as_ref(), path);
                assert!(view.is_original());
                count += 1;
            });
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn hex_val_decodes_both_cases() {
        assert_eq!(hex_val(b'0'), Some(0));
        assert_eq!(hex_val(b'9'), Some(9));
        assert_eq!(hex_val(b'a'), Some(10));
        assert_eq!(hex_val(b'F'), Some(15));
        assert_eq!(hex_val(b'g'), None);
        assert_eq!(hex_val(b'%'), None);
    }

    #[test]
    fn byte_at_decodes_complete_escapes() {
        assert_eq!(byte_at(b"%2f", 0), Some(b'/'));
        assert_eq!(byte_at(b"%2F", 0), Some(b'/'));
        assert_eq!(byte_at(b"a%2eb", 1), Some(b'.'));
        assert_eq!(byte_at(b"%00", 0), Some(0));
        // not a `%`, or truncated/invalid escape
        assert_eq!(byte_at(b"abc", 0), None);
        assert_eq!(byte_at(b"%2", 0), None);
        assert_eq!(byte_at(b"%2g", 0), None);
    }

    #[test]
    fn overlong_at_decodes_2_3_4_byte_forms() {
        assert_eq!(overlong_at(b"\xc0\xaf", 0), Some((b'/', 2)));
        assert_eq!(overlong_at(b"\xc0\xae", 0), Some((b'.', 2)));
        assert_eq!(overlong_at(b"\xe0\x80\xaf", 0), Some((b'/', 3)));
        assert_eq!(overlong_at(b"\xf0\x80\x80\xaf", 0), Some((b'/', 4)));
        // ordinary single-byte escape is not overlong
        assert_eq!(overlong_at(b"%2f", 0), None);
        // non-target overlong (overlong 'A') is ignored
        assert_eq!(overlong_at(b"\xc1\x81", 0), None);
        // truncated continuation
        assert_eq!(overlong_at(b"\xc0", 0), None);
    }

    #[test]
    fn fullwidth_at_recognizes_structural_bytes() {
        // Raw UTF-8 fullwidth forms (3 bytes each).
        assert_eq!(fullwidth_at("／".as_bytes(), 0), Some((b'/', 3)));
        assert_eq!(fullwidth_at("．".as_bytes(), 0), Some((b'.', 3)));
        assert_eq!(fullwidth_at("；".as_bytes(), 0), Some((b';', 3)));
        assert_eq!(fullwidth_at("＼".as_bytes(), 0), Some((b'\\', 3)));
        // A fullwidth *letter* (U+FF21 `Ａ`) is not a structural confusable.
        assert_eq!(fullwidth_at("Ａ".as_bytes(), 0), None);
        // Ordinary input.
        assert_eq!(fullwidth_at(b"abc", 0), None);
        assert_eq!(fullwidth_at(b"%2f", 0), None);
    }
}
