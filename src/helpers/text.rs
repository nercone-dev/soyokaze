//! [`Text`], the string type field names and values are held in.
//!
//! A field section is mostly short strings — `host`, `accept`, `gzip`, a
//! status code — and allocating each one costs more than the message itself.
//! [`Text`] keeps anything up to [`INLINE`] octets in the value and only
//! reaches for the heap beyond that.
//!
//! [`Text`] is immutable apart from [`Text::make_ascii_lowercase`], which is
//! what field names need, and compares and hashes as the string it holds, so
//! it can stand in for `&str` in a map.

use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

/// The longest string held without allocating.
///
/// Chosen so that [`Text`] fits in the same space as a `Box<str>` plus its
/// discriminant and length, which covers all but the longest field values.
pub const INLINE: usize = 30;

/// Where a [`Text`] keeps its octets.
#[derive(Clone)]
pub enum Repr {
    /// Held in the value itself, `len` octets of `octets` being live.
    Inline {
        /// How many leading octets are live; never above [`INLINE`].
        len: u8,
        /// The octets, of which only the first `len` are meaningful.
        octets: [u8; INLINE],
    },
    /// Held on the heap, for anything longer than [`INLINE`].
    Heap(Box<str>),
}

/// A short immutable string that stays off the heap.
///
/// Everything a [`Text`] can be built from is valid UTF-8 by construction —
/// except the `verified` constructors, which trust the caller. It derefs to
/// `str`, so the usual string methods are available on it directly.
#[derive(Clone)]
pub struct Text(Repr);

impl Text {
    /// The empty string.
    pub const fn new() -> Self {
        Self(Repr::Inline { len: 0, octets: [0; INLINE] })
    }

    /// Copies up to [`INLINE`] octets of `source` into a fresh inline buffer.
    ///
    /// The copy is done as a pair of overlapping fixed-width copies rather
    /// than a length-driven loop. Octets past `source.len()` are left zero.
    ///
    /// # Panics
    ///
    /// Panics when `source` is longer than [`INLINE`].
    #[inline]
    pub fn copy_inline(source: &[u8]) -> [u8; INLINE] {
        let mut octets = [0u8; INLINE];
        let len = source.len();

        if len >= 16 {
            octets[..16].copy_from_slice(&source[..16]);
            octets[len - 16..len].copy_from_slice(&source[len - 16..]);
        } else if len >= 8 {
            octets[..8].copy_from_slice(&source[..8]);
            octets[len - 8..len].copy_from_slice(&source[len - 8..]);
        } else if len >= 4 {
            octets[..4].copy_from_slice(&source[..4]);
            octets[len - 4..len].copy_from_slice(&source[len - 4..]);
        } else if len >= 2 {
            octets[..2].copy_from_slice(&source[..2]);
            octets[len - 2..len].copy_from_slice(&source[len - 2..]);
        } else if len == 1 {
            octets[0] = source[0];
        }

        octets
    }

    /// Copies a string slice, staying inline when it is short enough.
    #[allow(clippy::should_implement_trait)]
    #[inline]
    pub fn from_str(text: &str) -> Self {
        let octets = text.as_bytes();

        match octets.len() <= INLINE {
            true => Self(Repr::Inline { len: octets.len() as u8, octets: Self::copy_inline(octets) }),
            false => Self(Repr::Heap(text.into())),
        }
    }

    /// Takes ownership of a `String`, reusing its allocation when it is long
    /// enough to need one.
    #[inline]
    pub fn from_string(text: String) -> Self {
        match text.len() <= INLINE {
            true => Self::from_str(&text),
            false => Self(Repr::Heap(text.into_boxed_str())),
        }
    }

    /// Lowercases ASCII octets while copying them in.
    ///
    /// Input that is not ASCII goes through lossy UTF-8 decoding first, so
    /// this never fails.
    #[inline]
    pub fn from_ascii_lowercase(octets: &[u8]) -> Self {
        if !octets.is_ascii() {
            return Self::from_string(String::from_utf8_lossy(octets).to_ascii_lowercase());
        }

        if octets.len() <= INLINE {
            let mut inline = Self::copy_inline(octets);
            inline[..octets.len()].make_ascii_lowercase();
            return Self(Repr::Inline { len: octets.len() as u8, octets: inline });
        }

        let mut text = octets.to_vec();
        text.make_ascii_lowercase();
        Self(Repr::Heap(String::from_utf8_lossy(&text).into_owned().into_boxed_str()))
    }

    /// Copies octets that are expected to be ASCII, checking that they are.
    ///
    /// Input that is not ASCII goes through lossy UTF-8 decoding, so this
    /// never fails. Use [`Text::from_verified_ascii`] only where the check has
    /// already been done.
    #[inline]
    pub fn from_ascii(octets: &[u8]) -> Self {
        match octets.is_ascii() {
            true => {
                if octets.len() <= INLINE {
                    return Self(Repr::Inline { len: octets.len() as u8, octets: Self::copy_inline(octets) });
                }

                Self::from_utf8_lossy(octets)
            }
            false => Self::from_utf8_lossy(octets),
        }
    }

    /// Copies octets already known to be ASCII, skipping the check.
    ///
    /// This is the constructor the parsers use after
    /// [`scan::classify_field_value`] has already established that a field
    /// value carries no octet at or above `0x80`, so paying for a second pass
    /// would be waste.
    ///
    /// The caller must have established that `octets` is ASCII. Passing
    /// anything else produces a [`Text`] that is not valid UTF-8, and reading
    /// it back through [`Text::as_str`] is undefined behaviour. Debug builds
    /// assert; release builds do not check. Use [`Text::from_ascii`] wherever
    /// the input has not already been classified.
    ///
    /// [`scan::classify_field_value`]: crate::helpers::scan::classify_field_value
    #[inline]
    pub fn from_verified_ascii(octets: &[u8]) -> Self {
        debug_assert!(octets.is_ascii(), "{:?} is not ASCII", String::from_utf8_lossy(octets));

        if octets.len() <= INLINE {
            return Self(Repr::Inline { len: octets.len() as u8, octets: Self::copy_inline(octets) });
        }

        Self(Repr::Heap(unsafe { std::str::from_utf8_unchecked(octets) }.into()))
    }

    /// [`Text::from_verified_ascii`], lowercasing as it copies.
    ///
    /// This is what field names go through, since a name is a token and so is
    /// ASCII by the time it has been parsed.
    ///
    /// The same precondition applies: the caller must have established that
    /// `octets` is ASCII, and passing anything else is undefined behaviour.
    #[inline]
    pub fn from_verified_ascii_lowercase(octets: &[u8]) -> Self {
        debug_assert!(octets.is_ascii(), "{:?} is not ASCII", String::from_utf8_lossy(octets));

        if octets.len() <= INLINE {
            let mut inline = Self::copy_inline(octets);
            inline[..octets.len()].make_ascii_lowercase();
            return Self(Repr::Inline { len: octets.len() as u8, octets: inline });
        }

        let mut text = octets.to_vec();
        text.make_ascii_lowercase();
        Self(Repr::Heap(unsafe { String::from_utf8_unchecked(text) }.into_boxed_str()))
    }

    /// Copies octets, replacing anything that is not valid UTF-8.
    ///
    /// This is the constructor to reach for when nothing is known about the
    /// input; it never fails.
    #[inline]
    pub fn from_utf8_lossy(octets: &[u8]) -> Self {
        match std::str::from_utf8(octets) {
            Ok(text) => Self::from_str(text),
            Err(_) => Self::from_string(String::from_utf8_lossy(octets).into_owned()),
        }
    }

    /// The string held, wherever it lives.
    #[inline]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            Repr::Inline { len, octets } => unsafe { std::str::from_utf8_unchecked(&octets[..*len as usize]) },
            Repr::Heap(text) => text,
        }
    }

    /// The octets of the string held.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            Repr::Inline { len, octets } => &octets[..*len as usize],
            Repr::Heap(text) => text.as_bytes(),
        }
    }

    /// The length in octets, not characters.
    #[inline]
    pub fn len(&self) -> usize {
        match &self.0 {
            Repr::Inline { len, .. } => *len as usize,
            Repr::Heap(text) => text.len(),
        }
    }

    /// Whether the string is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the octets are held in the value rather than on the heap.
    pub fn is_inline(&self) -> bool {
        matches!(self.0, Repr::Inline { .. })
    }

    /// Lowercases the ASCII letters in place, leaving everything else alone.
    pub fn make_ascii_lowercase(&mut self) {
        match &mut self.0 {
            Repr::Inline { len, octets } => octets[..*len as usize].make_ascii_lowercase(),
            Repr::Heap(text) => text.make_ascii_lowercase(),
        }
    }

    /// Consumes the text and returns a `String`, reusing the heap allocation
    /// when there is one.
    pub fn into_string(self) -> String {
        match self.0 {
            Repr::Inline { .. } => self.as_str().to_owned(),
            Repr::Heap(text) => text.into_string(),
        }
    }

    /// Consumes the text and returns its octets.
    pub fn into_bytes(self) -> Vec<u8> {
        self.into_string().into_bytes()
    }
}

impl Default for Text {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for Text {
    type Target = str;

    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for Text {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for Text {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for Text {
    #[inline]
    fn from(text: &str) -> Self {
        Self::from_str(text)
    }
}

impl From<String> for Text {
    #[inline]
    fn from(text: String) -> Self {
        Self::from_string(text)
    }
}

impl From<&String> for Text {
    fn from(text: &String) -> Self {
        Self::from_str(text)
    }
}

impl From<std::borrow::Cow<'_, str>> for Text {
    fn from(text: std::borrow::Cow<'_, str>) -> Self {
        match text {
            std::borrow::Cow::Borrowed(text) => Self::from_str(text),
            std::borrow::Cow::Owned(text) => Self::from_string(text),
        }
    }
}

impl From<Text> for String {
    fn from(text: Text) -> Self {
        text.into_string()
    }
}

impl PartialEq for Text {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Text {}

impl PartialEq<str> for Text {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl PartialEq<&str> for Text {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl PartialEq<String> for Text {
    fn eq(&self, other: &String) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl PartialEq<Text> for str {
    fn eq(&self, other: &Text) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl PartialEq<Text> for &str {
    fn eq(&self, other: &Text) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl PartialOrd for Text {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Text {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl Hash for Text {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
