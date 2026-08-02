use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

pub const INLINE: usize = 30;

#[derive(Clone)]
pub enum Repr {
    Inline { len: u8, octets: [u8; INLINE] },
    Heap(Box<str>),
}

#[derive(Clone)]
pub struct Text(Repr);

impl Text {
    pub const fn new() -> Self {
        Self(Repr::Inline { len: 0, octets: [0; INLINE] })
    }

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

    #[allow(clippy::should_implement_trait)]
    #[inline]
    pub fn from_str(text: &str) -> Self {
        let octets = text.as_bytes();

        match octets.len() <= INLINE {
            true => Self(Repr::Inline { len: octets.len() as u8, octets: Self::copy_inline(octets) }),
            false => Self(Repr::Heap(text.into())),
        }
    }

    #[inline]
    pub fn from_string(text: String) -> Self {
        match text.len() <= INLINE {
            true => Self::from_str(&text),
            false => Self(Repr::Heap(text.into_boxed_str())),
        }
    }

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

    #[inline]
    pub fn from_verified_ascii(octets: &[u8]) -> Self {
        debug_assert!(octets.is_ascii(), "{:?} is not ASCII", String::from_utf8_lossy(octets));

        if octets.len() <= INLINE {
            return Self(Repr::Inline { len: octets.len() as u8, octets: Self::copy_inline(octets) });
        }

        Self(Repr::Heap(unsafe { std::str::from_utf8_unchecked(octets) }.into()))
    }

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

    #[inline]
    pub fn from_utf8_lossy(octets: &[u8]) -> Self {
        match std::str::from_utf8(octets) {
            Ok(text) => Self::from_str(text),
            Err(_) => Self::from_string(String::from_utf8_lossy(octets).into_owned()),
        }
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            Repr::Inline { len, octets } => unsafe { std::str::from_utf8_unchecked(&octets[..*len as usize]) },
            Repr::Heap(text) => text,
        }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            Repr::Inline { len, octets } => &octets[..*len as usize],
            Repr::Heap(text) => text.as_bytes(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match &self.0 {
            Repr::Inline { len, .. } => *len as usize,
            Repr::Heap(text) => text.len(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_inline(&self) -> bool {
        matches!(self.0, Repr::Inline { .. })
    }

    pub fn make_ascii_lowercase(&mut self) {
        match &mut self.0 {
            Repr::Inline { len, octets } => octets[..*len as usize].make_ascii_lowercase(),
            Repr::Heap(text) => text.make_ascii_lowercase(),
        }
    }

    pub fn into_string(self) -> String {
        match self.0 {
            Repr::Inline { .. } => self.as_str().to_owned(),
            Repr::Heap(text) => text.into_string(),
        }
    }

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
