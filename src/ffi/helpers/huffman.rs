//! The HPACK and QPACK Huffman code, from C.
//!
//! One code serves both compression formats, as in
//! [`crate::helpers::huffman`]. The code table itself crosses, symbol by
//! symbol, alongside the whole-string encode and decode and the length either
//! one will produce.

use crate::ffi::{Buffer, Slice};

/// One code word: `length` bits, right-aligned in `code`.
///
/// The C half of [`Symbol`], field for field.
///
/// [`Symbol`]: crate::helpers::huffman::Symbol
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Symbol {
    /// The code word, right-aligned.
    pub code: u32,
    /// How many bits of `code` are meaningful; never more than 30.
    pub length: u8,
}

impl Symbol {
    /// The C half of `symbol`.
    pub fn build(symbol: &crate::helpers::huffman::Symbol) -> Self {
        Self { code: symbol.code, length: symbol.length }
    }
}

/// Why a Huffman string would not decode.
///
/// The C half of [`DecodeError`], with [`DecodeError::Ok`] added for the call
/// that succeeded.
///
/// [`DecodeError`]: crate::helpers::huffman::DecodeError
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// The input decoded.
    Ok = 0,
    /// The encoding does not end on the all-ones padding, or it spells out the
    /// end-of-string code in full.
    InvalidPadding = 1,
    /// The bits do not spell a code word.
    UnknownSymbol = 2,
    /// The input was null.
    Invalid = 3,
}

impl DecodeError {
    /// The error that stands for `error`.
    pub fn of(error: &crate::helpers::huffman::DecodeError) -> Self {
        match error {
            crate::helpers::huffman::DecodeError::InvalidPadding => Self::InvalidPadding,
            crate::helpers::huffman::DecodeError::UnknownSymbol => Self::UnknownSymbol,
        }
    }

    /// Writes an error through an out parameter, which may be null.
    ///
    /// # Safety
    ///
    /// `out` must either be null or be writable.
    pub unsafe fn report(out: *mut DecodeError, error: Self) {
        if !out.is_null() {
            unsafe { *out = error };
        }
    }

    /// A fixed description of the error.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::InvalidPadding => "huffman padding is not all one-bits",
            Self::UnknownSymbol => "huffman code does not map to a known symbol",
            Self::Invalid => "invalid argument",
        }
    }
}

/// A fixed description of `error`.
///
/// Borrowed from the library and valid for its lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_error_message(error: DecodeError) -> Slice {
    Slice::text(error.message())
}

/// The end-of-string symbol, which never appears in a well-formed encoding.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_eos() -> u16 {
    crate::helpers::huffman::EOS
}

/// How many symbols the code table holds: 256 octets and the end-of-string.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_table_len() -> usize {
    crate::helpers::huffman::TABLE.len()
}

/// The code word for `index`, which runs up to and including
/// [`soyokaze_huffman_eos`].
///
/// An index past the end reads as a zero-length code word.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_symbol(index: usize) -> Symbol {
    match crate::helpers::huffman::table().get(index) {
        Some(symbol) => Symbol::build(symbol),
        None => Symbol { code: 0, length: 0 },
    }
}

/// How many bits the code word for `index` is, or zero past the end.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_length(index: usize) -> u8 {
    crate::helpers::huffman::LENGTHS.get(index).copied().unwrap_or(0)
}

/// How many transitions one automaton row holds: one per four-bit input.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_nibble() -> usize {
    crate::helpers::huffman::NIBBLE
}

/// [`Transition`]: a symbol was completed and should be emitted.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_emit() -> u8 {
    crate::helpers::huffman::EMIT
}

/// [`Transition`]: the bits do not spell a code word, so decoding fails.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_fail() -> u8 {
    crate::helpers::huffman::FAIL
}

/// [`Transition`]: the end-of-string code was met, which is not allowed on the
/// wire.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_ended() -> u8 {
    crate::helpers::huffman::ENDED
}

/// One step of the decoding automaton, for one state and one four-bit input.
///
/// The C half of [`Transition`], field for field.
///
/// [`Transition`]: crate::helpers::huffman::Transition
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Transition {
    /// The state to move to.
    pub next: u16,
    /// The symbol completed, meaningful only when [`soyokaze_huffman_emit`] is
    /// set.
    pub symbol: u8,
    /// The or of [`soyokaze_huffman_emit`], [`soyokaze_huffman_fail`] and
    /// [`soyokaze_huffman_ended`].
    pub flags: u8,
}

impl Transition {
    /// The C half of `transition`.
    pub fn build(transition: &crate::helpers::huffman::Transition) -> Self {
        Self { next: transition.next, symbol: transition.symbol, flags: transition.flags }
    }
}

/// What following one bit out of a node reaches.
///
/// The C half of [`Branch`], with [`Branch::None`] added for the bit that
/// continues no code word.
///
/// [`Branch`]: crate::helpers::huffman::Branch
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Branch {
    /// The bit continues no code word.
    None = 0,
    /// Another node, by index; `value` is that index.
    Node = 1,
    /// A complete symbol; `value` is that symbol.
    Symbol = 2,
}

/// How many states the decoding automaton has.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_states() -> usize {
    crate::helpers::huffman::decode_table().rows.len()
}

/// How many nodes the bit-level tree of the code has.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_nodes() -> usize {
    crate::helpers::huffman::decode_table().branches.len()
}

/// The transition out of `state` on `nibble`, whose low four bits are read.
///
/// A state past the end reads as the stuck transition.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_transition(state: usize, nibble: u8) -> Transition {
    match crate::helpers::huffman::decode_table().rows.get(state) {
        Some(row) => Transition::build(&row[nibble as usize & (crate::helpers::huffman::NIBBLE - 1)]),
        None => Transition::build(&crate::helpers::huffman::Transition::STUCK),
    }
}

/// Whether `state` may end an encoding.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_huffman_accepting(state: usize) -> bool {
    crate::helpers::huffman::decode_table().accepting.get(state).copied().unwrap_or(false)
}

/// What following `bit` out of `node` reaches, writing the index or symbol
/// through `value`.
///
/// # Safety
///
/// `value` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_huffman_step(node: usize, bit: bool, value: *mut u32) -> Branch {
    let (branch, reached) = match crate::helpers::huffman::decode_table().step(node, bit) {
        Some(crate::helpers::huffman::Branch::Node(index)) => (Branch::Node, index as u32),
        Some(crate::helpers::huffman::Branch::Symbol(symbol)) => (Branch::Symbol, symbol as u32),
        None => (Branch::None, 0),
    };

    if !value.is_null() {
        unsafe { *value = reached };
    }

    branch
}

/// How many octets encoding this input will produce, padding included.
///
/// A null `data` measures the empty input.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_huffman_encoded_len(data: *const u8, data_len: usize) -> usize {
    crate::helpers::huffman::encoded_len(unsafe { Slice::borrow(data, data_len) }.unwrap_or_default())
}

/// Huffman-encodes octets, owned by the caller.
///
/// A null `data` encodes nothing and comes back empty.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_huffman_encode(data: *const u8, data_len: usize) -> Buffer {
    match unsafe { Slice::borrow(data, data_len) } {
        Some(data) => Buffer::new(crate::helpers::huffman::encode(data).to_vec()),
        None => Buffer::EMPTY,
    }
}

/// Huffman-decodes octets through `out`, returning whether they decoded.
///
/// Refused when the input is null or is not a valid Huffman sequence — a
/// truncated symbol, or padding done wrong. What went wrong is written through
/// `error`, which may be null.
///
/// # Safety
///
/// `data` must either be null or point to `data_len` readable octets, and
/// `out` and `error` must either be null or be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_huffman_decode(data: *const u8, data_len: usize, out: *mut Buffer, error: *mut DecodeError) -> bool {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        unsafe { DecodeError::report(error, DecodeError::Invalid) };
        return false;
    };

    match crate::helpers::huffman::decode(data) {
        Ok(octets) => {
            if !out.is_null() {
                unsafe { *out = Buffer::new(octets.to_vec()) };
            }

            unsafe { DecodeError::report(error, DecodeError::Ok) };
            true
        }
        Err(failure) => {
            unsafe { DecodeError::report(error, DecodeError::of(&failure)) };
            false
        }
    }
}

/// As [`soyokaze_huffman_decode`], reporting through `ascii` whether every
/// octet decoded is printable ASCII.
///
/// A field value that is all printable ASCII may be held without copying,
/// which is what the decoders inside the crate use this for.
///
/// # Safety
///
/// As [`soyokaze_huffman_decode`], and `ascii` must either be null or be
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_huffman_decode_ascii(data: *const u8, data_len: usize, out: *mut Buffer, ascii: *mut bool, error: *mut DecodeError) -> bool {
    let Some(data) = (unsafe { Slice::borrow(data, data_len) }) else {
        unsafe { DecodeError::report(error, DecodeError::Invalid) };
        return false;
    };

    let mut octets = Vec::new();

    match crate::helpers::huffman::decode_into_ascii(data, &mut octets) {
        Ok(printable) => {
            if !out.is_null() {
                unsafe { *out = Buffer::new(octets) };
            }

            if !ascii.is_null() {
                unsafe { *ascii = printable };
            }

            unsafe { DecodeError::report(error, DecodeError::Ok) };
            true
        }
        Err(failure) => {
            unsafe { DecodeError::report(error, DecodeError::of(&failure)) };
            false
        }
    }
}
