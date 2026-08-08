//! The field vocabulary HPACK and QPACK share, from C.
//!
//! [`Field`] carries one name and value pair in, and [`Fields`] carries a
//! decoded block back out. Both compression formats cross the boundary with
//! these, the way [`crate::helpers::hpack`] and [`crate::helpers::qpack`]
//! share [`crate::helpers::fields`].

use crate::ffi::Slice;
use crate::helpers::fields::HeaderField;

/// One field going in: a name and a value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Field {
    /// The field name.
    pub name: Slice,
    /// The field value.
    pub value: Slice,
}

impl Field {
    /// Reads `count` fields out of a C array.
    ///
    /// `None` when the array is null with a non-zero count, or any name or
    /// value is null or not UTF-8.
    ///
    /// # Safety
    ///
    /// `fields` must either be null or point to `count` readable [`Field`]
    /// values whose own pointers are valid.
    pub unsafe fn parse_all(fields: *const Field, count: usize) -> Option<Vec<HeaderField>> {
        if fields.is_null() {
            return (count == 0).then(Vec::new);
        }

        let mut parsed = Vec::with_capacity(count);

        for index in 0..count {
            let field = unsafe { *fields.add(index) };
            let name = unsafe { Slice::borrow_text(field.name.data, field.name.len) }?;
            let value = unsafe { Slice::borrow_text(field.value.data, field.value.len) }?;
            parsed.push(HeaderField::new(name, value));
        }

        Some(parsed)
    }
}

/// A decoded field section, as a decoder hands it back.
pub struct Fields(pub Vec<HeaderField>);

/// Releases a [`Fields`].
///
/// # Safety
///
/// `fields` must come from a decode call and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_fields_free(fields: *mut Fields) {
    if !fields.is_null() {
        drop(unsafe { Box::from_raw(fields) });
    }
}

/// How many fields the section holds.
///
/// # Safety
///
/// `fields` must either be null or be a handle that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_fields_count(fields: *const Fields) -> usize {
    unsafe { fields.as_ref() }.map_or(0, |fields| fields.0.len())
}

/// The name of the field at `index`, borrowed from `fields`.
///
/// # Safety
///
/// As [`soyokaze_fields_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_fields_name(fields: *const Fields, index: usize) -> Slice {
    Slice::maybe(unsafe { fields.as_ref() }.and_then(|fields| fields.0.get(index)).map(|field| field.name.as_str()))
}

/// The value of the field at `index`, borrowed from `fields`.
///
/// # Safety
///
/// As [`soyokaze_fields_count`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_fields_value(fields: *const Fields, index: usize) -> Slice {
    Slice::maybe(unsafe { fields.as_ref() }.and_then(|fields| fields.0.get(index)).map(|field| field.value.as_str()))
}
