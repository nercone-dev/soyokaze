"""Scanning octets a word at a time.

The word-at-a-time primitives the crate's parsers are built out of: finding an
octet, copying a run, and classifying a field value. Nothing here knows what it
is scanning for.
"""

import ctypes

from .. import ffi
from ..ffi import library

LANES = library.soyokaze_scan_lanes()
"""How many octets one word holds."""

LOW = library.soyokaze_scan_low()
"""The word with the low bit of every octet set."""

HIGH = library.soyokaze_scan_high()
"""The word with the high bit of every octet set."""

VALUE_CONTROL = library.soyokaze_scan_value_control()
""":func:`classify_field_value`: an octet below space, or delete."""

VALUE_OBS_TEXT = library.soyokaze_scan_value_obs_text()
""":func:`classify_field_value`: an octet at or above ``0x80``."""

def holds_zero(word):
    """A word marking which octets of ``word`` are zero."""
    return library.soyokaze_scan_holds_zero(word)

def holds_less(word, bound):
    """A word marking which octets of ``word`` are below ``bound``."""
    return library.soyokaze_scan_holds_less(word, bound)

def marks_zero(word):
    """A word marking which octets of ``word`` are exactly zero."""
    return library.soyokaze_scan_marks_zero(word)

def word_at(haystack, offset):
    """The word at ``offset``, read in native order."""
    haystack = ffi.Library.encoded(haystack)
    return library.soyokaze_scan_word_at(haystack, len(haystack), offset)

def find(haystack, needle):
    """Where ``needle`` first appears, or ``None`` when it does not."""
    haystack = ffi.Library.encoded(haystack)
    found = library.soyokaze_scan_find(haystack, len(haystack), needle)
    return None if found < 0 else found

def copy(source):
    """A copy of ``source``, made the way the crate copies a run of octets."""
    source = ffi.Library.encoded(source)
    destination = (ctypes.c_uint8 * len(source))()
    library.soyokaze_scan_copy(destination, len(source), source, len(source))
    return bytes(destination)

def same(left, right):
    """Whether the two runs hold the same octets."""
    left, right = ffi.Library.encoded(left), ffi.Library.encoded(right)
    return library.soyokaze_scan_same(left, len(left), right, len(right))

def classify_field_value(text):
    """The or of :data:`VALUE_CONTROL` and :data:`VALUE_OBS_TEXT` over every octet."""
    text = ffi.Library.encoded(text)
    return library.soyokaze_scan_classify_field_value(text, len(text))

def is_field_value(text):
    """Whether every octet may appear in a field value."""
    text = ffi.Library.encoded(text)
    return library.soyokaze_scan_is_field_value(text, len(text))

def all_in_class(text, table, mask):
    """Whether every octet has ``mask`` set in a 256-entry classification table."""
    text, table = ffi.Library.encoded(text), ffi.Library.encoded(table)
    return library.soyokaze_scan_all_in_class(text, len(text), table, mask)
