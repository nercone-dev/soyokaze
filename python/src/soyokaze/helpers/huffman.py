"""The HPACK and QPACK Huffman code.

One code serves both compression formats, as in the crate. The code table
itself is here, symbol by symbol, alongside the whole-string encode and decode
and the decoding automaton they walk.
"""

import ctypes
import enum

from .. import ffi
from ..errors import ProtocolError
from ..ffi import library

EOS = library.soyokaze_huffman_eos()
"""The end-of-string symbol, which never appears in a well-formed encoding."""

NIBBLE = library.soyokaze_huffman_nibble()
"""How many transitions one automaton row holds: one per four-bit input."""

EMIT = library.soyokaze_huffman_emit()
""":class:`Transition`: a symbol was completed and should be emitted."""

FAIL = library.soyokaze_huffman_fail()
""":class:`Transition`: the bits do not spell a code word, so decoding fails."""

ENDED = library.soyokaze_huffman_ended()
""":class:`Transition`: the end-of-string code was met, which the wire forbids."""

class Symbol:
    """One code word: ``length`` bits, right-aligned in ``code``."""

    def __init__(self, code, length):
        self.code = code
        self.length = length

    def __eq__(self, other):
        return isinstance(other, Symbol) and (self.code, self.length) == (other.code, other.length)

    def __repr__(self):
        return f"Symbol({self.code:#x}, {self.length})"

class Transition:
    """One step of the decoding automaton, for one state and one four-bit input."""

    def __init__(self, next, symbol, flags):
        self.next = next
        self.symbol = symbol
        self.flags = flags

    def __repr__(self):
        return f"Transition({self.next}, {self.symbol}, {self.flags:#x})"

class Branch(enum.IntEnum):
    """What following one bit out of a node reaches."""

    NONE = 0
    NODE = 1
    SYMBOL = 2

class DecodeError(enum.IntEnum):
    """Why a Huffman string would not decode."""

    OK = 0
    INVALID_PADDING = 1
    UNKNOWN_SYMBOL = 2
    INVALID = 3

    def message(self):
        """A fixed description of the error."""
        return library.soyokaze_huffman_error_message(int(self)).text()

def table():
    """The code word for each octet, and for :data:`EOS` at the end."""
    return [symbol(index) for index in range(library.soyokaze_huffman_table_len())]

def symbol(index):
    """The code word for ``index``, which runs up to and including :data:`EOS`."""
    built = library.soyokaze_huffman_symbol(index)
    return Symbol(built.code, built.length)

def lengths():
    """How many bits each code word is."""
    return [length(index) for index in range(library.soyokaze_huffman_table_len())]

def length(index):
    """How many bits the code word for ``index`` is."""
    return library.soyokaze_huffman_length(index)

class DecodeTable:
    """The decoding automaton, built once and shared."""

    @classmethod
    def states(cls):
        """How many states the automaton has."""
        return library.soyokaze_huffman_states()

    @classmethod
    def nodes(cls):
        """How many nodes the bit-level tree of the code has."""
        return library.soyokaze_huffman_nodes()

    @classmethod
    def transition(cls, state, nibble):
        """The transition out of ``state`` on ``nibble``."""
        built = library.soyokaze_huffman_transition(state, nibble)
        return Transition(built.next, built.symbol, built.flags)

    @classmethod
    def accepting(cls, state):
        """Whether ``state`` may end an encoding."""
        return library.soyokaze_huffman_accepting(state)

    @classmethod
    def step(cls, node, bit):
        """What following ``bit`` out of ``node`` reaches.

        Returns ``(branch, value)``, where ``value`` is a node index for
        :attr:`Branch.NODE` and a symbol for :attr:`Branch.SYMBOL`.
        """
        value = ctypes.c_uint32()
        branch = Branch(library.soyokaze_huffman_step(node, bit, ctypes.byref(value)))
        return branch, value.value

def decode_table():
    """The shared decoding automaton."""
    return DecodeTable

def encoded_len(data):
    """How many octets :func:`encode` will produce, padding included."""
    data = ffi.Library.encoded(data)
    return library.soyokaze_huffman_encoded_len(data, len(data))

def encode(data):
    """Huffman-encodes octets."""
    data = ffi.Library.encoded(data)
    return library.soyokaze_huffman_encode(data, len(data)).take()

def decode(data):
    """Huffman-decodes octets, raising :class:`ProtocolError` on a bad sequence."""
    data = ffi.Library.encoded(data)
    out, error = ffi.Buffer(), ctypes.c_int32()
    if not library.soyokaze_huffman_decode(data, len(data), ctypes.byref(out), ctypes.byref(error)):
        raise ProtocolError(DecodeError(error.value).message())
    return out.take()

def decode_into_ascii(data):
    """As :func:`decode`, also reporting whether every octet is printable ASCII.

    Returns ``(octets, ascii)``.
    """
    data = ffi.Library.encoded(data)
    out, ascii, error = ffi.Buffer(), ctypes.c_bool(), ctypes.c_int32()
    if not library.soyokaze_huffman_decode_ascii(data, len(data), ctypes.byref(out), ctypes.byref(ascii), ctypes.byref(error)):
        raise ProtocolError(DecodeError(error.value).message())
    return out.take(), ascii.value
