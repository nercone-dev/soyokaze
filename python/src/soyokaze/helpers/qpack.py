"""QPACK, the HTTP/3 field compression format.

Fields cross the same way they do for HPACK, and the extra moving part is
QPACK's two instruction streams: what an :class:`Encoder` emits rides the
encoder stream to the peer's decoder, and what a :class:`Decoder` emits
rides back. Both cross here as raw octets, exactly as they travel.
"""

import ctypes

from .. import ffi
from ..errors import InvalidError, error_out, raise_for
from ..ffi import library
from .hpack import fields_argument, fields_taken

class Encoder:
    """A QPACK encoder with its dynamic table and instruction stream."""

    def __init__(self):
        self.handle = library.soyokaze_qpack_encoder_new()

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_qpack_encoder_free(self.handle)
            self.handle = None

    def set_max_capacity(self, max_capacity):
        """Records the peer's ``SETTINGS_QPACK_MAX_TABLE_CAPACITY``."""
        library.soyokaze_qpack_encoder_set_max_capacity(self.handle, max_capacity)

    def set_max_outstanding_sections(self, max_sections):
        """Caps how many unacknowledged sections the encoder tracks."""
        library.soyokaze_qpack_encoder_set_max_outstanding_sections(self.handle, max_sections)

    def set_capacity(self, capacity):
        """Sets the dynamic table capacity.

        Returns the instruction octets that announce it — send them down the
        encoder stream — or empty octets when the capacity did not change.
        """
        instructions = ffi.Buffer()
        if not library.soyokaze_qpack_encoder_set_capacity(self.handle, capacity, ctypes.byref(instructions)):
            raise InvalidError("the capacity was refused")
        return ffi.take(instructions)

    def encode(self, stream_id, fields):
        """Encodes one field section.

        Returns ``(block, instructions)``: the block for the request stream,
        and whatever instruction octets the encoding produced for the
        encoder stream.
        """
        array, slices = fields_argument(fields)
        block = ffi.Buffer()
        instructions = ffi.Buffer()
        if not library.soyokaze_qpack_encode(self.handle, stream_id, array, len(fields), ctypes.byref(block), ctypes.byref(instructions)):
            raise InvalidError("the fields were refused")
        return ffi.take(block), ffi.take(instructions)

    def on_decoder_instructions(self, data):
        """Feeds the encoder what arrived on the decoder stream."""
        error = error_out()
        data = ffi.encoded(data)
        raise_for(library.soyokaze_qpack_encoder_on_decoder_instructions(self.handle, data, len(data), ctypes.byref(error)), error)

    def cancel(self, stream_id):
        """Forgets the outstanding sections of a stream that was reset."""
        library.soyokaze_qpack_encoder_cancel(self.handle, stream_id)

class Decoder:
    """A QPACK decoder with its dynamic table and instruction stream."""

    def __init__(self):
        self.handle = library.soyokaze_qpack_decoder_new()

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_qpack_decoder_free(self.handle)
            self.handle = None

    def set_max_decoded_size(self, max_size):
        """Caps how large one decoded section may grow."""
        library.soyokaze_qpack_decoder_set_max_decoded_size(self.handle, max_size)

    def set_max_capacity(self, max_capacity):
        """Records this side's advertised ``SETTINGS_QPACK_MAX_TABLE_CAPACITY``."""
        library.soyokaze_qpack_decoder_set_max_capacity(self.handle, max_capacity)

    def on_encoder_instructions(self, data):
        """Feeds the decoder what arrived on the encoder stream.

        Returns whatever answer the instructions call for — octets for the
        decoder stream — or empty octets when nothing needs saying.
        """
        instructions = ffi.Buffer()
        error = error_out()
        data = ffi.encoded(data)
        raise_for(library.soyokaze_qpack_decoder_on_encoder_instructions(self.handle, data, len(data), ctypes.byref(instructions), ctypes.byref(error)), error)
        return ffi.take(instructions)

    def decode(self, stream_id, block):
        """Decodes one block.

        Returns ``(fields, instructions)``: the pairs decoded, and the
        acknowledgement octets for the decoder stream — empty when nothing
        needs saying.
        """
        out = ctypes.c_void_p()
        instructions = ffi.Buffer()
        error = error_out()
        block = ffi.encoded(block)
        raise_for(library.soyokaze_qpack_decode(self.handle, stream_id, block, len(block), ctypes.byref(out), ctypes.byref(instructions), ctypes.byref(error)), error)
        return fields_taken(out), ffi.take(instructions)
