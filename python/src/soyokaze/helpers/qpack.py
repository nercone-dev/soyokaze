"""QPACK, the HTTP/3 field compression format.

Fields cross the same way they do for HPACK, and the extra moving part is
QPACK's two instruction streams: what an :class:`Encoder` emits rides the
encoder stream to the peer's decoder, and what a :class:`Decoder` emits rides
back. Both cross either as raw octets, exactly as they travel, or one
:class:`EncoderInstruction` or :class:`DecoderInstruction` at a time.

QPACK numbers its :class:`StaticTable` from zero, which is the only way it
differs from HPACK here.
"""

import ctypes
import enum
import sys

from .. import ffi
from ..errors import Error, InvalidError
from ..ffi import library
from .fields import Fields, HeaderField, StaticIndex

class StaticTable:
    """The fixed table both ends already agree on."""

    BASE = library.soyokaze_qpack_static_base()
    """The lowest index the table is numbered from."""

    COUNT = library.soyokaze_qpack_static_count()
    """How many entries the table holds."""

    @classmethod
    def entries(cls):
        """Every entry, in wire order."""
        return [cls.get(index) for index in range(cls.BASE, cls.BASE + cls.COUNT)]

    @classmethod
    def get(cls, index):
        """The entry at ``index``, or ``None`` past the end."""
        name = library.soyokaze_qpack_static_name(index).text()
        if name is None:
            return None
        return HeaderField(name, library.soyokaze_qpack_static_value(index).text())

    @classmethod
    def index(cls):
        """The reverse index over the table."""
        return StaticIndex(library.soyokaze_qpack_static_index())

    @classmethod
    def find(cls, field):
        """Looks a field up, returning ``(index, exact)`` or ``None``."""
        name, value = ffi.Library.encoded(field.name), ffi.Library.encoded(field.value)
        out, exact = ctypes.c_uint64(), ctypes.c_bool()
        if not library.soyokaze_qpack_static_find(name, len(name), value, len(value), ctypes.byref(out), ctypes.byref(exact)):
            return None
        return out.value, exact.value

class DynamicTable:
    """The table an encoder and a decoder build up as they go.

    Indices are absolute — counted against how many entries have ever been
    inserted — unless a method says otherwise. Borrowed from the encoder or
    decoder that owns it, and valid only until that handle is used again.
    """

    DEFAULT_CAPACITY = library.soyokaze_qpack_default_capacity()
    """The capacity a table starts at: none, until the peer allows one."""

    def __init__(self, handle):
        self.handle = handle

    def size(self):
        """How many octets the entries add up to."""
        return library.soyokaze_qpack_table_size(self.handle)

    def capacity(self):
        """What the table is currently sized to."""
        return library.soyokaze_qpack_table_capacity(self.handle)

    def len(self):
        """How many entries the table holds."""
        return library.soyokaze_qpack_table_len(self.handle)

    def is_empty(self):
        """Whether the table holds nothing."""
        return library.soyokaze_qpack_table_is_empty(self.handle)

    def inserted_count(self):
        """How many entries have ever been inserted."""
        return library.soyokaze_qpack_table_inserted_count(self.handle)

    def get(self, absolute_index):
        """The entry at ``absolute_index``, or ``None``."""
        name = library.soyokaze_qpack_table_name(self.handle, absolute_index).text()
        if name is None:
            return None
        return HeaderField(name, library.soyokaze_qpack_table_value(self.handle, absolute_index).text())

    def fits(self, field):
        """Whether the field would fit in the table as it is sized now."""
        name, value = ffi.Library.encoded(field.name), ffi.Library.encoded(field.value)
        return library.soyokaze_qpack_table_fits(self.handle, name, len(name), value, len(value))

    def relative(self, index):
        """The relative index an absolute one is written as, or ``None``."""
        relative = library.soyokaze_qpack_table_relative(self.handle, index)
        return None if relative < 0 else relative

    def indexed(self, base, index):
        """The absolute index a block's indexed reference names, or ``None``."""
        absolute = library.soyokaze_qpack_table_indexed(self.handle, base, index)
        return None if absolute < 0 else absolute

    def post_base(self, base, index):
        """The absolute index a block's post-base reference names, or ``None``."""
        absolute = library.soyokaze_qpack_table_post_base(self.handle, base, index)
        return None if absolute < 0 else absolute

    def find(self, field):
        """Looks a field up, returning ``(absolute_index, exact)`` or ``None``."""
        name, value = ffi.Library.encoded(field.name), ffi.Library.encoded(field.value)
        out, exact = ctypes.c_uint64(), ctypes.c_bool()
        if not library.soyokaze_qpack_table_find(self.handle, name, len(name), value, len(value), ctypes.byref(out), ctypes.byref(exact)):
            return None
        return out.value, exact.value

    def probe(self, field, below):
        """Looks a field up among the entries below ``below``.

        Returns ``(matched, blocked)``, where ``matched`` is
        ``(absolute_index, exact)`` or ``None``, and ``blocked`` says whether an
        entry at or above ``below`` would have matched.
        """
        name, value = ffi.Library.encoded(field.name), ffi.Library.encoded(field.value)
        out, exact, blocked = ctypes.c_uint64(), ctypes.c_bool(), ctypes.c_bool()
        found = library.soyokaze_qpack_table_probe(self.handle, name, len(name), value, len(value), below, ctypes.byref(out), ctypes.byref(exact), ctypes.byref(blocked))
        return ((out.value, exact.value) if found else None), blocked.value

    def __len__(self):
        return self.len()

class Prefix:
    """The prefix a field section opens with."""

    @classmethod
    def max_entries(cls, max_capacity):
        """The most entries a table of this capacity could ever hold."""
        return library.soyokaze_qpack_prefix_max_entries(max_capacity)

    @classmethod
    def relative(cls, base, absolute):
        """The index a field block names an absolute entry by."""
        return library.soyokaze_qpack_prefix_relative(base, absolute)

    @classmethod
    def encode_insert_count(cls, required, max_capacity):
        """Encodes the required insert count that leads a field block."""
        return library.soyokaze_qpack_prefix_encode_insert_count(required, max_capacity)

    @classmethod
    def decode_insert_count(cls, encoded, inserted, max_capacity):
        """Recovers the required insert count from its wrapped form."""
        out = ctypes.c_uint64()
        if not library.soyokaze_qpack_prefix_decode_insert_count(encoded, inserted, max_capacity, ctypes.byref(out)):
            raise InvalidError("the insert count could not have been produced by an encoder")
        return out.value

class EncoderInstructionKind(enum.IntEnum):
    """Which instruction an encoder-stream instruction is."""

    SET_DYNAMIC_TABLE_CAPACITY = 0
    INSERT_WITH_NAME_REFERENCE = 1
    INSERT_WITH_LITERAL_NAME = 2
    DUPLICATE = 3

class EncoderInstruction:
    """An instruction the encoder sends on its unidirectional stream."""

    def __init__(self, handle):
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_qpack_encoder_instruction_free(self.handle)
            self.handle = None

    @classmethod
    def SetDynamicTableCapacity(cls, capacity):
        """Resize the dynamic table, within what the decoder advertised."""
        return cls(library.soyokaze_qpack_encoder_instruction_set_capacity(capacity))

    @classmethod
    def InsertWithNameReference(cls, from_static, name_index, value):
        """Insert a field whose name is taken from an existing entry."""
        value = ffi.Library.encoded(value)
        return cls(library.soyokaze_qpack_encoder_instruction_insert_with_name_reference(from_static, name_index, value, len(value)))

    @classmethod
    def InsertWithLiteralName(cls, name, value):
        """Insert a field, spelling out both name and value."""
        name, value = ffi.Library.encoded(name), ffi.Library.encoded(value)
        return cls(library.soyokaze_qpack_encoder_instruction_insert_with_literal_name(name, len(name), value, len(value)))

    @classmethod
    def Duplicate(cls, index):
        """Re-insert an existing entry, so it survives eviction of the original."""
        return cls(library.soyokaze_qpack_encoder_instruction_duplicate(index))

    @classmethod
    def decode(cls, data):
        """Decodes one instruction off the encoder stream, returning ``(read, instruction)``."""
        data = ffi.Library.encoded(data)
        out, read, error = ctypes.c_void_p(), ctypes.c_size_t(), Error.out()
        Error.raise_for(library.soyokaze_qpack_encoder_instruction_decode(data, len(data), ctypes.byref(out), ctypes.byref(read), ctypes.byref(error)), error)
        return read.value, cls(out)

    def kind(self):
        """Which instruction this is."""
        return EncoderInstructionKind(library.soyokaze_qpack_encoder_instruction_kind(self.handle))

    def capacity(self):
        """The capacity a ``SetDynamicTableCapacity`` asks for."""
        return library.soyokaze_qpack_encoder_instruction_capacity(self.handle)

    def from_static(self):
        """Whether an ``InsertWithNameReference`` addresses the static table."""
        return library.soyokaze_qpack_encoder_instruction_from_static(self.handle)

    def index(self):
        """The entry an ``InsertWithNameReference`` or a ``Duplicate`` names."""
        return library.soyokaze_qpack_encoder_instruction_index(self.handle)

    def name(self):
        """The name an ``InsertWithLiteralName`` spells out."""
        return library.soyokaze_qpack_encoder_instruction_name(self.handle).bytes()

    def value(self):
        """The value an insertion spells out."""
        return library.soyokaze_qpack_encoder_instruction_value(self.handle).bytes()

    def encode(self):
        """The instruction as it travels the encoder stream."""
        return library.soyokaze_qpack_encoder_instruction_encode(self.handle).take()

    def release(self):
        """Hands the handle over to a call that consumes it."""
        handle, self.handle = self.handle, None
        return handle

    def __repr__(self):
        return f"EncoderInstruction({self.kind().name})"

class DecoderInstructionKind(enum.IntEnum):
    """Which instruction a decoder-stream instruction is."""

    SECTION_ACKNOWLEDGMENT = 0
    STREAM_CANCELLATION = 1
    INSERT_COUNT_INCREMENT = 2

class DecoderInstruction:
    """An instruction the decoder sends back on its unidirectional stream."""

    def __init__(self, handle):
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_qpack_decoder_instruction_free(self.handle)
            self.handle = None

    @classmethod
    def SectionAcknowledgment(cls, stream_id):
        """A field section on this stream was decoded."""
        return cls(library.soyokaze_qpack_decoder_instruction_section_acknowledgment(stream_id))

    @classmethod
    def StreamCancellation(cls, stream_id):
        """This stream was abandoned, so its sections will never be acknowledged."""
        return cls(library.soyokaze_qpack_decoder_instruction_stream_cancellation(stream_id))

    @classmethod
    def InsertCountIncrement(cls, increment):
        """This many further insertions have been taken in."""
        return cls(library.soyokaze_qpack_decoder_instruction_insert_count_increment(increment))

    @classmethod
    def decode(cls, data):
        """Decodes one instruction off the decoder stream, returning ``(read, instruction)``."""
        data = ffi.Library.encoded(data)
        out, read, error = ctypes.c_void_p(), ctypes.c_size_t(), Error.out()
        Error.raise_for(library.soyokaze_qpack_decoder_instruction_decode(data, len(data), ctypes.byref(out), ctypes.byref(read), ctypes.byref(error)), error)
        return read.value, cls(out)

    def kind(self):
        """Which instruction this is."""
        return DecoderInstructionKind(library.soyokaze_qpack_decoder_instruction_kind(self.handle))

    def stream_id(self):
        """The stream an acknowledgment or a cancellation names."""
        return library.soyokaze_qpack_decoder_instruction_stream_id(self.handle)

    def increment(self):
        """How many entries an ``InsertCountIncrement`` reports."""
        return library.soyokaze_qpack_decoder_instruction_increment(self.handle)

    def encode(self):
        """The instruction as it travels the decoder stream."""
        return library.soyokaze_qpack_decoder_instruction_encode(self.handle).take()

    def release(self):
        """Hands the handle over to a call that consumes it."""
        handle, self.handle = self.handle, None
        return handle

    def __repr__(self):
        return f"DecoderInstruction({self.kind().name})"

class Encoder:
    """A QPACK encoder with its dynamic table and instruction stream."""

    DEFAULT_CAPACITY_LIMIT = library.soyokaze_qpack_default_capacity_limit()
    """The capacity the encoder bounds itself to unless told otherwise."""

    DEFAULT_MAX_OUTSTANDING_SECTIONS = library.soyokaze_qpack_default_max_outstanding_sections()
    """How many unacknowledged sections are allowed unless told otherwise."""

    DEFAULT_MAX_INSTRUCTION_SIZE = library.soyokaze_qpack_default_max_instruction_size()
    """How large one buffered instruction may grow unless told otherwise."""

    DEFAULT_IDLE_CAPACITY = library.soyokaze_qpack_default_idle_capacity()
    """How much of a drained stream buffer is kept for reuse."""

    def __init__(self):
        self.handle = library.soyokaze_qpack_encoder_new()

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_qpack_encoder_free(self.handle)
            self.handle = None

    def set_max_capacity(self, max_capacity):
        """Records the peer's ``SETTINGS_QPACK_MAX_TABLE_CAPACITY``.

        Returns the instruction octets announcing the new capacity — send them
        down the encoder stream — or empty octets when it did not change.
        """
        instructions = ffi.Buffer()
        if not library.soyokaze_qpack_encoder_set_max_capacity(self.handle, max_capacity, ctypes.byref(instructions)):
            raise InvalidError("the capacity was refused")
        return instructions.take()

    def set_capacity_limit(self, capacity_limit):
        """Bounds the capacity the encoder keeps, whatever the peer permits.

        Returns the instruction octets announcing a shrunk capacity, or empty
        octets when it did not change.
        """
        instructions = ffi.Buffer()
        if not library.soyokaze_qpack_encoder_set_capacity_limit(self.handle, capacity_limit, ctypes.byref(instructions)):
            raise InvalidError("the capacity limit was refused")
        return instructions.take()

    def set_max_outstanding_sections(self, max_sections):
        """Caps how many unacknowledged sections the encoder tracks."""
        library.soyokaze_qpack_encoder_set_max_outstanding_sections(self.handle, max_sections)

    def set_max_instruction_size(self, max_size):
        """Caps how large a single buffered instruction may grow."""
        library.soyokaze_qpack_encoder_set_max_instruction_size(self.handle, max_size)

    def set_idle_capacity(self, idle_capacity):
        """Caps how much of a drained stream buffer is kept for reuse."""
        library.soyokaze_qpack_encoder_set_idle_capacity(self.handle, idle_capacity)

    def capacity_limit(self):
        """What the encoder bounds its own table to."""
        return library.soyokaze_qpack_encoder_capacity_limit(self.handle)

    def max_capacity(self):
        """The peer's advertised table capacity, as last recorded."""
        return library.soyokaze_qpack_encoder_max_capacity(self.handle)

    def outstanding(self):
        """How many field sections are still unacknowledged."""
        return library.soyokaze_qpack_encoder_outstanding(self.handle)

    def known_received_count(self):
        """How many insertions the peer's decoder is known to have taken in."""
        return library.soyokaze_qpack_encoder_known_received_count(self.handle)

    def dynamic_table(self):
        """The encoder's dynamic table."""
        return DynamicTable(library.soyokaze_qpack_encoder_table(self.handle))

    def reference(self, field):
        """What the encoder would reference a field by, across both tables.

        Returns ``(from_static, index, exact)`` or ``None``.
        """
        name, value = ffi.Library.encoded(field.name), ffi.Library.encoded(field.value)
        from_static, out, exact = ctypes.c_bool(), ctypes.c_uint64(), ctypes.c_bool()
        if not library.soyokaze_qpack_encoder_reference(self.handle, name, len(name), value, len(value), ctypes.byref(from_static), ctypes.byref(out), ctypes.byref(exact)):
            return None
        return from_static.value, out.value, exact.value

    def queue(self, instructions):
        """Queues instructions onto the encoder stream, consuming them."""
        array = (ctypes.c_void_p * len(instructions))(*[instruction.release() for instruction in instructions])
        library.soyokaze_qpack_encoder_queue(self.handle, array, len(instructions))

    def encoder_stream(self):
        """What the encoder has waiting on its stream."""
        return library.soyokaze_qpack_encoder_stream(self.handle).bytes()

    def take_encoder_stream(self):
        """Takes what the encoder has waiting on its stream."""
        return library.soyokaze_qpack_encoder_take_stream(self.handle).take()

    def encode(self, stream_id, headers):
        """Encodes one field section.

        Returns ``(block, instructions)``: the block for the request stream,
        and whatever instruction octets the encoding produced for the encoder
        stream.
        """
        array, slices = Fields.argument(headers)
        block, instructions = ffi.Buffer(), ffi.Buffer()
        if not library.soyokaze_qpack_encode(self.handle, stream_id, array, len(array), ctypes.byref(block), ctypes.byref(instructions)):
            raise InvalidError("the fields were refused")
        return block.take(), instructions.take()

    def on_decoder_instructions(self, data):
        """Feeds the encoder what arrived on the decoder stream."""
        error = Error.out()
        data = ffi.Library.encoded(data)
        Error.raise_for(library.soyokaze_qpack_encoder_on_decoder_instructions(self.handle, data, len(data), ctypes.byref(error)), error)

    def on_decoder_instruction(self, instruction):
        """Takes in one decoder-stream instruction, consuming it."""
        library.soyokaze_qpack_encoder_on_decoder_instruction(self.handle, instruction.release())

    def cancel(self, stream_id):
        """Forgets the outstanding sections of a stream that was reset."""
        library.soyokaze_qpack_encoder_cancel(self.handle, stream_id)

class Decoder:
    """A QPACK decoder with its dynamic table and instruction stream."""

    DEFAULT_MAX_CAPACITY = library.soyokaze_qpack_default_max_capacity()
    """The table capacity the decoder advertises unless told otherwise."""

    DEFAULT_MAX_DECODED_SIZE = library.soyokaze_qpack_default_max_decoded_size()
    """How large one decoded section may grow unless told otherwise."""

    DEFAULT_MAX_INSTRUCTION_SIZE = library.soyokaze_qpack_default_max_instruction_size()
    """How large one buffered instruction may grow unless told otherwise."""

    DEFAULT_MAX_BLOCKED_STREAMS = library.soyokaze_qpack_default_max_blocked_streams()
    """How many streams may block on the encoder stream unless told otherwise."""

    DEFAULT_IDLE_CAPACITY = library.soyokaze_qpack_default_idle_capacity()
    """How much of a drained stream buffer is kept for reuse."""

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

    def set_max_instruction_size(self, max_size):
        """Caps how large a single buffered instruction may grow."""
        library.soyokaze_qpack_decoder_set_max_instruction_size(self.handle, max_size)

    def set_max_blocked_streams(self, max_streams):
        """Caps how many streams may wait QPACK-blocked at once."""
        library.soyokaze_qpack_decoder_set_max_blocked_streams(self.handle, max_streams)

    def set_idle_capacity(self, idle_capacity):
        """Caps how much of a drained stream buffer is kept for reuse."""
        library.soyokaze_qpack_decoder_set_idle_capacity(self.handle, idle_capacity)

    def blocked(self):
        """How many streams are waiting on insertions that have not arrived."""
        return library.soyokaze_qpack_decoder_blocked(self.handle)

    def unblocked(self):
        """Which streams the last insertions unblocked."""
        octets = library.soyokaze_qpack_decoder_unblocked(self.handle).take()
        return [int.from_bytes(octets[at:at + 8], sys.byteorder) for at in range(0, len(octets), 8)]

    def cancel(self, stream_id):
        """Forgets a stream that was abandoned before its blocks arrived."""
        library.soyokaze_qpack_decoder_cancel(self.handle, stream_id)

    def dynamic_table(self):
        """The decoder's dynamic table."""
        return DynamicTable(library.soyokaze_qpack_decoder_table(self.handle))

    def resolve(self, from_static, base, index):
        """The field a block's reference names, across both tables, or ``None``."""
        name, value = ffi.Buffer(), ffi.Buffer()
        if not library.soyokaze_qpack_decoder_resolve(self.handle, from_static, base, index, ctypes.byref(name), ctypes.byref(value)):
            return None
        return HeaderField(name.take().decode(), value.take().decode())

    def resolve_name(self, from_static, base, index):
        """The name a block's reference names, across both tables, or ``None``."""
        name = library.soyokaze_qpack_decoder_resolve_name(self.handle, from_static, base, index).taken()
        return None if name is None else name.decode()

    def queue(self, instructions):
        """Queues instructions onto the decoder stream, consuming them."""
        array = (ctypes.c_void_p * len(instructions))(*[instruction.release() for instruction in instructions])
        library.soyokaze_qpack_decoder_queue(self.handle, array, len(instructions))

    def decoder_stream(self):
        """What the decoder has waiting on its stream."""
        return library.soyokaze_qpack_decoder_stream(self.handle).bytes()

    def take_decoder_stream(self):
        """Takes what the decoder has waiting on its stream."""
        return library.soyokaze_qpack_decoder_take_stream(self.handle).take()

    def on_encoder_instructions(self, data):
        """Feeds the decoder what arrived on the encoder stream.

        Returns whatever answer the instructions call for — octets for the
        decoder stream — or empty octets when nothing needs saying.
        """
        instructions = ffi.Buffer()
        error = Error.out()
        data = ffi.Library.encoded(data)
        Error.raise_for(library.soyokaze_qpack_decoder_on_encoder_instructions(self.handle, data, len(data), ctypes.byref(instructions), ctypes.byref(error)), error)
        return instructions.take()

    def on_encoder_instruction(self, instruction):
        """Takes in one encoder-stream instruction, consuming it.

        Returns what the decoder owes back, or ``None`` when it owes nothing.
        """
        out, error = ctypes.c_void_p(), Error.out()
        Error.raise_for(library.soyokaze_qpack_decoder_on_encoder_instruction(self.handle, instruction.release(), ctypes.byref(out), ctypes.byref(error)), error)
        return DecoderInstruction(out) if out else None

    def decode(self, stream_id, block):
        """Decodes one block.

        Returns ``(fields, instructions)``: the pairs decoded, and the
        acknowledgement octets for the decoder stream — empty when nothing
        needs saying.
        """
        out = ctypes.c_void_p()
        instructions = ffi.Buffer()
        error = Error.out()
        block = ffi.Library.encoded(block)
        Error.raise_for(library.soyokaze_qpack_decode(self.handle, stream_id, block, len(block), ctypes.byref(out), ctypes.byref(instructions), ctypes.byref(error)), error)
        return Fields.taken(out), instructions.take()
