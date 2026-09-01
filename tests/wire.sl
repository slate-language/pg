// The wire format: how a message is built, and how one is read back out of a stream that knows
// nothing about where messages begin.

import { message, sealed, putByte, putInt16, putInt32, putBytes, putString, reading, stream,
    byteOf } from "../wire.sl"

@test
A_MESSAGE_CARRIES_ITS_TAG_AND_A_LENGTH_THAT_COUNTS_ITSELF()
    // **The length excludes the tag and includes its own four bytes**, which is the rule an
    // implementation gets wrong by one in either direction -- and a length one too small leaves the
    // tail of this message to be read as the head of the next.
    val m = message("Q")

    putString(m, "select 1")

    val out = sealed(m, "Q")

    assert(out[0] == byteOf("Q"))
    assert(len(out) == 1 + 4 + 8 + 1)
    assert(out[4] == 13)
    assert(fromBytes(out[5..<13]).value == "select 1")

@test
A_STARTUP_PACKET_HAS_NO_TAG_AND_ITS_LENGTH_STILL_COUNTS_ITSELF()
    // The one message with no tag, which is what `message(null)` is for. Its length starts at byte
    // zero rather than at byte one, and getting that wrong is a connection that never gets past
    // hello.
    val m = message(null)

    putInt32(m, 196608)

    val out = sealed(m, null)

    assert(len(out) == 8)
    assert(out[3] == 8)
    assert(out[7] == 0)

@test
TEXT_IS_MEASURED_IN_BYTES_AND_NOT_IN_CHARACTERS()
    // **`len` counts characters, which is right, and a protocol counts bytes.** Every message here
    // works in English and breaks on the first name with an accent in it if that difference is
    // missed.
    val m = message("Q")

    putString(m, "café")

    val out = sealed(m, "Q")

    assert(len("café") == 4)
    assert(out[4] == 4 + 5 + 1)

@test
AN_INT32_IS_SIGNED_BECAUSE_MINUS_ONE_MEANS_NOTHING_HERE()
    // **-1 is how the protocol says a column has no value and a parameter is null.** Read as
    // unsigned it is four billion bytes still to come, which is a client that waits forever.
    val m = message("D")

    putInt32(m, -1)
    putInt32(m, 0)
    putInt32(m, 2147483647)

    val r = reading(sealed(m, "D")[5..])

    assert(r.int32() == -1)
    assert(r.int32() == 0)
    assert(r.int32() == 2147483647)

@test
AN_INT16_IS_SIGNED_TOO()
    // A column's type modifier is -1 where it has none, and a `RowDescription` carries one per
    // column -- so a reader that took it as unsigned would still be aligned and would still be
    // wrong.
    val m = message("T")

    putInt16(m, -1)
    putInt16(m, 300)

    val r = reading(sealed(m, "T")[5..])

    assert(r.int16() == -1)
    assert(r.int16() == 300)

@test
A_STRING_ENDS_AT_ITS_ZERO_BYTE_AND_THE_CURSOR_GOES_PAST_IT()
    val m = message("S")

    putString(m, "TimeZone")
    putString(m, "UTC")
    putString(m, "")

    val r = reading(sealed(m, "S")[5..])

    assert(r.string() == "TimeZone")
    assert(r.string() == "UTC")
    assert(r.string() == "")
    assert(r.left() == 0)

@test
A_MESSAGE_SPLIT_ACROSS_ARRIVALS_IS_NOT_A_MESSAGE_YET()
    // **A TCP read boundary is not a message boundary.** A client that assumed it was works on
    // loopback and fails on the first row wider than a packet -- which is the failure that only
    // shows up in production.
    val s = stream()

    // One byte at a time, which is the worst case a real socket can produce.
    val full = built("select 1")

    for i in 0..<len(full)
        assert(s.take() == null)

        s.feed([full[i]])

    val got = s.take()

    assert(got != null)
    assert(got.tag == "Q")
    assert(reading(got.body).string() == "select 1")
    assert(s.take() == null)

@test
TWO_MESSAGES_IN_ONE_ARRIVAL_ARE_READ_IN_ORDER()
    // The other side of the same fact: a server writes `RowDescription`, three `DataRow`s and a
    // `CommandComplete` in one write, and they arrive as one chunk.
    val s = stream()
    val both = []

    putBytes(both, built("first"))
    putBytes(both, built("second"))

    s.feed(both)

    assert(reading(s.take().body).string() == "first")
    assert(reading(s.take().body).string() == "second")
    assert(s.take() == null)

@test
A_MESSAGE_WITH_AN_EMPTY_BODY_IS_STILL_A_MESSAGE()
    // `ParseComplete`, `BindComplete`, `NoData` and `EmptyQueryResponse` all carry nothing but their
    // tag and a length of four -- and a reader that needed a body would stall on the first one.
    val s = stream()

    s.feed(sealed(message("1"), "1"))

    val got = s.take()

    assert(got.tag == "1")
    assert(len(got.body) == 0)

built(text)
    val m = message("Q")

    putString(m, text)
    sealed(m, "Q")
