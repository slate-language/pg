// The wire format itself: how a message is built, and how one is read back out of a stream.
//
// **PostgreSQL's protocol is length-prefixed and not delimited**, which is the one thing that decides
// the shape of this file. Every message after the startup packet is a one-byte tag, a four-byte
// length that counts itself, and that many bytes less four -- so a reader can always say whether a
// whole message has arrived, and never has to look for a separator inside data that may contain one.
// That is why there is nothing here about escaping: a value carrying a newline, a null byte or what
// looks like another message is still one field of one message.
//
// **Everything is big-endian**, network order, including the length. A little-endian reading of a
// length is the mistake that shows as a client waiting forever for a message that already arrived.

// -- writing ---------------------------------------------------------------------------------------

// A message under construction: the bytes so far, with the tag and length filled in at the end.
//
// **The length cannot be written first because it is not known yet**, so `message` records where the
// four bytes belong and `sealed` goes back and writes them. Writing a guess and correcting it is the
// alternative and is how a protocol writer ends up with a length that is right except in one branch.
export message(tag) -> array
    val out = []

    if tag != null
        putByte(out, byteOf(tag))

    // The length's four bytes, written now and filled in by `sealed`.
    putInt32(out, 0)
    out

// The message finished: the length written over the four bytes `message` reserved.
//
// **The length counts itself and excludes the tag**, which is the protocol's rule and the one an
// implementation gets wrong by one in either direction. A length too small leaves the tail of this
// message to be read as the head of the next.
export sealed(out: array, tag) -> array
    val start = if tag == null then 0 else 1
    val n = len(out) - start

    out[start] = (n >> 24) & 255
    out[start + 1] = (n >> 16) & 255
    out[start + 2] = (n >> 8) & 255
    out[start + 3] = n & 255
    out

export putByte(out: array, b: integer) = push(out, b & 255)

export putInt16(out: array, n: integer)
    push(out, (n >> 8) & 255)
    push(out, n & 255)

export putInt32(out: array, n: integer)
    push(out, (n >> 24) & 255)
    push(out, (n >> 16) & 255)
    push(out, (n >> 8) & 255)
    push(out, n & 255)

export putBytes(out: array, bs: array)
    for b in bs
        push(out, b & 255)

// Text, as the protocol's `String`: UTF-8 and a zero byte.
//
// **`toBytes` and not `len`**, because a length in characters is a length in bytes only for ASCII --
// and a database is full of text that is not. That difference is silent: everything works until the
// first name with an accent in it.
export putString(out: array, s: string)
    putBytes(out, toBytes(s))
    push(out, 0)

// -- reading ---------------------------------------------------------------------------------------

// A cursor over one message's body.
//
// **A message is read field by field in the order the protocol lists them**, and the cursor is what
// keeps that reading honest: a field read short leaves the next one misaligned, so every reader here
// ends by asking the cursor what is left rather than assuming.
export reading(bs: array) -> object
    var i = 0

    val r = { }

    r.byte = () ->
        val b = bs[i]

        i = i + 1
        b

    r.int16 = () ->
        val n = (bs[i] << 8) | bs[i + 1]

        i = i + 2
        if n >= 32768 then n - 65536 else n

    r.int32 = () ->
        val n = (bs[i] << 24) | (bs[i + 1] << 16) | (bs[i + 2] << 8) | bs[i + 3]

        i = i + 4

        // **Signed, because the protocol uses -1 for "nothing here"** -- a column with no value, a
        // parameter that is null. A length read as unsigned makes that 4,294,967,295 bytes to come.
        if n >= 2147483648 then n - 4294967296 else n

    // A `String`: everything up to the next zero byte.
    r.string = () ->
        var end = i

        while end < len(bs) && bs[end] != 0
            end = end + 1

        val out = fromBytes(bs[i..<end])

        i = end + 1

        // **Text that is not UTF-8 is a fault rather than an empty string.** The server sends what
        // the database is encoded in, so this can only fire where the two disagree about that, and
        // saying so is worth more than a name that silently came back blank.
        if !out.ok then throw "the server sent text that is not UTF-8, which means this connection's encoding is not UTF-8"

        out.value

    r.bytes = (n) ->
        val out = bs[i..<(i + n)]

        i = i + n
        out

    r.rest = () -> bs[i..]

    r.left = () -> len(bs) - i

    r

// A stream of messages arriving in chunks that have nothing to do with where messages begin.
//
// **A TCP read boundary is not a message boundary**, and a client that assumed it was works on
// localhost and fails under load, or against a row wider than one packet. Everything is accumulated
// and `take` answers only whole messages.
export stream() -> object
    var held = []

    val s = { }

    s.feed = (chunk) ->
        for b in chunk
            push(held, b)

    // The next whole message, or `null` while one has not all arrived.
    s.take = () ->
        if len(held) < 5 then return null

        val size = (held[1] << 24) | (held[2] << 16) | (held[3] << 8) | held[4]

        // The tag is not counted by the length, so a message occupies `size + 1` bytes.
        if len(held) < size + 1 then return null

        val tag = fromBytes([held[0]]).value
        val body = held[5..<(size + 1)]

        held = held[(size + 1)..]

        { tag: tag, body: body }

    s

// The one byte a one-character tag is.
//
// **A tag is written as a character in the protocol's documentation and travels as a byte**, so
// spelling one here as `"Q"` rather than as 81 is what keeps this file readable against the manual.
export byteOf(c: string) -> integer = toBytes(c)[0]
