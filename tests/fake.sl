// A PostgreSQL server written in slate, answering bytes written out from the protocol.
//
// **EVERY TEST OF THE CLIENT TALKS TO THIS AND NOT TO A DATABASE.** The wire forms below are written
// out longhand from the message formats, so what they prove is that this client agrees with the
// *protocol* rather than with whichever PostgreSQL happens to be installed -- and the suite needs no
// server, no cluster and no password. `check/live.sl` is the other half of that bargain and is run
// by hand against a real one.
//
// **THE FAKE ANSWERS PER MESSAGE AND NEVER PER CHUNK, WHICH IS NOT A DETAIL.** A loopback delivers
// three queries written in one turn as one, two or three reads depending on nothing a test controls,
// so a server that answered every arrival would answer the wrong number of times and the failure
// would land in the teardown as a reset. It reads whole messages with the client's own framing and
// answers each one.

import { listen, onBytes, send, startTls, close as closeSocket, localPort } from slate:net
import { message, sealed, putByte, putInt16, putInt32, putBytes, putString, reading,
    stream, byteOf } from "../wire.sl"

// A server that answers each message with whatever `answer(kind, r, sock)` gives back.
//
// `kind` is `"startup"` for the first packet, and the message's tag after that -- `"Q"`, `"P"`,
// `"p"`, `"X"`. Answering `null` sends nothing, which is what a message that needs no reply gets.
//
// **`secure` is `{ cert, key }` for a server that will speak TLS, and `null` for one that will not.**
// Both are worth having: the client asks either way now, and what a server says to the question is
// exactly what the test is about. A server given a certificate answers `S` and upgrades its end; one
// given nothing answers `N` and carries on in the clear, which is what every test written before TLS
// existed still wants.
export server(answer, secure = null)
    val made = listen(0, (sock) ->
        var started = false
        var asked = false
        val messages = stream()
        var held = []

        onBytes(sock, (chunk) ->
            if chunk == null
                closeSocket(sock)

                return

            // The startup packet has no tag, so it is read by length before the framed reader takes
            // over. Everything after it is an ordinary tagged message.
            if !started
                for b in chunk
                    push(held, b)

                if len(held) < 4 then return

                val size = (held[0] << 24) | (held[1] << 16) | (held[2] << 8) | held[3]

                if len(held) < size then return

                // **The SSLRequest arrives BEFORE the startup packet and is shaped like one**: eight
                // bytes, a length and a magic number where a protocol version goes. It is answered
                // with one bare byte and no framing at all, which is the only message in the protocol
                // that has none.
                if !asked && size == 8
                    val code = (held[4] << 24) | (held[5] << 16) | (held[6] << 8) | held[7]

                    if code == 80877103
                        asked = true
                        held = held[8..]

                        // **The question itself is offered to `answer`**, so a test can say that a
                        // connection asked -- or, for `sslmode: "disable"`, that it did not. What it
                        // gives back is ignored: the reply to this one is a bare byte and not a
                        // message, and it is decided by `secure` rather than by a fixture.
                        answer("ssl", reading([]), sock)

                        if secure == null
                            send(sock, "N")
                        else
                            // **Sent before the upgrade and not after.** The byte answering the
                            // question is the last thing in the clear, and a server that secured its
                            // end first would encrypt it -- to a client that has not started a
                            // handshake and would read it as a record it cannot make sense of.
                            send(sock, "S")
                            startTls(sock, { cert: secure.cert, key: secure.key })

                        // The client waits for this byte before writing anything else, so there is
                        // never a startup packet behind it in the same arrival.
                        return

                val body = held[4..<size]
                val extra = held[size..]

                started = true
                held = []

                val out = answer("startup", reading(body), sock)

                if out != null then send(sock, out)

                messages.feed(extra)
            else
                messages.feed(chunk)

            while true
                val m = messages.take()

                if m == null then return

                val out = answer(m.tag, reading(m.body), sock)

                if out != null then send(sock, out))
    )

    made

export portOf(s) = localPort(s)

// -- the messages a server sends, written out from the protocol -------------------------------------

// `AuthenticationOk`, and the three messages that follow a successful login.
export authOk()
    val out = []

    val r = message("R")

    putInt32(r, 0)
    putBytes(out, sealed(r, "R"))
    putBytes(out, parameterStatus("server_version", "16.0"))
    putBytes(out, backendKey(1234, 5678))
    putBytes(out, readyFor("I"))
    out

// `AuthenticationCleartextPassword`.
export authCleartext()
    val r = message("R")

    putInt32(r, 3)
    sealed(r, "R")

// `AuthenticationMD5Password`, with the four-byte salt it challenges with.
export authMd5(salt)
    val r = message("R")

    putInt32(r, 5)
    putBytes(r, salt)
    sealed(r, "R")

// `AuthenticationSASL`, listing the mechanisms this server will accept.
export authSasl(mechanisms)
    val r = message("R")

    putInt32(r, 10)

    for m in mechanisms
        putString(r, m)

    putByte(r, 0)
    sealed(r, "R")

// `AuthenticationSASLContinue`, carrying the server's first message.
export authSaslContinue(text)
    val r = message("R")

    putInt32(r, 11)
    putBytes(r, toBytes(text))
    sealed(r, "R")

// `AuthenticationSASLFinal`, carrying the server's signature.
export authSaslFinal(text)
    val r = message("R")

    putInt32(r, 12)
    putBytes(r, toBytes(text))
    sealed(r, "R")

export parameterStatus(name, value)
    val s = message("S")

    putString(s, name)
    putString(s, value)
    sealed(s, "S")

export backendKey(pid, key)
    val k = message("K")

    putInt32(k, pid)
    putInt32(k, key)
    sealed(k, "K")

// `ReadyForQuery`, whose one byte is the transaction status: `I`, `T` or `E`.
export readyFor(status)
    val z = message("Z")

    putByte(z, byteOf(status))
    sealed(z, "Z")

// `RowDescription`. Each column carries its table, its type, and the format it is sent in -- all of
// which this client reads, so all of which have to be here.
export describe(columns)
    val t = message("T")

    putInt16(t, len(columns))

    for c in columns
        putString(t, c.name)
        putInt32(t, 0)
        putInt16(t, 0)
        putInt32(t, c.oid)
        putInt16(t, -1)
        putInt32(t, -1)
        putInt16(t, 0)

    sealed(t, "T")

// `DataRow`. **A column with no value is a length of -1 and not an empty one**, which is the
// difference this fake exists to be able to send.
export dataRow(values)
    val d = message("D")

    putInt16(d, len(values))

    for v in values
        if v == null
            putInt32(d, -1)
        else
            val bs = toBytes(v)

            putInt32(d, len(bs))
            putBytes(d, bs)

    sealed(d, "D")

export commandComplete(tag)
    val c = message("C")

    putString(c, tag)
    sealed(c, "C")

export emptyQuery()
    val i = message("I")

    sealed(i, "I")

// `ErrorResponse` and `NoticeResponse`, which share a shape: field letters, each with a string, and
// a zero byte to finish.
export errorResponse(fields) = noted("E", fields)

export noticeResponse(fields) = noted("N", fields)

noted(tag, fields)
    val e = message(tag)

    for f in fields
        putByte(e, byteOf(f.kind))
        putString(e, f.text)

    putByte(e, 0)
    sealed(e, tag)

// `NotificationResponse` -- what `notify` sends, which arrives between replies and belongs to no
// query at all.
export notification(pid, channel, payload)
    val a = message("A")

    putInt32(a, pid)
    putString(a, channel)
    putString(a, payload)
    sealed(a, "A")

// `ParseComplete`, `BindComplete` and `NoData`, which are the extended protocol's acknowledgements.
export parseComplete()
    val one = message("1")

    sealed(one, "1")

export bindComplete()
    val two = message("2")

    sealed(two, "2")

export noData()
    val n = message("n")

    sealed(n, "n")

// Several messages as one array of bytes, which is how a server actually writes a reply.
export joined(parts)
    val out = []

    for p in parts
        putBytes(out, p)

    out
