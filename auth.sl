// Logging in: the three ways a PostgreSQL server will ask, and the text encodings the answers need.
//
// **SCRAM-SHA-256 is the one that matters**, being what PostgreSQL 14 and later configure by default
// and what `initdb` writes into `pg_hba.conf` without being asked. A client that speaks only the
// older methods cannot log in to a current server at all.
//
// **The cryptography is `slate:crypto`'s and the layout is here**, which is the seam this package is
// written on: SHA-256, HMAC, PBKDF2 and the nonce come from the language, and hex, base64, MD5 and
// the message forms of RFC 5802 are ordinary slate. `slate:jwt` writes its own base64url for the
// same reason.
//
// **MD5 is written out here rather than asked for.** `slate:crypto` has no MD5 and should not grow
// one: nothing new should use it, and what it is needed for here is a *legacy* server's challenge,
// which costs two hashes of forty bytes once per connection. That is the whole case for writing it
// in slate, and it would not survive being needed in a loop.

import { sha256, hmac, pbkdf2, randomBytes } from slate:crypto

// -- text encodings ---------------------------------------------------------------------------------

val Hex = "0123456789abcdef"

export hex(bs)
    var out = ""

    for b in bs
        out = out + Hex[b >> 4] + Hex[b & 15]

    out

val B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// Standard base64 with padding, which is what SCRAM's salt, proof and verifier travel as.
//
// **Not base64url.** A token is url-safe because it goes in a header; this goes in a SASL message,
// which is bytes on a socket, and `+` and `/` are what the other end will send.
export base64(bs)
    var out = ""
    var i = 0

    while i + 2 < len(bs)
        val n = (bs[i] << 16) | (bs[i + 1] << 8) | bs[i + 2]

        out = out + B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63]
        i = i + 3

    val left = len(bs) - i

    if left == 1
        val n = bs[i] << 16

        out = out + B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + "=="
    elif left == 2
        val n = (bs[i] << 16) | (bs[i + 1] << 8)

        out = out + B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + "="

    out

// Base64 back to bytes.
//
// **Anything that is not a base64 character is skipped rather than refused**, which is the one place
// this is lenient: what arrives is a field of a message the server built, and a client that died on
// an unexpected newline would be refusing to log in over something that means nothing.
export unbase64(s)
    val out = []
    var acc = 0
    var bits = 0

    for i in 0..<len(s)
        val at = B64.indexOf(s[i])

        if at != null
            acc = (acc << 6) | at
            bits = bits + 6

            if bits >= 8
                bits = bits - 8
                push(out, (acc >> bits) & 255)

    out

// -- MD5, for a server that asks the old way ---------------------------------------------------------

val Md5K = [
    3614090360, 3905402710, 606105819, 3250441966, 4118548399, 1200080426, 2821735955, 4249261313,
    1770035416, 2336552879, 4294925233, 2304563134, 1804603682, 4254626195, 2792965006, 1236535329,
    4129170786, 3225465664, 643717713, 3921069994, 3593408605, 38016083, 3634488961, 3889429448,
    568446438, 3275163606, 4107603335, 1163531501, 2850285829, 4243563512, 1735328473, 2368359562,
    4294588738, 2272392833, 1839030562, 4259657740, 2763975236, 1272893353, 4139469664, 3200236656,
    681279174, 3936430074, 3572445317, 76029189, 3654602809, 3873151461, 530742520, 3299628645,
    4096336452, 1126891415, 2878612391, 4237533241, 1700485571, 2399980690, 4293915773, 2240044497,
    1873313359, 4264355552, 2734768916, 1309151649, 4149444226, 3174756917, 718787259, 3951481745]

val Md5S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

val Mask32 = 4294967295

rotated(x, n) = ((x << n) | (x >> (32 - n))) & Mask32

// MD5 of a byte array, as sixteen bytes.
//
// **Little-endian throughout, which is what makes it look wrong beside everything else here.** The
// length is appended as a little-endian count of *bits* and the digest comes out least significant
// byte first, where the PostgreSQL protocol around it is big-endian everywhere. Getting that
// backwards produces a hash that is stable, plausible and wrong.
export md5(bytes)
    val msg = []

    for b in bytes
        push(msg, b)

    val bits = len(bytes) * 8

    push(msg, 128)

    while len(msg) % 64 != 56
        push(msg, 0)

    for i in 0..<8
        push(msg, (bits >> (8 * i)) & 255)

    var a0 = 1732584193
    var b0 = 4023233417
    var c0 = 2562383102
    var d0 = 271733878

    var at = 0

    while at < len(msg)
        val m = []

        for j in 0..<16
            val k = at + j * 4

            push(m, msg[k] | (msg[k + 1] << 8) | (msg[k + 2] << 16) | (msg[k + 3] << 24))

        var a = a0
        var b = b0
        var c = c0
        var d = d0

        for i in 0..<64
            var f = 0
            var g = 0

            if i < 16
                f = (b & c) | ((~b & Mask32) & d)
                g = i
            elif i < 32
                f = (d & b) | ((~d & Mask32) & c)
                g = (5 * i + 1) % 16
            elif i < 48
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else
                f = c ^ (b | (~d & Mask32))
                g = (7 * i) % 16

            f = (f + a + Md5K[i] + m[g]) & Mask32
            a = d
            d = c
            c = b
            b = (b + rotated(f, Md5S[i])) & Mask32

        a0 = (a0 + a) & Mask32
        b0 = (b0 + b) & Mask32
        c0 = (c0 + c) & Mask32
        d0 = (d0 + d) & Mask32
        at = at + 64

    val out = []

    for word in [a0, b0, c0, d0]
        for i in 0..<4
            push(out, (word >> (8 * i)) & 255)

    out

// What an `AuthenticationMD5Password` is answered with: `md5` and the hex of a hash of a hash.
//
// **The user name is part of the inner hash and the salt is only in the outer one.** That is what
// makes the stored value a per-user constant and the wire value different on every connection --
// and it means a stolen `pg_shadow` row still logs in, which is exactly why this method was
// replaced.
export md5Password(user, password, salt)
    val inner = hex(md5(toBytes(password + user)))
    val outer = []

    for b in toBytes(inner)
        push(outer, b)

    for b in salt
        push(outer, b)

    "md5" + hex(md5(outer))

// -- SCRAM-SHA-256 -----------------------------------------------------------------------------------

// A client-side SCRAM exchange, as three messages and a check.
//
// **The verifier at the end is not a formality.** The server proves it knew the stored key by
// signing the same message the client did, so a middleman that got the client's proof still cannot
// finish the exchange -- and a client that skipped the check would be authenticating itself to
// anything that answered.
// **The user name is a parameter and PostgreSQL is given an empty one.** RFC 5802 carries it in
// `n=`; PostgreSQL takes the user from the startup packet instead and ignores this field, which is
// what libpq sends too -- and putting it here as well would mean escaping `=` and `,` in it for no
// gain. It is an argument rather than a constant so that the exchange RFC 7677 publishes, which uses
// `n=user`, can be run through this code exactly as written.
export scram(user, password, nonce)
    val first = "n=" + user + ",r=" + nonce

    val s = { }

    s.first = () -> "n,," + first

    // The client's final message, given the server's first.
    //
    // **The nonce the server sends back must begin with the one that was sent**, and checking that
    // is what makes this exchange a challenge rather than a formality: a reflected nonce that does
    // not extend the client's own is somebody replaying an old exchange.
    s.final = (serverFirst) ->
        val fields = parsed(serverFirst)

        if !has(fields, "r") || !has(fields, "s") || !has(fields, "i")
            throw "the server's SCRAM message is missing a field: " + serverFirst

        val theirs = fields["r"]

        if !theirs.startsWith(nonce) then throw "the server's SCRAM nonce does not extend the one this client sent"

        val salt = unbase64(fields["s"])
        val iterations = number(fields["i"])

        if iterations == null || iterations < 1 then throw "the server asked for an iteration count that is not a number: " + fields["i"]

        val salted = pbkdf2("SHA-256", toBytes(password), salt, iterations, 32)
        val clientKey = hmac("SHA-256", salted, "Client Key")
        val storedKey = sha256(clientKey)

        // `c=biws` is base64 of `n,,` -- the same GS2 header sent in the first message, repeated so
        // that a middleman cannot have removed it to strip channel binding.
        val without = "c=biws,r=" + theirs
        val message = first + "," + serverFirst + "," + without
        val signature = hmac("SHA-256", storedKey, message)

        val proof = []

        for i in 0..<len(clientKey)
            push(proof, clientKey[i] ^ signature[i])

        val serverKey = hmac("SHA-256", salted, "Server Key")

        val expected = base64(hmac("SHA-256", serverKey, message))

        { message: without + ",p=" + base64(proof), verifier: expected }

    // Whether the server's final message carries the signature it should.
    s.verify = (serverFinal, expected) ->
        val fields = parsed(serverFinal)

        if has(fields, "e") then throw "the server refused this login: " + fields["e"]

        has(fields, "v") && fields["v"] == expected

    s

// A SCRAM message, which is comma-separated `key=value` with the value free to contain `=`.
//
// **Split on the FIRST `=` and not on every one**, since base64 padding puts `=` inside the value:
// `s=QSXCR+Q6sek8bf92==` is one field and splitting on all of them loses the salt.
parsed(text)
    val out = { }

    for part in text.split(",")
        val at = part.indexOf("=")

        if at != null && at > 0
            out[part[0..<at]] = part[(at + 1)..]

    out

// A fresh client nonce, as base64 of eighteen bytes from the kernel.
//
// **This is what the whole exchange rests on and it cannot be computed.** A nonce a program worked
// out from the clock or from a counter is one an attacker can work out too, and every proof after it
// is then replayable. `randomBytes` is the reason `slate:crypto` had to exist before this package
// could.
export freshNonce() = base64(randomBytes(18))
