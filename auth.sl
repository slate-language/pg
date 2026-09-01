// Logging in: the three ways a PostgreSQL server will ask, and the text encodings the answers need.
//
// **SCRAM-SHA-256 is the one that matters**, being what PostgreSQL 14 and later configure by default
// and what `initdb` writes into `pg_hba.conf` without being asked. A client that speaks only the
// older methods cannot log in to a current server at all.
//
// **The cryptography is `slate:crypto`'s and the layout is here**, which is the seam this package is
// written on: SHA-256, HMAC, PBKDF2, MD5 and the nonce come from the language, and hex, base64 and
// the message forms of RFC 5802 are ordinary slate. `slate:jwt` writes its own base64url for the
// same reason.
//
// **MD5 WAS WRITTEN OUT HERE UNTIL slate 0.0.6, AND THE ARGUMENT FOR THAT DID NOT SURVIVE THE
// LANGUAGE GROWING ONE.** The case made here was that `slate:crypto` should not grow an MD5 --
// nothing new should use it, and what it is wanted for is a legacy server's challenge costing two
// hashes of forty bytes per connection. That was an argument about what the cost of *writing* one
// was worth, and `sysl.crypto` grew MD5 in 0.0.98 for this very login, so slate exposes it on the
// terms `sha1` was already exposed under and a hundred and twenty lines of rounds went with it.

import { sha256, hmac, pbkdf2, randomBytes, md5 } from slate:crypto

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
