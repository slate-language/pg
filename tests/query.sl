// The client itself, against a PostgreSQL server written in slate.
//
// **The fake server's replies are written out from the message formats**, so what passes here is
// this client agreeing with the protocol rather than with whatever database happens to be
// installed -- and the suite needs no server, no cluster and no password. `check/live.sl` runs the
// same ground against a real PostgreSQL 16 and is the other half of the bargain.

import { pg } from "../pg.sl"
import { sha256, hmac, pbkdf2 } from slate:crypto
import { send, close as closeSocket, localPort } from slate:net
import { message, sealed, putByte, putInt32, putBytes, putString, reading } from "../wire.sl"
import { server, authOk, authCleartext, authMd5, authSasl, authSaslContinue, authSaslFinal,
    describe, dataRow, commandComplete, emptyQuery, errorResponse, noticeResponse, notification,
    parseComplete, bindComplete, noData, readyFor, parameterStatus, joined } from "./fake.sl"
import { md5Password, base64, unbase64, hex } from "../auth.sl"

// **A test that hangs is worse than a test that fails**, since a socket keeps the program alive and
// `slate test` would wait for the rest of the run with nothing printed. Three seconds is far longer
// than a loopback exchange and far shorter than a person's patience.
val Guard = 3000

// A watchdog that ends the run rather than letting it hang, and says which test left it running.
//
// **It is a call rather than a `throw` written in the lambda** because a block lambda has to be the
// last argument and `setTimeout` takes the delay after it -- so the body is an expression, and the
// sentence lives in the function it calls.
late(what) = setTimeout(() -> ranLong(what), Guard)

ranLong(what)
    throw "the " + what + " did not finish in time"

// The connection every test here makes, against a fake answering `answer`.
async connected(answer)
    val fake = server(answer)
    val db = await pg({
        host: "127.0.0.1",
        port: localPort(fake),
        user: "ada",
        password: "pencil",
        database: "notes",
    })

    { fake: fake, r: db }

// A plain server: it accepts anybody and answers every simple query with one row.
plain(kind, r, sock)
    if kind == "startup" then return authOk()

    if kind == "Q"
        return joined([
            describe([{ name: "n", oid: 23 }]),
            dataRow(["1"]),
            commandComplete("SELECT 1"),
            readyFor("I"),
        ])

    null

@test
async A_CONNECTION_IS_MADE_AND_A_SIMPLE_QUERY_ANSWERS_ROWS()
    val guard = late("connection test")

    val made = await connected(plain)

    assert(made.r.ok)

    val db = made.r.value
    val said = await db.query("select 1 as n")

    assert(said.ok)
    assert(len(said.value.rows) == 1)
    assert(said.value.rows[0].n == 1)
    assert(said.value.command == "SELECT")
    assert(said.value.count == 1)

    db.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async THE_STARTUP_PACKET_CARRIES_THE_USER_THE_DATABASE_AND_THE_ENCODING()
    // **`client_encoding` is asked for rather than assumed**, since everything read here becomes
    // slate text and slate text is UTF-8 -- a connection in LATIN1 would hand over bytes that are
    // not what they claim to be.
    val guard = late("startup test")

    var seen = { }

    val made = await connected((kind, r, sock) ->
        if kind == "startup"
            assert(r.int32() == 196608)

            while r.left() > 1
                val name = r.string()

                seen[name] = r.string()

            return authOk()

        plain(kind, r, sock))

    assert(made.r.ok)
    assert(seen.user == "ada")
    assert(seen.database == "notes")
    assert(seen.client_encoding == "UTF8")
    assert(seen.application_name == "slate")

    made.r.value.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_CLEARTEXT_PASSWORD_IS_SENT_WHEN_THE_SERVER_ASKS_FOR_ONE()
    val guard = late("cleartext test")

    var sent = null

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authCleartext()

        if kind == "p"
            sent = r.string()

            return authOk()

        plain(kind, r, sock))

    assert(made.r.ok)
    assert(sent == "pencil")

    made.r.value.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async AN_MD5_CHALLENGE_IS_ANSWERED_WITH_THE_HASH_THE_SERVER_EXPECTS()
    // **The salt is the server's and changes every connection**, which is the whole of what MD5
    // authentication adds over sending the password -- and it is why the answer cannot be a
    // constant this test could have recorded.
    val guard = late("md5 test")

    val salt = [17, 34, 51, 68]
    var sent = null

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authMd5(salt)

        if kind == "p"
            sent = r.string()

            return authOk()

        plain(kind, r, sock))

    assert(made.r.ok)
    assert(sent == md5Password("ada", "pencil", salt))
    assert(sent.startsWith("md5"))

    made.r.value.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_SCRAM_LOGIN_IS_CHECKED_BY_A_SERVER_THAT_DOES_THE_OTHER_HALF()
    // **The fake does what a real server does**: it holds a salt and an iteration count, derives the
    // stored key, and checks the client's proof against the message both sides built. A client whose
    // proof is over the wrong message fails here exactly as it would against PostgreSQL.
    val guard = late("SCRAM test")

    val salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    val iterations = 4096
    val salted = pbkdf2("SHA-256", toBytes("pencil"), salt, iterations, 32)
    val storedKey = sha256(hmac("SHA-256", salted, "Client Key"))
    val serverKey = hmac("SHA-256", salted, "Server Key")

    var clientFirst = null
    var serverFirst = null
    var proved = false

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authSasl(["SCRAM-SHA-256"])

        if kind == "p"
            if clientFirst == null
                assert(r.string() == "SCRAM-SHA-256")

                val size = r.int32()
                val whole = fromBytes(r.bytes(size)).value

                // The GS2 header is stripped: what is signed is the message without it.
                clientFirst = whole[3..]

                val theirs = fieldOf(clientFirst, "r")

                serverFirst = "r=" + theirs + "nonce,s=" + base64(salt) + ",i=" + string(iterations)

                return authSaslContinue(serverFirst)

            val final = fromBytes(r.rest()).value
            val without = final[0..<final.indexOf(",p=")]
            val proof = unbase64(final[(final.indexOf(",p=") + 3)..])
            val auth = clientFirst + "," + serverFirst + "," + without
            val signature = hmac("SHA-256", storedKey, auth)
            val clientKey = []

            for i in 0..<len(proof)
                push(clientKey, proof[i] ^ signature[i])

            proved = hex(sha256(clientKey)) == hex(storedKey)

            assert(proved)

            return joined([
                authSaslFinal("v=" + base64(hmac("SHA-256", serverKey, auth))),
                authOk(),
            ])

        plain(kind, r, sock))

    assert(made.r.ok)
    assert(proved)

    made.r.value.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_SERVER_THAT_CANNOT_PROVE_ITSELF_ENDS_THE_CONNECTION()
    // **The client checks the server's signature too**, so a server that answers a plausible
    // `SASLFinal` it could not have computed is refused rather than trusted. Without this check a
    // program would authenticate itself to anything that answered.
    val guard = late("imposter test")

    var asked = false

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authSasl(["SCRAM-SHA-256"])

        if kind == "p"
            if !asked
                asked = true

                r.string()

                val size = r.int32()
                val whole = fromBytes(r.bytes(size)).value

                return authSaslContinue("r=" + fieldOf(whole[3..], "r") + "nonce,s=AQIDBA==,i=4096")

            return joined([
                authSaslFinal("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
                authOk(),
            ])

        plain(kind, r, sock))

    assert(!made.r.ok)
    assert(made.r.error.contains("did not prove it knew the password"))

    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_SERVER_OFFERING_NO_MECHANISM_THIS_CLIENT_SPEAKS_SAYS_SO()
    val guard = late("mechanism test")

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authSasl(["SCRAM-SHA-1-PLUS"])

        null)

    assert(!made.r.ok)
    assert(made.r.error.contains("SCRAM-SHA-256"))

    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_LOGIN_THE_SERVER_REFUSES_IS_AN_ANSWER_AND_NOT_A_FAULT()
    // A password that is wrong, a role that is not there, a `pg_hba.conf` that has no line for this
    // host: all of them are `ErrorResponse` before the connection is up, and all of them are things
    // a program handles rather than crashes on.
    val guard = late("refusal test")

    val made = await connected((kind, r, sock) ->
        if kind == "startup"
            return errorResponse([
                { kind: "S", text: "FATAL" },
                { kind: "C", text: "28P01" },
                { kind: "M", text: "password authentication failed for user \"ada\"" },
            ])

        null)

    assert(!made.r.ok)
    assert(made.r.error == "password authentication failed for user \"ada\"")

    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_QUERY_THE_SERVER_REFUSES_IS_AN_ANSWER_AND_THE_CONNECTION_SURVIVES()
    // **The error is not answered until `ReadyForQuery`.** The server skips to the next `Sync` after
    // an error, so a client that answered at the `ErrorResponse` would be one message ahead of the
    // server for the rest of the connection -- and the next query would be given this one's `Z`.
    val guard = late("query error test")

    var asked = 0

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authOk()

        if kind == "Q"
            asked = asked + 1

            if asked == 1
                return joined([
                    errorResponse([
                        { kind: "S", text: "ERROR" },
                        { kind: "C", text: "23505" },
                        { kind: "M", text: "duplicate key value violates unique constraint \"notes_title_key\"" },
                        { kind: "n", text: "notes_title_key" },
                    ]),
                    readyFor("I"),
                ])

            return joined([
                describe([{ name: "n", oid: 23 }]),
                dataRow(["1"]),
                commandComplete("SELECT 1"),
                readyFor("I"),
            ])

        null)

    val db = made.r.value
    val bad = await db.query("insert into notes (title) values ('first')")

    assert(!bad.ok)
    assert(bad.code == "23505")
    assert(bad.info.constraint == "notes_title_key")
    assert(bad.error.contains("duplicate key"))

    val good = await db.query("select 1 as n")

    assert(good.ok)
    assert(good.value.rows[0].n == 1)

    db.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_PARAMETER_MAKES_THIS_THE_EXTENDED_PROTOCOL_AND_null_TRAVELS_AS_MINUS_ONE()
    // **Parameters are what decide which protocol is spoken**, exactly as node's `pg` decides it: a
    // simple query cannot carry a parameter at all. What this test reads is the `Bind` the client
    // wrote, which is where a null that travelled as an empty string would show.
    val guard = late("extended test")

    var sql = null
    var params = []

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authOk()

        if kind == "P"
            r.string()

            sql = r.string()

            return null

        if kind == "B"
            r.string()
            r.string()
            r.int16()

            val n = r.int16()

            for i in 0..<n
                val size = r.int32()

                push(params, if size < 0 then null else fromBytes(r.bytes(size)).value)

            return null

        if kind == "S"
            return joined([
                parseComplete(),
                bindComplete(),
                describe([{ name: "t", oid: 25 }]),
                dataRow([null]),
                commandComplete("SELECT 1"),
                readyFor("I"),
            ])

        null)

    val db = made.r.value
    val said = await db.query("select $1::text as t, $2::text as u, $3::int as n", [null, "", 7])

    assert(sql == "select $1::text as t, $2::text as u, $3::int as n")
    assert(len(params) == 3)
    assert(params[0] == null)
    assert(params[1] == "")
    assert(params[2] == "7")

    // And a column with no value comes back as `null` rather than as the empty string.
    assert(said.value.rows[0].t == null)

    db.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_ROW_SPLIT_ACROSS_ARRIVALS_IS_STILL_ONE_ROW()
    // **A TCP read boundary is not a message boundary**, and the failure it causes only shows up on
    // a row wider than a packet. Here the server writes the reply in two pieces, one of them ending
    // in the middle of a `DataRow`.
    val guard = late("split test")

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authOk()

        if kind == "Q"
            val whole = joined([
                describe([{ name: "title", oid: 25 }]),
                dataRow(["a title long enough to be worth splitting"]),
                commandComplete("SELECT 1"),
                readyFor("I"),
            ])

            // Everything but the last nineteen bytes now, the rest on the next turn.
            send(sock, whole[0..<(len(whole) - 19)])

            return whole[(len(whole) - 19)..]

        null)

    val db = made.r.value
    val said = await db.query("select title from notes")

    assert(said.ok)
    assert(said.value.rows[0].title == "a title long enough to be worth splitting")

    db.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async SEVERAL_STATEMENTS_IN_ONE_SIMPLE_QUERY_ARE_ALL_KEPT()
    // A simple query may hold several statements, each with its own rows and its own tag. The last
    // is what the query answers and `results` carries every one -- which is what a migration or a
    // script pasted into `query` needs.
    val guard = late("multi-statement test")

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authOk()

        if kind == "Q"
            return joined([
                describe([{ name: "n", oid: 23 }]),
                dataRow(["1"]),
                commandComplete("SELECT 1"),
                describe([{ name: "n", oid: 23 }]),
                dataRow(["2"]),
                dataRow(["3"]),
                commandComplete("SELECT 2"),
                readyFor("I"),
            ])

        null)

    val db = made.r.value
    val said = await db.query("select 1 as n; select 2 as n union select 3")

    assert(len(said.value.results) == 2)
    assert(said.value.results[0].rows[0].n == 1)
    assert(len(said.value.rows) == 2)
    assert(said.value.count == 2)

    db.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async AN_EMPTY_QUERY_IS_AN_ANSWER_WITH_NO_ROWS_AND_NO_COMMAND()
    val guard = late("empty query test")

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authOk()

        if kind == "Q" then return joined([emptyQuery(), readyFor("I")])

        null)

    val db = made.r.value
    val said = await db.query("")

    assert(said.ok)
    assert(said.value.command == null)
    assert(len(said.value.rows) == 0)

    db.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_NOTICE_IS_NOT_AN_ANSWER_TO_ANYTHING_AND_A_NOTIFICATION_IS_NOT_A_ROW()
    // **Both arrive BETWEEN replies**, so a client that matched every message to the query in flight
    // would hand a `raise notice` back as a row -- silently, both being well formed.
    val guard = late("notice test")

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authOk()

        if kind == "Q"
            return joined([
                noticeResponse([
                    { kind: "S", text: "NOTICE" },
                    { kind: "M", text: "a notice" },
                ]),
                notification(42, "jobs", "ready"),
                describe([{ name: "n", oid: 23 }]),
                dataRow(["1"]),
                commandComplete("SELECT 1"),
                readyFor("I"),
            ])

        null)

    val db = made.r.value

    var notice = null
    var event = null

    db.onNotice((n) ->
        notice = n)

    db.onNotify((n) ->
        event = n)

    val said = await db.query("select 1 as n")

    assert(notice.message == "a notice")
    assert(notice.severity == "NOTICE")
    assert(event.channel == "jobs")
    assert(event.payload == "ready")
    assert(event.pid == 42)

    // And the query got its own row and nothing else.
    assert(len(said.value.rows) == 1)

    db.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async THE_TRANSACTION_STATUS_IS_WHAT_THE_SERVER_SAID_LAST()
    val guard = late("status test")

    var asked = 0

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authOk()

        if kind == "Q"
            asked = asked + 1

            return joined([commandComplete("BEGIN"), readyFor(if asked == 1 then "T" else "I")])

        null)

    val db = made.r.value

    assert(db.status() == "I")

    await db.query("begin")

    assert(db.status() == "T")

    await db.query("rollback")

    assert(db.status() == "I")

    db.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_SERVER_PARAMETER_IS_KEPT_AND_A_LATER_ONE_REPLACES_IT()
    val guard = late("parameter test")

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return joined([authOk(), parameterStatus("TimeZone", "UTC")])

        if kind == "Q"
            return joined([
                parameterStatus("TimeZone", "Europe/Paris"),
                commandComplete("SET"),
                readyFor("I"),
            ])

        null)

    val db = made.r.value

    assert(db.parameters().server_version == "16.0")
    assert(db.parameters().TimeZone == "UTC")

    await db.query("set time zone 'Europe/Paris'")

    assert(db.parameters().TimeZone == "Europe/Paris")

    db.close()
    closeSocket(made.fake)
    clearTimeout(guard)

@test
async CLOSING_ANSWERS_EVERY_QUERY_STILL_WAITING()
    // **A waiting query is SETTLED rather than left**, and with a result rather than a failure -- a
    // program awaiting an answer that will never come would otherwise wait for the rest of the run,
    // which in a server is a request that never finishes.
    val guard = late("close test")

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authOk()

        // Every query is accepted and none is answered.
        null)

    val db = made.r.value
    val one = db.query("select 1")
    val two = db.query("select 2")

    db.close()

    assert(!(await one).ok)
    assert(!(await two).ok)
    assert((await one).error.contains("closed"))

    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_SERVER_THAT_GOES_AWAY_ANSWERS_EVERY_QUERY_STILL_WAITING()
    val guard = late("disconnect test")

    val made = await connected((kind, r, sock) ->
        if kind == "startup" then return authOk()

        if kind == "Q"
            closeSocket(sock)

            return null

        null)

    val db = made.r.value
    val said = await db.query("select 1")

    assert(!said.ok)
    assert(said.error.contains("connection"))

    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_QUERY_ON_A_CLOSED_CONNECTION_IS_THE_PROGRAMS_OWN_MISTAKE()
    // **Two channels, and which one a failure uses says what kind of failure it is.** A database
    // that refuses a query is an answer; querying something a program itself closed is a defect in
    // the program.
    val guard = late("closed test")

    val made = await connected(plain)
    val db = made.r.value

    db.close()

    var said = ""

    try
        await db.query("select 1")
    catch e
        said = string(e)

    assert(said.contains("closed"))

    closeSocket(made.fake)
    clearTimeout(guard)

@test
async A_CONNECTION_TO_NOTHING_IS_AN_ANSWER()
    // Port 1 is not something a database listens on. **A refused connection is the ordinary thing a
    // program handles**, which is why it comes back rather than stopping the run.
    val guard = late("refused test")

    val said = await pg({ host: "127.0.0.1", port: 1, user: "ada", password: "x", database: "notes" })

    assert(!said.ok)

    clearTimeout(guard)

// One field out of a SCRAM message, for the fake server to read the client's nonce.
fieldOf(text, name)
    for part in text.split(",")
        if part.startsWith(name + "=") then return part[(len(name) + 1)..]

    null
