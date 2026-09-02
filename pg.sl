// A PostgreSQL client, written in slate over `slate:net` and `slate:crypto`.
//
//     import { pg } from pg
//
//     val db = (await pg("postgres://ada@127.0.0.1/notes")).value
//     val r = await db.query("select id, title from notes where author = $1", "ada")
//
//     for row in r.value.rows
//         print(row.id, row.title)
//
//     db.close()
//
// ## The client is on the loop, and that is the point
//
// **A database call in a server must not stop the server.** Everything here is a promise on the same
// event loop that is answering HTTP, so a handler that queries PostgreSQL keeps every other request
// moving. That is the same reason `slate:redis` binds a parser and not a connection, and it is why
// this is written in slate rather than bound to libpq: libpq's `PQexec` blocks, and a blocking call
// on this loop stops the whole program.
//
// ## One export, because a connection is one object
//
// `pg(options)` answers a result carrying the connection, and everything else is a method on it --
// `query`, `close`, `onNotice`, `onNotify`, `status`, `parameters`. That is the shape `slate:redis`
// and `slate:regex` have, and for the reason they have it: a program that wants a database wants one
// noun rather than a vocabulary.
//
// ## Two channels, as everywhere else in slate
//
// **A query answers a result**, because a constraint violation, a syntax error and a table that is
// not there are all ordinary things for a program to handle -- a server wants to answer `409` rather
// than fall over. **Calling `query` on a connection that is closed throws**, because that is the
// program's own mistake and not the database's answer.
//
// ## What is not here
//
// **No COPY and no cursors.** A `COPY` sent through `query` is refused with a sentence rather than
// left to desynchronise the connection.
//
// **No connection pool.** A pool is a program's own arrangement over several connections and needs
// nothing from the protocol; what it needs from a driver is that a connection is one object with a
// `close`, which is what this is.
//
// ## TLS, which PostgreSQL negotiates rather than assumes
//
// **A connection begins in the clear and asks.** Eight bytes go out -- a length and a magic number
// where a protocol version would be -- and the server answers a single byte: `S` to say it will
// speak TLS, `N` to say it will not. Only then does the handshake start, and the startup packet goes
// after it. That is why this needs `startTls` rather than a secure `connect`: there is nothing to
// secure until the server has agreed, and by then the socket is open and has been written to.
//
// `sslmode` is libpq's and is spelled the same way, in an option or in the URL a provider hands out:
//
//     pg({ host: "db.example.com", sslmode: "require", trust: authority })
//     pg("postgres://user:secret@db.example.com/app?sslmode=require")
//
// **`prefer` is the default**, which is libpq's default and not 0.1.0's behaviour -- every connection
// now asks, and a server that says no is spoken to in the clear exactly as before.
//
// **`require` verifies fully, which libpq's `require` does not.** libpq encrypts without checking who
// it is talking to unless told `verify-full`, on the argument that a man in the middle is somebody
// else's problem; slate's TLS offers no way to skip verification, so `require`, `verify-ca` and
// `verify-full` are one behaviour here. A private authority is named with `trust`, as PEM text, which
// is *added* to the machine's own store rather than put in place of it.
//
// **A handshake that fails is not retried in the clear.** libpq drops to an unencrypted connection
// under `prefer` when TLS fails after the server said `S`; a certificate that does not check out is
// a reason to stop rather than a reason to continue quietly.

import { connect, onBytes, onError, send, startTls, close as closeSocket } from slate:net
import { env } from slate:process
import { message, sealed, putByte, putInt16, putInt32, putBytes, putString, reading, stream,
    byteOf } from "./wire.sl"
import { decoded, encoded, affected, bytea as asBytea } from "./values.sl"
import { scram, freshNonce, md5Password } from "./auth.sl"

// The protocol version this speaks: 3.0, as `196608`, which is what every server since 7.4 answers.
val Version = 196608

// The number that asks for TLS, sent where a version goes. `1234 << 16 | 5679`, which is how the
// protocol writes every request that is not a connection -- cancellation is the one beside it.
val SslRequest = 80877103

// `pg(options)` -- a connection, or the reason there is not one.
//
// **The options may be a URL**, since that is how a deployment carries them: `DATABASE_URL` is one
// environment variable and six settings, and a driver that made a program take it apart would be
// making every program write the same twenty lines.
export pg(options) = opened(settings(options))

// Bytes for a `bytea` parameter. An array of small numbers is an array of numbers to everybody who
// reads it, so this is how a program says it meant bytes.
export bytea(bs) = asBytea(bs)

// -- what a query answers ----------------------------------------------------------------------------

// One statement's result. **`command` and `count` are `null` for a statement that reports neither** --
// an empty query, or a `BEGIN` -- rather than absent, because a field that is there only sometimes is
// one every caller has to test for before reading.
//
// `results` is on the answer's own value and holds one of these per statement, a simple query being
// allowed to carry several. It is not here, or the type would describe itself.
export type Result = { command: any, count: any, rows: array, values: array, fields: array }

// What `db.query` answers: the last statement's result under `value`, or why there is not one.
//
// **Only the fields that apply are ever there**, which is why every one of them is optional --
// reading `r.value` off a refusal is `undefined`, and slate refuses to carry that anywhere. `code` is
// the SQLSTATE and `info` is the whole `ErrorResponse` with its fields named.
export type Answer = { ok: boolean, value?: object, error?: string, code?: any, info?: object }

// **The exact decimal is `pg/decimal`, a module of its own rather than a name re-exported here.**
// `Decimal` is a class, so it is a value AND a type under one name, and slate can re-export the
// value half of that and not the type half -- a program that could make one could not then say
// `d: Decimal`. A subpath module is the mechanism a package has for a second door, and one door
// with both halves behind it beats two doors with one each:
//
//     import { pg } from pg
//     import { decimal, Decimal } from pg/decimal

async opened(cfg)
    val made = await connect(cfg.host, cfg.port)

    if !made.ok then return made

    val sock = made.value
    val messages = stream()

    // The queries that have gone out and not been answered, oldest first.
    //
    // **This is the whole of how an answer is matched to its query.** The protocol has no request
    // ids and needs none: a `Sync` ends every exchange with a `ReadyForQuery`, and answers come back
    // in the order the queries were written. That is also what makes pipelining free.
    var waiting = []

    // The exchange being read now: the rows so far, what the columns are, and what went wrong.
    var current = null

    var startup = pending()
    var settled = false
    var shut = false
    var notices = null
    var notifications = null

    // What the server said about itself -- `server_version`, `client_encoding`, `TimeZone` and the
    // rest. It arrives before the first query and may change under the program's feet, since a `set`
    // makes the server send it again.
    val parameters = { }

    // `I` idle, `T` inside a transaction, `E` inside one that has failed. Read from every
    // `ReadyForQuery`, which is the only place the server says.
    var transaction = "I"

    // The exchange this connection is in the middle of: SCRAM has three messages and has to remember
    // what it sent between them.
    var sasl = null
    var verifier = null

    // -- ending ------------------------------------------------------------------------------------

    // Answer everything outstanding and let the connection go.
    //
    // **Every waiting query is SETTLED rather than left**, and with a result rather than a failure. A
    // connection that has gone is an outside condition like any other, and a program awaiting a
    // query would otherwise wait for the rest of the run -- which in a server is a request that
    // never finishes.
    stop(why)
        if shut then return

        shut = true

        if !settled
            settled = true

            settle(startup, { ok: false, error: why })

        if current != null
            settle(current.promise, { ok: false, error: why })

            current = null

        for q in waiting
            settle(q.promise, { ok: false, error: why })

        waiting = []

        closeSocket(sock)

    // -- reading -----------------------------------------------------------------------------------

    heard(chunk)
        if chunk == null
            stop("the database closed this connection")

            return

        messages.feed(chunk)

        while true
            val m = messages.take()

            if m == null then return

            // **A failure in a handler must not be swallowed and must not leave the stream half
            // read.** Anything thrown here ends the connection, because after a message this client
            // could not make sense of, the two ends no longer agree about where the next one begins.
            try
                took(m)
            catch e
                stop(string(e))

                return

    took(m)
        val r = reading(m.body)

        // A notice is not an answer to anything: `raise notice`, a deprecation, a message about the
        // server shutting down. It arrives between replies and is never matched to a query.
        if m.tag == "N"
            if notices != null then notices(fields(r))

            return

        // `listen` and `notify`. The message is delivered whether or not anybody asked to see it,
        // and dropped where nobody did -- what must not happen is that it is taken for a row.
        if m.tag == "A"
            val fromPid = r.int32()
            val channel = r.string()
            val payload = r.string()

            if notifications != null then notifications({ channel: channel, payload: payload, pid: fromPid })

            return

        if m.tag == "S"
            val name = r.string()

            parameters[name] = r.string()

            return

        // The key a cancellation request would carry. Nothing sends one yet, and reading it keeps
        // the stream aligned.
        if m.tag == "K" then return

        if m.tag == "E"
            failed(fields(r))

            return

        if m.tag == "R"
            authenticate(r)

            return

        if m.tag == "Z"
            transaction = fromBytes(r.bytes(1)).value

            ready()

            return

        // Everything below here belongs to a query in flight. A message arriving with none is a
        // client and a server that disagree about where they are, which is not something to step
        // over.
        if current == null then return

        if m.tag == "T"
            current.fields = described(r)
        elif m.tag == "D"
            row(r)
        elif m.tag == "C"
            complete(r.string())
        elif m.tag == "I"
            complete("")
        elif m.tag == "G" || m.tag == "H" || m.tag == "W"
            // **A `COPY` is refused rather than half-spoken.** `CopyFail` is what unwedges the
            // server after a `CopyInResponse`; the others end on their own once the command does.
            if m.tag == "G"
                val no = message("f")

                putString(no, "COPY is not supported by this client")
                write(sealed(no, "f"))

            current.error = { message: "COPY is not supported by this client -- use `psql` or a server-side `COPY ... FROM PROGRAM`" }

    // `ParseComplete`, `BindComplete`, `NoData`, `ParameterDescription`, `PortalSuspended` and
    // `CloseComplete` all say that a step went as asked. Nothing here needs to know.

    // A `RowDescription`: what the columns are called and what type each one is.
    described(r)
        val n = r.int16()
        val out = []

        for i in 0..<n
            val name = r.string()

            // The table and column this came from, then the type, its size and its modifier, then
            // the format. **Read rather than skipped**, because the cursor is what keeps the next
            // field aligned.
            r.int32()
            r.int16()

            val oid = r.int32()

            r.int16()
            r.int32()
            r.int16()

            push(out, { name: name, oid: oid })

        out

    // A `DataRow`: one value per column, each with its own length, and -1 where there is none.
    row(r)
        val n = r.int16()
        val out = { }
        val list = []

        for i in 0..<n
            val size = r.int32()

            // **-1 is absence and 0 is an empty string, and they are different values.** A driver
            // that collapsed them would turn a name nobody filled in into a name that is blank.
            val text = if size < 0 then null else fromBytes(r.bytes(size))
            val raw = if size < 0 then null else (if text.ok then text.value else null)

            val field = if i < len(current.fields) then current.fields[i] else { name: "column" + string(i + 1), oid: 0 }
            val v = decoded(field.oid, raw, cfg.decimals)

            // **A repeated column name keeps the last one**, which is what a program reading
            // `select a.id, b.id` sees in every other driver. `values` is beside it for the query
            // where that is not good enough.
            out[field.name] = v

            push(list, v)

        push(current.rows, out)
        push(current.values, list)

    // A `CommandComplete`: this statement is done, and its tag says what it did.
    //
    // **A simple query may hold several statements**, so each one's rows are put away and the next
    // begins with none. The last is what `query` answers, and `results` carries all of them.
    complete(tag)
        val one = {
            command: if tag == "" then null else tag.split(" ")[0],
            count: affected(tag),
            rows: current.rows,
            values: current.values,
            fields: current.fields,
        }

        push(current.results, one)

        current.rows = []
        current.values = []
        current.fields = []

    // An `ErrorResponse`. **The query is not answered here**, because the server has more to say --
    // it skips to the next `Sync` and sends `ReadyForQuery`, and answering early would leave this
    // client one message ahead of the server for the rest of the connection.
    failed(info)
        if current != null
            current.error = info

            return

        if !settled
            settled = true
            shut = true

            settle(startup, { ok: false, error: said(info) })

            closeSocket(sock)

            return

        stop(said(info))

    // A `ReadyForQuery`: the exchange is over, whatever became of it.
    ready()
        if !settled
            settled = true

            settle(startup, { ok: true, value: client })

            next()

            return

        if current == null
            next()

            return

        val done = current

        current = null

        if done.error != null
            settle(done.promise, {
                ok: false,
                error: said(done.error),
                code: done.error.code ?? null,
                info: done.error,
            })
        else
            val last = if len(done.results) == 0 then empty() else done.results[len(done.results) - 1]

            settle(done.promise, { ok: true, value: last with { results: done.results } })

        next()

    empty() -> Result = { command: null, count: null, rows: [], values: [], fields: [] }

    // -- logging in --------------------------------------------------------------------------------

    // An `Authentication...` message, which is five different messages sharing one tag.
    authenticate(r)
        val kind = r.int32()

        // 0 is `AuthenticationOk`. Everything else is a demand for something.
        if kind == 0 then return

        if kind == 3
            // Cleartext. **The password crosses the socket as itself**, which is why this is only
            // ever configured over a trusted network -- and this client has no TLS, so if a server
            // asks for it, it means it.
            val m = message("p")

            putString(m, cfg.password)
            write(sealed(m, "p"))

            return

        if kind == 5
            val salt = r.bytes(4)
            val m = message("p")

            putString(m, md5Password(cfg.user, cfg.password, salt))
            write(sealed(m, "p"))

            return

        if kind == 10
            // SASL: the server lists the mechanisms it will accept.
            //
            // **`SCRAM-SHA-256-PLUS` is deliberately not taken even where it is offered.** It binds
            // the exchange to the TLS channel, and there is no TLS here to bind it to.
            var found = false

            while true
                val name = r.string()

                if name == "" then break

                if name == "SCRAM-SHA-256" then found = true

            if !found then throw "this server offers no SASL mechanism this client speaks -- SCRAM-SHA-256 is the one it has"

            sasl = scram("", cfg.password, freshNonce())

            val first = sasl.first()
            val m = message("p")

            putString(m, "SCRAM-SHA-256")
            putInt32(m, len(toBytes(first)))
            putBytes(m, toBytes(first))
            write(sealed(m, "p"))

            return

        if kind == 11
            val final = sasl.final(text(r.rest()))

            verifier = final.verifier

            val m = message("p")

            putBytes(m, toBytes(final.message))
            write(sealed(m, "p"))

            return

        if kind == 12
            // **The server proves itself too, and this client checks.** A middleman that captured a
            // proof still cannot produce this signature, and a client that skipped the check would
            // be authenticating itself to whatever answered.
            if !sasl.verify(text(r.rest()), verifier) then throw "this server did not prove it knew the password, so it is not the server it says it is"

            return

        throw "this server asked for an authentication method this client does not speak (" + string(kind) + ")"

    // -- writing -----------------------------------------------------------------------------------

    write(bytes)
        // **A write that fails ends the connection.** There is no answer coming for anything already
        // in flight, and a client that carried on would wait for one.
        try
            send(sock, bytes)
        catch e
            stop("the connection to the database was lost while writing")

    // The next query in the queue, written now that the last exchange is over.
    next()
        if shut || current != null || len(waiting) == 0 then return

        current = waiting[0]

        removeAt(waiting, 0)

        write(current.bytes)

    // `db.query(sql)` and `db.query(sql, a, b, ...)`.
    //
    // **Parameters are what decides which protocol is spoken**, exactly as node's `pg` decides it: a
    // query with none is a simple `Query`, and one with any is `Parse`/`Bind`/`Execute`. That is not
    // an optimisation -- a simple query cannot carry parameters at all, and the extended one cannot
    // carry more than one statement.
    //
    // **A parameter is never interpolated into the SQL**, which is the whole of why they exist: the
    // server parses the statement before it is given a single value, so nothing a parameter contains
    // can become part of the query.
    //
    // **`params` arrives as an array whatever the caller wrote**, `query` gathering its arguments --
    // so there is no longer a `null` here to tell from an empty list, and the two meant the same
    // thing anyway.
    async ask(sql: string, params: array)
        if shut then throw "this database connection is closed"

        val q = {
            promise: pending(),
            bytes: if len(params) == 0 then simple(sql) else extended(sql, params),
            rows: [],
            values: [],
            fields: [],
            results: [],
            error: null,
        }

        push(waiting, q)
        next()

        await q.promise

    simple(sql)
        val m = message("Q")

        putString(m, sql)
        sealed(m, "Q")

    // `Parse`, `Bind`, `Describe`, `Execute`, `Sync` -- written as one array of bytes and sent once.
    //
    // **The unnamed statement and the unnamed portal are used and then left**, which is what makes
    // this a plain query rather than a prepared one: the next `Parse` replaces them. A named
    // statement would be faster for something run in a loop and is a decision a program should make,
    // not a driver.
    extended(sql, params)
        val out = []

        val parse = message("P")

        putString(parse, "")
        putString(parse, sql)

        // **No parameter types, which means the server infers them.** Saying `0` types is not the
        // same as saying nothing: it tells the server to work each one out from where it is used,
        // which is what makes `where id = $1` read the text as a number.
        putInt16(parse, 0)
        putBytes(out, sealed(parse, "P"))

        val bind = message("B")

        putString(bind, "")
        putString(bind, "")

        // One format code for every parameter, and text for all of them.
        putInt16(bind, 0)
        putInt16(bind, len(params))

        for p in params
            val text = encoded(p)

            if text == null
                // **-1, which is not a length of zero.** A parameter that is null and one that is an
                // empty string are two different values and the database treats them as such.
                putInt32(bind, -1)
            else
                val bs = toBytes(text)

                putInt32(bind, len(bs))
                putBytes(bind, bs)

        // Text for every column that comes back, as above.
        putInt16(bind, 0)
        putBytes(out, sealed(bind, "B"))

        val describe = message("D")

        putByte(describe, byteOf("P"))
        putString(describe, "")
        putBytes(out, sealed(describe, "D"))

        val execute = message("E")

        putString(execute, "")

        // No limit on the rows returned. A limit is what a cursor is for, and a portal left suspended
        // is state this connection would have to remember.
        putInt32(execute, 0)
        putBytes(out, sealed(execute, "E"))

        val sync = message("S")

        putBytes(out, sealed(sync, "S"))
        out

    // -- starting ------------------------------------------------------------------------------------

    // -- TLS, asked for before anything else ---------------------------------------------------------

    // **Eight bytes out and one byte back, and both are in the clear.** This is the whole of
    // PostgreSQL's negotiation: there is no ALPN and no port that means TLS, so a client that assumed
    // either would be talking to a server that is still waiting to be asked.
    if cfg.sslmode != "disable"
        val told = pending()
        var answered = false

        val ask = message(null)

        putInt32(ask, SslRequest)
        write(sealed(ask, null))

        // **A reader of its own for one byte, replaced by the framed one below.** Nothing else can
        // arrive in between -- the server writes the byte and waits -- and replacing a socket's
        // reader is what `onBytes` is for.
        onBytes(sock, (chunk) ->
            if answered then return

            answered = true

            settle(told, if chunk == null || len(chunk) == 0 then -1 else chunk[0]))

        val said = await told

        if said == byteOf("S")
            // **The host is what the certificate is checked against**, which is why `pg` takes a name
            // and hands the same name here. A program that resolved it first would have nothing left
            // to verify.
            val up = await startTls(sock, { host: cfg.host, trust: cfg.trust })

            if !up.ok
                closeSocket(sock)

                return { ok: false, error: "the database's certificate was not accepted: " + up.error }
        elif said == byteOf("E")
            // A server old enough not to know the request answers an `ErrorResponse` to it.
            closeSocket(sock)

            return { ok: false, error: "this server is too old to be asked about TLS" }
        elif cfg.sslmode == "require"
            closeSocket(sock)

            val why = if said == -1 then "closed the connection rather than answering" else "will not speak TLS"

            return { ok: false, error: "`sslmode` is `require` and this server " + why }

    onBytes(sock, heard)

    // **A socket error ends the connection with a sentence rather than the `null` a clean close
    // gives.** Without this a reset in the middle of a query is indistinguishable from a server that
    // finished, and the program is told the connection closed when it was actually broken.
    onError(sock, (why) -> stop("the connection to the database failed: " + why))

    // The startup packet, which is the one message with no tag: a version, then the settings this
    // connection wants, then a zero byte.
    val hello = message(null)

    putInt32(hello, Version)
    putString(hello, "user")
    putString(hello, cfg.user)
    putString(hello, "database")
    putString(hello, cfg.database)
    putString(hello, "application_name")
    putString(hello, cfg.application)

    // **`client_encoding` is asked for rather than assumed.** Everything this client reads is turned
    // into slate text, and slate text is UTF-8, so a connection in LATIN1 would hand over bytes that
    // are not what they claim to be.
    putString(hello, "client_encoding")
    putString(hello, "UTF8")
    putByte(hello, 0)
    write(sealed(hello, null))

    val client = { }

    // **Stored on the object rather than reached through a proto**, so calling one passes it what it
    // was given and nothing else -- `db.query(sql)` is `ask(sql, [])` and no receiver.
    //
    // **The parameters are GATHERED**, which is what makes the common query read as one thing:
    // `db.query("select * from notes where author = $1", "ada")`. A list a program worked out is
    // spread back, `db.query(sql, ...values)`, and that is the case the old list-taking form served
    // directly.
    client.query = (sql, ...params) -> ask(sql, params)
    client.close = () -> bye()
    client.onNotice = (f) ->
        notices = f

    client.onNotify = (f) ->
        notifications = f

    client.status = () -> transaction
    client.parameters = () -> parameters

    // `db.close()` -- and every query still waiting is answered.
    //
    // **`Terminate` is sent before the socket goes.** A server told nothing sees a reset and logs it
    // as a client that crashed, which is a line in somebody's log for every clean exit.
    bye()
        if !shut
            val m = message("X")

            write(sealed(m, "X"))

        stop("this database connection was closed")

    await startup

// -- settings ----------------------------------------------------------------------------------------

// What a connection needs, out of an object, a URL, or the environment.
//
// **The environment is read last and is not a fallback for a value that was given.** `PGHOST` and
// its siblings are what libpq reads and what every tool in the ecosystem sets, so a program that
// takes none of them still works where `psql` does.
settings(options) -> object
    val given = if options == null then { } else (if options is string then fromUrl(options) else options)

    val {
        host = given.host ?? (env("PGHOST") ?? "127.0.0.1"),
        port = given.port ?? (asPort(env("PGPORT")) ?? 5432),
        user = given.user ?? (env("PGUSER") ?? (env("USER") ?? "postgres")),
        password = given.password ?? (env("PGPASSWORD") ?? ""),
        application = given.application ?? "slate",
    } = given

    {
        host: host,
        port: port,
        user: user,
        password: password,

        // **The database defaults to the user's name**, which is libpq's rule and the reason
        // `psql` on its own connects to something.
        database: given.database ?? (env("PGDATABASE") ?? user),
        application: application,

        // **`PGSSLMODE` is read for the same reason `PGHOST` is**: it is what every tool in the
        // ecosystem sets, and a program that takes none of them still works where `psql` does.
        sslmode: sslModeOf(given.sslmode ?? (env("PGSSLMODE") ?? "prefer")),

        // A certificate authority this machine does not already have, **as PEM text and never as a
        // path**. libpq's `sslrootcert` names a file, and slate's TLS takes the bytes -- so where the
        // PEM came from is the program's business, which is one `readFileSync` and no guessing about
        // whose filesystem is being described. Not read from the environment for that reason.
        trust: given.trust ?? "",

        // **Whether a `numeric` column comes back as a `Decimal` rather than as its text.** Off by
        // default because it changes the type of a column -- `values.sl`'s `Numeric` arm says what
        // that costs and what it buys. Not read from the environment: it decides what a program's
        // own code is holding, which is not something a deployment gets to change underneath it.
        decimals: given.decimals ?? false,
    }

// The `sslmode` a program asked for, as one of the three behaviours there are.
//
// **libpq spells six and this has three, and the three that collapse do so because slate's TLS has
// no way to encrypt without verifying.** `verify-ca` and `verify-full` are therefore what `require`
// already does. `allow` is folded into `prefer` rather than implemented: libpq's `allow` connects in
// the clear FIRST and reconnects with TLS only if refused, which is a second connection and an
// ordering nobody asks for on purpose -- it is what a URL carries when somebody meant "either".
//
// **An unknown value is refused rather than treated as the default.** `sslmode=requrie` that quietly
// meant `prefer` is a connection a deployment believes is encrypted and is not.
sslModeOf(name: string) -> string
    if name == "disable" || name == "prefer" || name == "require" then return name
    if name == "allow" then return "prefer"
    if name == "verify-ca" || name == "verify-full" then return "require"

    throw "`sslmode` is one of `disable`, `allow`, `prefer`, `require`, `verify-ca` or `verify-full`, and this is " + name

// The parameters a connection URL carries after `?`.
//
// **Only `sslmode` is looked for.** A parameter this driver does not know is a parameter for
// something else -- `psql` reads a dozen that mean nothing here -- and refusing one would turn a URL
// that works everywhere into a URL that works everywhere but slate.
readQuery(out: object, text: string)
    for pair in split(text, "&")
        val eq = pair.indexOf("=")

        if eq != null && unescaped(pair[0..<eq]) == "sslmode"
            out.sslmode = unescaped(pair[(eq + 1)..])

asPort(text) -> integer | null
    if text == null then return null

    val n = number(text)

    if n == null then null else integer(n)

// `postgres://user:password@host:port/database`, which is how a deployment carries all six.
//
// **`postgresql://` and `postgres://` are both spelled in the wild** and neither is more correct, so
// both are read. Anything else is refused rather than guessed at: a URL that is not a database URL
// is a configuration mistake, and connecting to whatever it happened to name would be worse.
fromUrl(text: string) -> object
    var rest = text

    if rest.startsWith("postgres://")
        rest = rest[11..]
    elif rest.startsWith("postgresql://")
        rest = rest[13..]
    else
        throw "a database URL begins `postgres://` or `postgresql://`, and this one is " + text

    val out = { }

    val slash = rest.indexOf("/")

    if slash != null
        val name = rest[(slash + 1)..]
        val q = name.indexOf("?")

        // **`sslmode` is read and everything else is ignored, not refused.** A hosting provider's
        // connection string carries `application_name`, `connect_timeout`, `options` and more, and
        // stopping over one would make this driver unusable with a URL that works everywhere else.
        out.database = if q == null then name else name[0..<q]

        if q != null then readQuery(out, name[(q + 1)..])

        rest = rest[0..<slash]

    val at = lastIndexOf(rest, "@")

    if at != null
        val who = rest[0..<at]
        val colon = who.indexOf(":")

        if colon == null
            out.user = unescaped(who)
        else
            out.user = unescaped(who[0..<colon])
            out.password = unescaped(who[(colon + 1)..])

        rest = rest[(at + 1)..]

    val colon = rest.indexOf(":")

    if colon == null
        if rest != "" then out.host = rest
    else
        if colon > 0 then out.host = rest[0..<colon]

        val n = number(rest[(colon + 1)..])

        if n != null then out.port = integer(n)

    out

// **The LAST `@`, because a password may contain one** -- and an unescaped `@` in a password is
// common enough that splitting on the first one would send this client to connect to a host named
// after half of somebody's password.
lastIndexOf(s: string, c: string) -> integer | null
    var found = null

    for i in 0..<len(s)
        if s[i] == c then found = i

    found

// Percent-decoding, since a password in a URL has to escape `@`, `:` and `/`.
unescaped(s: string) -> string
    var out = ""
    var i = 0

    while i < len(s)
        if s[i] == "%" && i + 2 < len(s)
            val hi = "0123456789abcdef".indexOf(s[i + 1].lower())
            val lo = "0123456789abcdef".indexOf(s[i + 2].lower())

            if hi != null && lo != null
                val r = fromBytes([(hi << 4) | lo])

                out = out + (if r.ok then r.value else "")
                i = i + 3
            else
                out = out + s[i]
                i = i + 1
        else
            out = out + s[i]
            i = i + 1

    out

// -- messages the server sends about itself -----------------------------------------------------------

// An `ErrorResponse` or a `NoticeResponse`: a list of one-byte field types, each with a string.
//
// **The fields are named rather than kept as letters.** `C` is the SQLSTATE code every program
// branches on -- `23505` for a unique violation -- and a driver that handed back `{ C: "23505" }`
// would make every program that uses it carry a copy of this table.
fields(r: object) -> object
    val out = { }

    // **The terminator is compared as a BYTE and not as text.** A NUL written into the source as a
    // literal makes the whole file binary to every tool that reads it -- `file` calls it data and a
    // grep of it answers nothing at all, silently, which reads as the word not being there.
    while r.left() > 0
        val tag = r.bytes(1)

        if tag[0] == 0 then break

        val kind = fromBytes(tag).value

        val text = r.string()

        if kind == "S" then out.severity = text
        elif kind == "V" then out.severityCode = text
        elif kind == "C" then out.code = text
        elif kind == "M" then out.message = text
        elif kind == "D" then out.detail = text
        elif kind == "H" then out.hint = text
        elif kind == "P" then out.position = text
        elif kind == "W" then out.where = text
        elif kind == "s" then out.schema = text
        elif kind == "t" then out.table = text
        elif kind == "c" then out.column = text
        elif kind == "d" then out.dataType = text
        elif kind == "n" then out.constraint = text
        elif kind == "F" then out.file = text
        elif kind == "L" then out.line = text
        elif kind == "R" then out.routine = text

        if r.left() == 0 then break

    out

// What to put in `error`, which is the one line a program is most likely to print or log.
said(info) = info.message ?? "the database refused this without saying why"

// The text of a message's remaining bytes.
text(bs: array) -> string
    val r = fromBytes(bs)

    if !r.ok then throw "the server sent text that is not UTF-8 in a SASL message"

    r.value
