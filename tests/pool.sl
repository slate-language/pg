// The pool, against the same PostgreSQL server written in slate that every other test here talks to.
//
// **The fake counts its connections**, which is what makes a pool testable at all: `min`, `max`, reuse
// and dropping are every one of them a statement about how many times a client logged in, and nothing
// about a pool is observable from a query's answer.

import { pool } from "../pg.sl"
import { send, close as closeSocket, localPort } from slate:net
import { server, authOk, describe, dataRow, commandComplete, errorResponse, readyFor,
    joined } from "./fake.sl"

// **A test that hangs is worse than a test that fails**, and a pool has more ways to hang than a
// connection does -- a waiter that is never answered and a drain that never ends are two of the things
// under test here.
val Guard = 3000

late(what) = setTimeout(() -> ranLong(what), Guard)

ranLong(what)
    throw "the " + what + " did not finish in time"

// A pause, which several of these need: a borrow has to still be out when the next one arrives.
async naps(ms)
    val q = pending()

    setTimeout(() -> settle(q, true), ms)

    await q

// Where the fake is listening, as connection options.
at(fake) = { host: "127.0.0.1", port: localPort(fake), user: "ada", password: "pencil", database: "notes" }

// One row, which is what every query here answers.
oneRow() = joined([
    describe([{ name: "n", oid: 23 }]),
    dataRow(["1"]),
    commandComplete("SELECT 1"),
    readyFor("I"),
])

// A server that accepts anybody and answers at once.
plainly(kind, r, sock)
    if kind == "startup" then return authOk()
    if kind == "Q" then return oneRow()

    null

// The same, answering after a moment so that a second borrow arrives while the first is still out.
//
// **The reply is scheduled and `null` is returned**, since the fake sends whatever the handler gives
// back -- so a handler that wants to be slow sends for itself later and gives back nothing now.
slowly(kind, r, sock)
    if kind == "startup" then return authOk()

    if kind == "Q"
        setTimeout(() -> send(sock, oneRow()), 60)

        return null

    null

@test
async A_POOL_OPENS_ITS_MINIMUM_AND_THEN_REUSES_WHAT_IT_HAS()
    val guard = late("pool minimum test")

    var starts = 0

    val fake = server((kind, r, sock) ->
        if kind == "startup"
            starts = starts + 1

            return authOk()

        plainly(kind, r, sock))

    val made = await pool(at(fake), { min: 2, max: 4 })

    assert(made.ok)

    val p = made.value

    // **The connections are open before the first query**, which is the whole of what `min` buys.
    assert(starts == 2)
    assert(p.size() == 2)
    assert(p.free() == 2)

    var i = 0

    while i < 5
        val said = await p.query("select 1 as n")

        assert(said.ok)
        assert(said.value.rows[0].n == 1)

        i = i + 1

    // Five queries one after another need one connection, and took one of the two.
    assert(starts == 2)
    assert(p.size() == 2)
    assert(p.free() == 2)

    await p.close()
    closeSocket(fake)
    clearTimeout(guard)

@test
async A_POOL_THAT_CANNOT_REACH_THE_DATABASE_SAYS_SO_WHEN_IT_IS_MADE()
    val guard = late("pool refusal test")

    // Nothing is listening on this port, so the first of the `min` connections fails.
    val made = await pool({ host: "127.0.0.1", port: 1, user: "ada", database: "notes" }, { min: 1, max: 2 })

    assert(!made.ok)
    assert(made.error != null)

    clearTimeout(guard)

@test
async OVERLAPPING_QUERIES_OPEN_CONNECTIONS_UP_TO_MAX_AND_NO_FURTHER()
    val guard = late("pool maximum test")

    var starts = 0

    val fake = server((kind, r, sock) ->
        if kind == "startup"
            starts = starts + 1

            return authOk()

        slowly(kind, r, sock))

    val made = await pool(at(fake), { min: 1, max: 3 })

    assert(made.ok)

    val p = made.value

    assert(starts == 1)

    // Four at once against a server that takes its time: three go out and the fourth waits.
    val a = p.query("select 1 as n")
    val b = p.query("select 1 as n")
    val c = p.query("select 1 as n")
    val d = p.query("select 1 as n")

    await naps(20)

    assert(p.size() == 3)
    assert(p.waiting() == 1)

    assert((await a).ok)
    assert((await b).ok)
    assert((await c).ok)
    assert((await d).ok)

    // **The fourth was answered by a connection that came back**, not by a fourth login.
    assert(starts == 3)
    assert(p.size() == 3)
    assert(p.free() == 3)
    assert(p.waiting() == 0)

    await p.close()
    closeSocket(fake)
    clearTimeout(guard)

@test
async A_WAITER_THAT_IS_NOT_GIVEN_A_CONNECTION_IN_TIME_FAILS_RATHER_THAN_HANGING()
    val guard = late("pool waiter timeout test")

    var starts = 0

    val fake = server((kind, r, sock) ->
        if kind == "startup"
            starts = starts + 1

            return authOk()

        plainly(kind, r, sock))

    val made = await pool(at(fake), { min: 1, max: 1, timeout: 60 })

    assert(made.ok)

    val p = made.value

    // The one connection there may be is held for far longer than a waiter is given.
    val holding = p.with(async (db) ->
        await naps(400)

        (await db.query("select 1 as n")).ok)

    await naps(20)

    val said = await p.query("select 1 as n")

    // **A waiter that ran out is an answer and not a throw**, which is where every other outside
    // condition arrives too -- a program can answer `503` rather than fall over.
    assert(!said.ok)
    assert(said.error.indexOf("waited") != null)

    val out = await holding

    assert(out.ok)
    assert(out.value)
    assert(starts == 1)

    await p.close()
    closeSocket(fake)
    clearTimeout(guard)

@test
async A_CONNECTION_THAT_DIED_IS_DROPPED_AND_THE_NEXT_BORROW_OPENS_A_FRESH_ONE()
    val guard = late("pool dropped connection test")

    var starts = 0
    var asked = 0

    val fake = server((kind, r, sock) ->
        if kind == "startup"
            starts = starts + 1

            return authOk()

        if kind == "Q"
            asked = asked + 1

            // The second query is answered by the server going away, which is what a restart, a
            // `pg_terminate_backend` or an idle timeout looks like from here.
            if asked == 2
                closeSocket(sock)

                return null

            return oneRow()

        null)

    val made = await pool(at(fake), { min: 1, max: 2 })

    assert(made.ok)

    val p = made.value

    assert((await p.query("select 1 as n")).ok)
    assert(starts == 1)
    assert(p.free() == 1)

    val broke = await p.query("select 1 as n")

    assert(!broke.ok)

    // **It is not put back**, so there is nothing to hand the next borrower.
    assert(p.size() == 0)
    assert(p.free() == 0)

    val after = await p.query("select 1 as n")

    assert(after.ok)
    assert(starts == 2)

    await p.close()
    closeSocket(fake)
    clearTimeout(guard)

@test
async A_FAILED_QUERY_IS_NOT_A_FAILED_CONNECTION_AND_THE_CONNECTION_IS_KEPT()
    val guard = late("pool failed query test")

    var starts = 0

    val fake = server((kind, r, sock) ->
        if kind == "startup"
            starts = starts + 1

            return authOk()

        if kind == "Q"
            return joined([
                errorResponse([
                    { kind: "S", text: "ERROR" },
                    { kind: "C", text: "42P01" },
                    { kind: "M", text: "relation \"nope\" does not exist" },
                ]),
                readyFor("I"),
            ])

        null)

    val made = await pool(at(fake), { min: 1, max: 2 })

    assert(made.ok)

    val p = made.value
    val said = await p.query("select * from nope")

    assert(!said.ok)
    assert(said.code == "42P01")

    // A syntax error is the database answering, not the connection going. One login, one connection
    // still in the pool.
    assert(p.size() == 1)
    assert(p.free() == 1)
    assert(starts == 1)

    await p.close()
    closeSocket(fake)
    clearTimeout(guard)

@test
async WITH_HOLDS_ONE_CONNECTION_FOR_EVERY_STATEMENT_IN_THE_CLOSURE()
    val guard = late("pool with test")

    var starts = 0

    val fake = server((kind, r, sock) ->
        if kind == "startup"
            starts = starts + 1

            return authOk()

        plainly(kind, r, sock))

    val made = await pool(at(fake), { min: 1, max: 4 })

    assert(made.ok)

    val p = made.value

    val out = await p.with(async (db) ->
        val one = await db.query("select 1 as n")
        val two = await db.query("select 1 as n")

        assert(p.free() == 0)

        one.value.rows[0].n + two.value.rows[0].n)

    assert(out.ok)
    assert(out.value == 2)

    // **Three statements, one login** -- which is the whole reason a transaction can be written this
    // way and cannot be written with `query`.
    assert(starts == 1)
    assert(p.free() == 1)

    await p.close()
    closeSocket(fake)
    clearTimeout(guard)

@test
async A_CONNECTION_LEFT_INSIDE_A_TRANSACTION_IS_NOT_PUT_BACK()
    val guard = late("pool open transaction test")

    var starts = 0

    val fake = server((kind, r, sock) ->
        if kind == "startup"
            starts = starts + 1

            return authOk()

        if kind == "Q"
            val sql = r.string()

            // `T` is what a server says once a transaction is open, and it is the only way a client
            // knows.
            if sql == "begin" then return joined([commandComplete("BEGIN"), readyFor("T")])

            return oneRow()

        null)

    val made = await pool(at(fake), { min: 1, max: 2 })

    assert(made.ok)

    val p = made.value

    val out = await p.with(async (db) -> (await db.query("begin")).ok)

    assert(out.ok)

    // The closure forgot to commit. The next borrower would have found itself inside that
    // transaction, so the connection is closed rather than kept.
    assert(p.size() == 0)
    assert(p.free() == 0)

    assert((await p.query("select 1 as n")).ok)
    assert(starts == 2)

    await p.close()
    closeSocket(fake)
    clearTimeout(guard)

@test
async A_CLOSURE_THAT_THROWS_GIVES_THE_CONNECTION_BACK_AND_THE_THROW_GOES_ON()
    val guard = late("pool throwing closure test")

    val fake = server(plainly)
    val made = await pool(at(fake), { min: 1, max: 2 })

    assert(made.ok)

    val p = made.value

    var caught = null

    try
        await p.with(async (db) ->
            assert((await db.query("select 1 as n")).ok)

            gaveUp())
    catch e
        caught = e

    assert(caught != null)

    // **The connection came back**, since a closure that threw says nothing about the connection --
    // it was left idle, so it is kept.
    assert(p.size() == 1)
    assert(p.free() == 1)

    await p.close()
    closeSocket(fake)
    clearTimeout(guard)

gaveUp()
    throw "the closure gave up"

@test
async CLOSE_WAITS_FOR_WHAT_IS_OUT_CLOSES_EVERYTHING_AND_REFUSES_A_NEW_BORROW()
    val guard = late("pool drain test")

    val fake = server(plainly)
    val made = await pool(at(fake), { min: 2, max: 4 })

    assert(made.ok)

    val p = made.value

    assert(p.size() == 2)

    val holding = p.with(async (db) ->
        await naps(150)

        (await db.query("select 1 as n")).ok)

    await naps(20)

    val ending = p.close()

    // **A borrow after `close` is the program's own mistake and throws**, which is where calling
    // `query` on a closed connection already goes.
    var threw = null

    try
        await p.query("select 1 as n")
    catch e
        threw = e

    assert(threw != null)

    // The one that was already out finished its statement rather than being cut off.
    val out = await holding

    assert(out.ok)
    assert(out.value)

    await ending

    assert(p.size() == 0)
    assert(p.free() == 0)

    // Closing twice is not an error, and the second one does not wait for anything.
    await p.close()

    closeSocket(fake)
    clearTimeout(guard)

@test
async A_CONNECTION_ABOVE_THE_MINIMUM_IS_CLOSED_ONCE_IT_HAS_SAT_IDLE()
    val guard = late("pool idle test")

    var starts = 0

    val fake = server((kind, r, sock) ->
        if kind == "startup"
            starts = starts + 1

            return authOk()

        slowly(kind, r, sock))

    val made = await pool(at(fake), { min: 1, max: 3, idle: 60 })

    assert(made.ok)

    val p = made.value

    val a = p.query("select 1 as n")
    val b = p.query("select 1 as n")
    val c = p.query("select 1 as n")

    assert((await a).ok)
    assert((await b).ok)
    assert((await c).ok)

    assert(starts == 3)
    assert(p.free() == 3)

    await naps(150)

    // **The burst is given back and `min` is kept**, so a moment of load does not leave the server
    // holding three backends for the rest of the day.
    assert(p.size() == 1)
    assert(p.free() == 1)

    // And the one that is left still works.
    assert((await p.query("select 1 as n")).ok)
    assert(starts == 3)

    await p.close()
    closeSocket(fake)
    clearTimeout(guard)
