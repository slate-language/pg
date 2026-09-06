// A pool of connections, over anything that answers one.
//
//     import { pool } from pg
//
//     val p = (await pool("postgres://ada@127.0.0.1/notes", { max: 8 })).value
//     val r = await p.query("select id from notes where author = $1", "ada")
//
//     await p.close()
//
// ## Why this is a file of its own, and why it takes `open` rather than importing `pg`
//
// **The pool needs one thing from the client: a function that answers a connection.** Given that, it
// is arithmetic over a list -- so it is written against `open` and knows nothing about PostgreSQL,
// which is also what keeps `pg.sl` from importing this file and this file from importing `pg.sl`.
// `pg.sl` hands it `() -> opened(cfg)` and re-exports the result as `pool`, so a program still sees
// one door.
//
// ## A connection is BORROWED and not handed out
//
// **Everything a program can do with the pool gives the connection back**, which is the whole of why
// the pool is safe to share. `query` borrows for one statement. `with` holds one for a closure, which
// is the transaction case and the only reason a program needs to see a connection at all: `begin` and
// `commit` are two statements and they must be the same connection or they mean nothing.
//
// ## What is dropped rather than returned
//
// **A connection that died is not put back**, since the pool would then hand a program a socket that
// is gone. **Nor is one left inside a transaction**: a closure that threw between `begin` and `commit`
// leaves the server holding an open transaction, and the next borrower would find itself inside it.
// Both are closed and the count goes down, so the next borrow opens a fresh one.
//
// **A query that FAILED is not a connection that failed.** A constraint violation, a syntax error and
// a table that is not there all answer `{ ok: false }` on a connection that is perfectly well, and a
// pool that dropped one on every such answer would reconnect for every typo. The discriminator is the
// connection's own `alive`, and nothing else.
//
// ## Waiting, which is what `max` is for
//
// **A borrow past `max` queues rather than opening a connection anyway**, because `max` is usually the
// server's `max_connections` divided among the machines that talk to it -- a pool that exceeded it
// would turn a slow moment into refused connections for everybody. A waiter is given the next
// connection that comes back, oldest first, and is failed after `timeout` so that a program which
// leaks a borrow is a request that answers slowly rather than a server that stops.

// `poolOver(open, tuning)` -- a pool, or the reason there is not one.
//
// `open` answers `{ ok, value }` with a connection under `value`, which is what `pg` answers.
//
// **The four settings are node-postgres's four under shorter names** -- `min`, `max`, `idle` and
// `timeout` for its `min`, `max`, `idleTimeoutMillis` and `connectionTimeoutMillis` -- because these
// are the numbers a person arrives already knowing, and spelling them differently would buy nothing.
//
// **`min` is 1 rather than 0 so that a pool which cannot reach the database says so when it is made.**
// A pool of nothing always succeeds and answers its first query with the connection error, which
// moves a deployment mistake from start-up into the first request.
export async poolOver(open, tuning)
    val {
        min = 1,
        max = 10,

        // How long a connection above `min` is kept before it is closed. A connection costs the
        // server memory and a backend process, so a burst that opened ten should not hold ten.
        idle = 30000,

        // How long a borrow waits for a connection once `max` are out.
        timeout = 10000,
    } = tuning ?? { }

    if max < 1 then throw "a pool's `max` is at least 1, and this is " + string(max)
    if min < 0 then throw "a pool's `min` is at least 0, and this is " + string(min)
    if min > max then throw "a pool's `min` cannot be more than its `max`, and " + string(min) + " is more than " + string(max)

    // Connections open or opening, borrowed or not. **Counted up before the connection exists**, so
    // two borrows racing at the limit cannot both decide there is room.
    var total = 0

    // The connections nobody is using: `{ id, db, timer }`, oldest first, and taken from the end so
    // that the ones a burst added are the ones that go idle and get reaped.
    val free = []

    // Borrows that arrived at `max`, oldest first.
    val waiters = []

    var ids = 0
    var closing = false
    var drained = null

    // -- the count ---------------------------------------------------------------------------------

    gone()
        total = total - 1

        if closing && total == 0 && drained != null
            val d = drained

            drained = null

            settle(d, true)

    async made()
        total = total + 1

        val r = await open()

        if !r.ok then gone()

        r

    // -- the free list -----------------------------------------------------------------------------

    // Drop `e` from the free list, answering whether it was still there.
    //
    // **Identity is an id and not the object**, since `==` on two objects is a comparison of what
    // they contain and two entries holding equal-looking connections would be one entry.
    dropped(e) -> boolean
        var i = 0

        while i < free.length
            if free[i].id == e.id
                removeAt(free, i)

                return true

            i = i + 1

        false

    // An entry's reaper, put out. **There may not be one**: a connection at or below `min` is never
    // reaped, so it is parked with no timer at all rather than with one that re-arms itself for the
    // life of the pool -- and `clearTimeout` is asked for an id and not for a maybe.
    unarmed(e)
        if e.timer != null
            clearTimeout(e.timer)

            e.timer = null

    // A connection that has sat unused for `idle` and is not one of the `min` kept.
    //
    // **The timer is armed only while there are more than `min` open.** A repeating sweep would keep
    // the event loop alive for as long as the pool exists, which in a test is a run that does not end
    // and in a program is a process that will not exit.
    reaped(e)
        if total <= min then return
        if !dropped(e) then return

        e.db.close()
        gone()

    // -- waiting -----------------------------------------------------------------------------------

    waited(w)
        if w.settled then return

        var i = 0

        while i < waiters.length
            if waiters[i].id == w.id
                removeAt(waiters, i)

                i = waiters.length
            else
                i = i + 1

        w.settled = true

        settle(w.promise, { ok: false, error: "waited " + string(timeout) + "ms for a pooled connection and all " + string(max) + " are out" })

    // Give `db` to the oldest waiter, if there is one. The connection stays borrowed either way, which
    // is why nothing is counted here.
    handed(db) -> boolean
        while waiters.length > 0
            val w = waiters[0]

            removeAt(waiters, 0)

            if !w.settled
                w.settled = true

                clearTimeout(w.timer)
                settle(w.promise, { ok: true, value: db })

                return true

        false

    // -- borrowing and giving back -----------------------------------------------------------------

    async borrow()
        if closing then throw "this connection pool is closed"

        while free.length > 0
            val e = free[free.length - 1]

            removeAt(free, free.length - 1)
            unarmed(e)

            if e.db.alive() then return { ok: true, value: e.db }

            // The server, or something between, closed it while it sat here.
            gone()

        if total < max then return await made()

        ids = ids + 1

        val w = { id: ids, promise: pending(), settled: false, timer: null }

        w.timer = setTimeout(() -> waited(w), timeout)

        push(waiters, w)

        await w.promise

    give(db)
        if !db.alive()
            gone()

            return

        // `I` idle, `T` in a transaction, `E` in one that has failed. Anything but `I` is a connection
        // the next borrower would find in the middle of somebody else's work.
        if db.status() != "I" || closing
            db.close()
            gone()

            return

        if handed(db) then return

        ids = ids + 1

        val e = { id: ids, db: db, timer: null }

        push(free, e)

        if total > min then e.timer = setTimeout(() -> reaped(e), idle)

    // -- the pool ----------------------------------------------------------------------------------

    val p = { }

    // One statement on a connection borrowed for it and given straight back.
    //
    // **It answers exactly what `db.query` answers**, plus the two things that can go wrong before
    // there is a connection at all -- an open that failed, and a wait that ran out. Both arrive as
    // `{ ok: false, error }`, which is where a database that is unreachable already arrives.
    async asked(sql: string, params: array)
        val got = await borrow()

        if !got.ok then return got

        val db = got.value
        var r = null

        try
            r = await db.query(sql, ...params)
        catch e
            give(db)

            throw e

        give(db)

        r

    // One connection held for as long as `f` runs, which is how a transaction is written.
    //
    //     await p.with(async db ->
    //         await db.query("begin")
    //         await db.query("insert into notes (title) values ($1)", title)
    //         await db.query("commit"))
    //
    // **What `f` answers comes back under `value`**, so the two ways of not getting a connection read
    // the same here as they do on `query`. **What `f` THROWS is thrown on**, because that is the
    // program's own failure and not the pool's -- the connection is given back first, and given back
    // means closed where a transaction was left open.
    async held(f)
        val got = await borrow()

        if !got.ok then return got

        val db = got.value
        var v = null

        try
            v = await f(db)
        catch e
            give(db)

            throw e

        give(db)

        { ok: true, value: v }

    // Every connection closed, and no more borrowing.
    //
    // **It waits for what is out to come back rather than closing it underneath a query.** A borrowed
    // connection is in the middle of somebody's statement; closing it would answer that statement with
    // a connection error for the sake of exiting a few milliseconds sooner. A borrow that is already
    // waiting is failed at once, since the connection it is waiting for will never come.
    async drain()
        if closing
            if drained != null then await drained

            return

        closing = true

        while waiters.length > 0
            val w = waiters[0]

            removeAt(waiters, 0)

            if !w.settled
                w.settled = true

                clearTimeout(w.timer)
                settle(w.promise, { ok: false, error: "this connection pool is closing" })

        while free.length > 0
            val e = free[0]

            removeAt(free, 0)
            unarmed(e)
            e.db.close()
            gone()

        if total == 0 then return

        drained = pending()

        await drained

    p.query = (sql, ...params) -> asked(sql, params)
    p.with = (f) -> held(f)
    p.close = () -> drain()

    // What the pool is doing, which is what a `/health` handler wants and what a test asserts.
    p.size = () -> total
    p.free = () -> free.length
    p.waiting = () -> waiters.length

    // **The `min` connections are opened here and not on the first query**, so a host that is wrong or
    // a password that is stale is a pool that was never made rather than a request that failed.
    var i = 0

    while i < min
        val r = await made()

        if !r.ok
            await drain()

            return r

        give(r.value)

        i = i + 1

    { ok: true, value: p }
