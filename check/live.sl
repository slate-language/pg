// A real round trip against a real PostgreSQL server, run by hand.
//
// **A fake server proves this client agrees with the protocol as written; only a real one proves the
// protocol was read correctly.** The suite under `tests/` is the first and this is the second, and
// neither replaces the other. It is not in the suite because it needs a server, and a suite that
// needed one would fail on every machine that has none.
//
// Start a server of its own -- not the machine's, so nothing here can touch real data:
//
//     initdb -D /tmp/pgcheck -U pgtest --auth-host=scram-sha-256 --pwfile=<(echo slatepw)
//     pg_ctl -D /tmp/pgcheck -o "-p 55432" -l /tmp/pgcheck.log start
//     slate check/live.sl
//     pg_ctl -D /tmp/pgcheck stop
//
// The password method is the point of the `--auth-host`: PostgreSQL 14 and later default to
// SCRAM-SHA-256, so a check that logged in with `trust` would be checking nothing about the half of
// this package that took the longest to write.

import { pg, bytea } from "../pg.sl"

var failures = 0

ok(what, got, wanted)
    if string(got) == string(wanted)
        print("  ok   ", what)
    else
        failures = failures + 1

        print("  FAIL ", what)
        print("         got   ", got)
        print("         wanted", wanted)

async main()
    val r = await pg({ host: "127.0.0.1", port: 55432, user: "pgtest", password: "slatepw", database: "postgres" })

    if !r.ok
        print("could not connect:", r.error)

        return

    val db = r.value

    print("connected to", db.parameters().server_version)

    // -- the simple protocol
    val one = await db.query("select 1 as n, 'hi' as greeting, null as nothing")

    ok("a simple query answers rows", toJSON(one.value.rows), "[{\"n\":1,\"greeting\":\"hi\",\"nothing\":null}]")
    ok("and says what it was", one.value.command, "SELECT")
    ok("and how many rows", one.value.count, 1)

    // -- parameters
    val two = await db.query("select $1::int + 1 as n, $2::text as t", [41, "ada"])

    ok("a parameter crosses and comes back", toJSON(two.value.rows), "[{\"n\":42,\"t\":\"ada\"}]")

    val quoted = await db.query("select $1::text as t", ["'; drop table users; --"])

    ok("a parameter is never SQL", quoted.value.rows[0].t, "'; drop table users; --")

    val nulled = await db.query("select $1::text as t, $2::text as u", [null, ""])

    ok("null and the empty string stay apart", toJSON(nulled.value.rows), "[{\"t\":null,\"u\":\"\"}]")

    // -- types
    val types = await db.query("select true as b, 1.5::float8 as f, 2.50::numeric as money, " +
        "'{\"a\":1}'::jsonb as doc, '\\x00ff'::bytea as bs, '2026-09-01'::date as d, " +
        "'2026-09-01 05:30:00'::timestamp as ts, 12345678901234::int8 as big")

    val row = types.value.rows[0]

    ok("a boolean", row.b, true)
    ok("a float", row.f, 1.5)
    ok("a numeric stays text", row.money, "2.50")
    ok("jsonb is parsed", toJSON(row.doc), "{\"a\":1}")
    ok("bytea is bytes", toJSON(row.bs), "[0,255]")
    ok("a date is a date", string(row.d), "2026-09-01")
    ok("a timestamp is one", string(row.ts), "2026-09-01T05:30:00")
    ok("an int8 is whole", row.big, 12345678901234)

    val back = await db.query("select $1::bytea as bs", [bytea([0, 1, 255])])

    ok("bytes go out and come back", toJSON(back.value.rows[0].bs), "[0,1,255]")

    val arr = await db.query("select $1::text[] as xs", [["a", "b,c", null]])

    ok("an array goes out and comes back as one", toJSON(arr.value.rows[0].xs), "[\"a\",\"b,c\",null]")

    val nums = await db.query("select array[1, 2, 3] as ns, array[[1, 2], [3, 4]] as grid")

    ok("an array of numbers is numbers", toJSON(nums.value.rows[0].ns), "[1,2,3]")
    ok("and an array of arrays keeps its shape", toJSON(nums.value.rows[0].grid), "[[1,2],[3,4]]")

    // -- writing
    await db.query("drop table if exists notes")
    await db.query("create table notes (id serial primary key, title text not null unique)")

    val put = await db.query("insert into notes (title) values ($1), ($2)", ["first", "second"])

    ok("an insert says how many", put.value.count, 2)

    val read = await db.query("select title from notes order by id")

    ok("and they are there", toJSON(read.value.rows), "[{\"title\":\"first\"},{\"title\":\"second\"}]")

    // -- errors
    val clash = await db.query("insert into notes (title) values ($1)", ["first"])

    ok("a unique violation is an answer", clash.ok, false)
    ok("and carries the SQLSTATE", clash.code, "23505")
    ok("and names the constraint", clash.info.constraint, "notes_title_key")

    val bad = await db.query("select * from a_table_that_is_not_there")

    ok("a missing table is an answer too", bad.code, "42P01")

    val alive = await db.query("select 1 as n")

    ok("and the connection is still usable", alive.value.rows[0].n, 1)

    // -- transactions
    await db.query("begin")
    ok("the status says so", db.status(), "T")

    await db.query("insert into notes (title) values ('third')")
    await db.query("rollback")

    val after = await db.query("select count(*)::int as n from notes")

    ok("a rollback rolls back", after.value.rows[0].n, 2)
    ok("and the status is idle again", db.status(), "I")

    // -- several statements in one simple query
    val many = await db.query("select 1 as n; select 2 as n; select 3 as n")

    ok("the last statement is the answer", many.value.rows[0].n, 3)
    ok("and every one of them is there", len(many.value.results), 3)

    // -- notices
    var heard = null

    db.onNotice((n) ->
        heard = n.message)

    await db.query("do $$ begin raise notice 'a notice'; end $$")

    ok("a notice arrives", heard, "a notice")

    // -- pipelining
    val a = db.query("select 1 as n")
    val b = db.query("select 2 as n")
    val c = db.query("select 3 as n")

    ok("three queries in flight answer in order",
        string((await a).value.rows[0].n) + string((await b).value.rows[0].n) + string((await c).value.rows[0].n),
        "123")

    await db.query("drop table notes")

    db.close()

    print("")

    if failures == 0 then print("all good") else print(failures, "failed")

main()
