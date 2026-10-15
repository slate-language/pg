// Migrations against a real PostgreSQL server, run by hand -- `tests/migrate.sl`'s ground again, with
// the database deciding what a transaction and a lock are instead of a fake.
//
// Its own cluster, as `check/live.sl` starts one (any port; `PG_URL` names it):
//
//     initdb -D /tmp/pgmig -U pgtest --auth-host=scram-sha-256 --pwfile=<(echo slatepw)
//     pg_ctl -D /tmp/pgmig -o "-p 55432" -l /tmp/pgmig.log start
//     PG_URL=postgres://pgtest:slatepw@127.0.0.1:55432/postgres slate check/migrate.sl
//     pg_ctl -D /tmp/pgmig stop
//
// It drops the tables it makes before every part, so it can be run again against the same cluster.

import { pg, pool, migrate, rollback, migrationStatus } from "../pg.sl"
import { env } from slate:process

val Url = env("PG_URL") ?? "postgres://pgtest:slatepw@127.0.0.1:55432/postgres"

val Three = "tests/migrations/three"
val Changed = "tests/migrations/changed"
val Failing = "tests/migrations/failing"

var failures = 0

ok(what, got, wanted)
    if string(got) == string(wanted)
        print("  ok   ", what)
    else
        failures = failures + 1

        print("  FAIL ", what)
        print("         got   ", got)
        print("         wanted", wanted)

async fresh(db)
    await db.query("drop table if exists toys, pets, people, half_done, after_broken, schema_migrations")

async tables(db)
    val r = await db.query("select table_name from information_schema.tables where table_schema = 'public' order by table_name")

    r.value.rows.map((x) -> x.table_name)

async versions(db)
    val r = await db.query("select version from schema_migrations order by version")

    r.value.rows.map((x) -> x.version)

async connected()
    val r = await pg(Url)

    if !r.ok then throw "could not connect: " + r.error

    r.value

async main()
    val db = await connected()

    print("connected to", db.parameters().server_version)

    // -- applying, and applying again
    await fresh(db)

    val first = await migrate(db, Three)

    ok("three migrations apply in numeric order", toJSON(first.value.applied.map((a) -> a.version)), "[1,2,10]")
    ok("and their tables exist", toJSON(await tables(db)), "[\"people\",\"pets\",\"schema_migrations\",\"toys\"]")
    ok("and are recorded", toJSON(await versions(db)), "[1,2,10]")

    val again = await migrate(db, Three)

    ok("a second run applies nothing", again.value.applied.length, 0)

    // -- a changed file
    await db.query("drop table toys")
    await db.query("delete from schema_migrations where version = 10")

    val changed = await migrate(db, Changed)

    ok("an applied file that changed is refused", changed.ok, false)
    ok("by name", changed.error.contains("2_pets.up.sql"), true)
    ok("and the pending one did not run", toJSON(await versions(db)), "[1,2]")

    val status = await migrationStatus(db, Changed)

    ok("the status names it changed", toJSON(status.value.changed.map((a) -> a.file)), "[\"2_pets.up.sql\"]")

    // -- a rollback with no down, then one with
    await migrate(db, Three)

    val nodown = await rollback(db, Three, { steps: 2 })

    ok("a rollback whose newest has no down is refused", nodown.error, "10_toys.up.sql has no 10_toys.down.sql, so it cannot be rolled back")
    ok("and undoes nothing", toJSON(await versions(db)), "[1,2,10]")

    await db.query("drop table toys")
    await db.query("delete from schema_migrations where version = 10")

    val back = await rollback(db, Three, { steps: 2 })

    ok("a rollback runs the downs newest first", toJSON(back.value.reverted.map((a) -> a.version)), "[2,1]")
    ok("and the tables are gone", toJSON(await tables(db)), "[\"schema_migrations\"]")

    // -- a failing migration
    await fresh(db)

    val broke = await migrate(db, Failing)

    ok("a failing migration is an answer", broke.ok, false)
    ok("with the server's code", broke.code, "42P01")
    ok("the one before it stays applied", toJSON(broke.applied.map((a) -> a.version)), "[1]")
    ok("and nothing it did was kept, nor anything after it", toJSON(await tables(db)), "[\"people\",\"schema_migrations\"]")
    ok("the connection is idle again", db.status(), "I")

    val pending = await migrationStatus(db, Failing)

    ok("the rest are pending", toJSON(pending.value.pending.map((a) -> a.version)), "[2,3]")

    // -- two runners at once
    await fresh(db)

    val other = await connected()
    val a = migrate(db, Three)
    val b = migrate(other, Three)
    val ra = await a
    val rb = await b

    ok("two runners both succeed", toJSON([ra.ok, rb.ok, ra.error ?? "", rb.error ?? ""]), "[true,true,\"\",\"\"]")
    ok("and apply three between them", ra.value.applied.length + rb.value.applied.length, 3)
    ok("once each", toJSON(await versions(db)), "[1,2,10]")

    val held = await db.query("select count(*)::int as n from pg_locks where locktype = 'advisory'")

    ok("and the lock is let go", held.value.rows[0].n, 0)

    other.close()

    // -- over a pool
    await fresh(db)

    val made = await pool(Url, { min: 1, max: 2 })
    val p = made.value
    val pooled = await migrate(p, Three)

    ok("a pool migrates", pooled.value.applied.length, 3)
    ok("and reports", (await migrationStatus(p, Three)).value.applied.length, 3)

    await p.close()
    await fresh(db)

    db.close()

    print(if failures == 0 then "all migration checks passed" else string(failures) + " failed")

main()
