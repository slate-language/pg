// Migrations, against a fake that keeps `schema_migrations` and the advisory lock the way PostgreSQL
// does -- per connection for the transaction, shared between connections for the table and the lock.
//
// **The fake understands only the statements the runner sends of its own**, and treats every other
// simple query as a migration's SQL: it records it, and refuses it where it mentions `no_such_table`,
// which is what `migrations/failing/2_broken.up.sql` does to a real server too. `check/migrate.sl` is
// the same ground against a real PostgreSQL.

import { pg, pool, migrate, rollback, migrationStatus } from "../pg.sl"
import { sha256 } from slate:crypto
import { readFileSync } from slate:fs
import { send, close as closeSocket, localPort } from slate:net
import { server, authOk, describe, dataRow, commandComplete, errorResponse, readyFor,
    parseComplete, bindComplete, noData, joined } from "./fake.sl"
import { hex } from "../auth.sl"

val Guard = 3000

late(what) = setTimeout(() -> ranLong(what), Guard)

ranLong(what)
    throw "the " + what + " did not finish in time"

val Three = "tests/migrations/three"
val Changed = "tests/migrations/changed"
val Failing = "tests/migrations/failing"

// A database: the committed rows, who holds the lock and who is waiting for it, and every statement
// any connection sent, in the order the fake saw them.
database()
    { rows: [], table: false, holder: null, waiters: [], log: [], conns: [] }

// What one connection is in the middle of: its transaction, what that transaction would commit, and
// the extended-protocol statement it is building.
connOf(base, sock)
    for c in base.conns
        if c.sock == sock then return c

    // **Compared by `id` and never by `==` on the object**: slate's `==` is by value, so two fresh
    // connections in the same state would be the same connection.
    val c = { id: base.conns.length, sock: sock, tx: "I", staged: [], sql: "", params: [] }

    push(base.conns, c)

    c

done(c, tag) = joined([commandComplete(tag), readyFor(c.tx)])

oneText(c, name, value) = joined([describe([{ name: name, oid: 25 }]), dataRow([value]), commandComplete("SELECT 1"), readyFor(c.tx)])

// The answer function a fake server is given, over one shared database.
answering(base)
    (kind, r, sock) -> answered(base, kind, r, sock)

answered(base, kind, r, sock)
    if kind == "startup" then return authOk()

    if kind == "ssl" then return null

    val c = connOf(base, sock)

    if kind == "X"
        if base.holder == c.id then release(base)

        return null

    if kind == "Q" then return simple(base, c, r.string())

    if kind == "P"
        r.string()

        c.sql = r.string()

        return null

    if kind == "B"
        r.string()
        r.string()
        r.int16()

        val n = r.int16()

        c.params = []

        for i in 0..<n
            val size = r.int32()

            push(c.params, if size < 0 then null else fromBytes(r.bytes(size)).value)

        return null

    if kind == "S" then return extended(base, c, sock)

    null

simple(base, c, sql)
    push(base.log, sql)

    if sql == "begin"
        c.tx = "T"
        c.staged = []

        return done(c, "BEGIN")

    if sql == "commit"
        val failed = c.tx == "E"

        if !failed
            for f in c.staged
                f()

        c.tx = "I"
        c.staged = []

        return done(c, if failed then "ROLLBACK" else "COMMIT")

    if sql == "rollback"
        c.tx = "I"
        c.staged = []

        return done(c, "ROLLBACK")

    if sql.startsWith("create table if not exists schema_migrations")
        base.table = true

        return done(c, "CREATE TABLE")

    if sql.startsWith("select to_regclass")
        return oneText(c, "t", if base.table then "schema_migrations" else null)

    if sql.startsWith("select version, name, checksum from schema_migrations")
        val parts = [describe([{ name: "version", oid: 20 }, { name: "name", oid: 25 }, { name: "checksum", oid: 25 }])]

        for row in base.rows.sorted((a, b) -> a.version < b.version)
            push(parts, dataRow([string(row.version), row.name, row.checksum]))

        push(parts, commandComplete("SELECT " + string(base.rows.length)))
        push(parts, readyFor(c.tx))

        return joined(parts)

    // Anything else is a migration's own SQL.
    if sql.contains("no_such_table")
        if c.tx == "T" then c.tx = "E"

        return joined([
            errorResponse([
                { kind: "S", text: "ERROR" },
                { kind: "C", text: "42P01" },
                { kind: "M", text: "relation \"no_such_table\" does not exist" },
            ]),
            readyFor(c.tx),
        ])

    done(c, "CREATE TABLE")

extended(base, c, sock)
    val sql = c.sql
    val params = c.params

    push(base.log, sql)

    if sql.startsWith("select pg_advisory_lock")
        val reply = joined([parseComplete(), bindComplete(), describe([{ name: "pg_advisory_lock", oid: 25 }]), dataRow([""]), commandComplete("SELECT 1"), readyFor(c.tx)])

        if base.holder == null || base.holder == c.id
            base.holder = c.id

            return reply

        // **Held by somebody else, so this connection is not answered** -- which is exactly what
        // PostgreSQL does: the statement simply has not finished yet.
        push(base.waiters, { id: c.id, sock: sock, reply: reply })

        return null

    if sql.startsWith("select pg_advisory_unlock")
        if base.holder == c.id then release(base)

        return joined([parseComplete(), bindComplete(), describe([{ name: "pg_advisory_unlock", oid: 16 }]), dataRow(["t"]), commandComplete("SELECT 1"), readyFor(c.tx)])

    if sql.startsWith("insert into schema_migrations")
        val row = { version: integer(number(params[0])), name: params[1], checksum: params[2] }

        push(c.staged, () -> push(base.rows, row))

        return joined([parseComplete(), bindComplete(), noData(), commandComplete("INSERT 0 1"), readyFor(c.tx)])

    if sql.startsWith("delete from schema_migrations")
        val v = integer(number(params[0]))

        push(c.staged, () -> unrecord(base, v))

        return joined([parseComplete(), bindComplete(), noData(), commandComplete("DELETE 1"), readyFor(c.tx)])

    throw "the migration fake was sent a statement it does not know: " + sql

unrecord(base, version)
    base.rows = base.rows.filter((r) -> r.version != version)

// The lock let go, and handed to whoever asked for it first.
release(base)
    base.holder = null

    if base.waiters.length > 0
        val w = base.waiters[0]

        base.waiters = base.waiters.slice(1)
        base.holder = w.id

        send(w.sock, w.reply)

async connectedTo(base)
    val fake = server(answering(base))
    val made = await pg({ host: "127.0.0.1", port: localPort(fake), user: "ada", password: "", database: "notes" })

    assert(made.ok)

    { fake: fake, db: made.value }

// The statements that were migrations' own SQL, in the order they ran.
ranSql(log)
    log.filter((s) -> s.startsWith("create table people") || s.startsWith("create table pets") || s.startsWith("create table toys") || s.startsWith("create table half") || s.startsWith("create table after") || s.startsWith("drop table"))

checksumOf(file) = hex(sha256(readFileSync(file).value))

@test
async PENDING_MIGRATIONS_ARE_APPLIED_IN_NUMERIC_ORDER_AND_RECORDED()
    val guard = late("apply test")
    val base = database()
    val m = await connectedTo(base)

    val r = await migrate(m.db, Three)

    assert(r.ok)
    assert(r.value.applied.map((a) -> a.version) == [1, 2, 10])
    assert(r.value.applied[2].name == "toys")
    assert(r.value.applied[2].file == "10_toys.up.sql")

    // **Numeric order and not text order**: `10_toys` sorts before `2_pets` as a name.
    val ran = ranSql(base.log)

    assert(ran.length == 3)
    assert(ran[0].startsWith("create table people"))
    assert(ran[1].startsWith("create table pets"))
    assert(ran[2].startsWith("create table toys"))

    assert(base.rows.length == 3)
    assert(base.rows[1].name == "pets")
    assert(base.rows[1].checksum == checksumOf(Three + "/2_pets.up.sql"))

    // Each migration is its own transaction, opened after the lock and the table and closed before
    // the next one opens.
    assert(base.log[0].startsWith("select pg_advisory_lock"))
    assert(base.log[1].startsWith("create table if not exists schema_migrations"))
    assert(base.log.filter((s) -> s == "begin").length == 3)
    assert(base.log.filter((s) -> s == "commit").length == 3)
    assert(base.log[base.log.length - 1].startsWith("select pg_advisory_unlock"))
    assert(base.holder == null)

    m.db.close()
    closeSocket(m.fake)
    clearTimeout(guard)

@test
async RUNNING_MIGRATE_TWICE_APPLIES_NOTHING_THE_SECOND_TIME()
    val guard = late("twice test")
    val base = database()
    val m = await connectedTo(base)

    assert((await migrate(m.db, Three)).ok)

    val before = base.log.length
    val again = await migrate(m.db, Three)

    assert(again.ok)
    assert(again.value.applied.length == 0)
    assert(base.rows.length == 3)
    assert(base.log.slice(before).filter((s) -> s == "begin").length == 0)

    m.db.close()
    closeSocket(m.fake)
    clearTimeout(guard)

@test
async AN_APPLIED_MIGRATION_WHOSE_FILE_CHANGED_IS_REFUSED_BY_NAME_AND_NOTHING_RUNS()
    val guard = late("checksum test")
    val base = database()
    val m = await connectedTo(base)

    assert((await migrate(m.db, Three)).ok)

    // Undo the newest so there is something pending, then change an applied file underneath it.
    base.rows = base.rows.filter((r) -> r.version != 10)

    val before = base.log.length
    val r = await migrate(m.db, Changed)

    assert(!r.ok)
    assert(r.error.contains("2_pets.up.sql"))
    assert(r.error.contains("has changed"))
    assert(r.applied.length == 0)

    // **Not even the pending one ran**, and the lock was given back.
    assert(base.log.slice(before).filter((s) -> s == "begin").length == 0)
    assert(base.rows.length == 2)
    assert(base.holder == null)

    // The status says the same thing without refusing.
    val s = await migrationStatus(m.db, Changed)

    assert(s.ok)
    assert(s.value.changed.map((a) -> a.file) == ["2_pets.up.sql"])
    assert(s.value.pending.map((a) -> a.version) == [10])

    // And a rollback will not undo a migration that is not what was applied either.
    val back = await rollback(m.db, Changed, { steps: 1 })

    assert(!back.ok)
    assert(back.error.contains("2_pets.up.sql"))

    m.db.close()
    closeSocket(m.fake)
    clearTimeout(guard)

@test
async A_FAILING_MIGRATION_KEEPS_NOTHING_AND_LEAVES_LATER_ONES_PENDING()
    val guard = late("failure test")
    val base = database()
    val m = await connectedTo(base)

    val r = await migrate(m.db, Failing)

    assert(!r.ok)
    assert(r.error.contains("2_broken.up.sql failed"))
    assert(r.error.contains("no_such_table"))
    assert(r.code == "42P01")
    assert(r.applied.map((a) -> a.version) == [1])

    // Its row is not there, the one after it never ran, and the connection is usable and idle.
    assert(base.rows.map((x) -> x.version) == [1])
    assert(!base.log.some((s) -> s.startsWith("create table after")))
    assert(base.log.contains("rollback"))
    assert(m.db.status() == "I")
    assert(base.holder == null)

    val s = await migrationStatus(m.db, Failing)

    assert(s.value.applied.map((a) -> a.version) == [1])
    assert(s.value.pending.map((a) -> a.version) == [2, 3])

    m.db.close()
    closeSocket(m.fake)
    clearTimeout(guard)

@test
async A_ROLLBACK_UNDOES_THE_NEWEST_FIRST_AND_REMOVES_THEIR_ROWS()
    val guard = late("rollback test")
    val base = database()
    val m = await connectedTo(base)

    assert((await migrate(m.db, Three)).ok)

    // 10 has no down, so take it off by hand and roll back the two below it.
    base.rows = base.rows.filter((r) -> r.version != 10)

    val before = base.log.length
    val r = await rollback(m.db, Three, { steps: 2 })

    assert(r.ok)
    assert(r.value.reverted.map((a) -> a.version) == [2, 1])

    val ran = ranSql(base.log.slice(before))

    assert(ran == ["drop table pets;\n", "drop table people;\n"])
    assert(base.rows.length == 0)

    // Nothing left to roll back is an empty answer and not a refusal.
    val none = await rollback(m.db, Three)

    assert(none.ok)
    assert(none.value.reverted.length == 0)

    m.db.close()
    closeSocket(m.fake)
    clearTimeout(guard)

@test
async A_ROLLBACK_WITH_NO_DOWN_FILE_IS_REFUSED_AND_UNDOES_NOTHING()
    val guard = late("no-down test")
    val base = database()
    val m = await connectedTo(base)

    assert((await migrate(m.db, Three)).ok)

    val before = base.log.length

    // Two steps: 10 has no down and 2 does. **Checked for all of them before any runs**, so 2 is not
    // undone either.
    val r = await rollback(m.db, Three, { steps: 2 })

    assert(!r.ok)
    assert(r.error == "10_toys.up.sql has no 10_toys.down.sql, so it cannot be rolled back")
    assert(r.reverted.length == 0)
    assert(base.rows.length == 3)
    assert(base.log.slice(before).filter((s) -> s == "begin").length == 0)
    assert(base.holder == null)

    m.db.close()
    closeSocket(m.fake)
    clearTimeout(guard)

@test
async A_STEPS_THAT_IS_NOT_A_COUNT_IS_THE_PROGRAMS_OWN_MISTAKE()
    val guard = late("steps test")
    val base = database()
    val m = await connectedTo(base)

    var said = ""

    try
        await rollback(m.db, Three, { steps: 0 })
    catch e
        said = string(e)

    assert(said.contains("`steps` is a count of at least 1"))

    m.db.close()
    closeSocket(m.fake)
    clearTimeout(guard)

@test
async A_DIRECTORY_THAT_DOES_NOT_SAY_WHAT_IT_MEANS_IS_REFUSED_NAMING_THE_FILE()
    val guard = late("directory test")
    val base = database()
    val m = await connectedTo(base)

    val malformed = await migrate(m.db, "tests/migrations/malformed")

    assert(!malformed.ok)
    assert(malformed.error.startsWith("people.up.sql is not a migration's name"))

    val duplicate = await migrate(m.db, "tests/migrations/duplicate")

    assert(!duplicate.ok)
    assert(duplicate.error == "01_pets.up.sql and 1_people.up.sql are both migration 1, and a number may be used once")

    val orphan = await migrationStatus(m.db, "tests/migrations/orphan")

    assert(!orphan.ok)
    assert(orphan.error == "1_people.down.sql has no 1_people.up.sql beside it")

    val gone = await rollback(m.db, "tests/migrations/not-there")

    assert(!gone.ok)
    assert(gone.error.startsWith("the migrations directory could not be read: "))

    // **The directory is read before the database is touched**, so none of these took the lock.
    assert(base.log.length == 0)

    m.db.close()
    closeSocket(m.fake)
    clearTimeout(guard)

@test
async THE_STATUS_OF_A_DATABASE_NEVER_MIGRATED_IS_ALL_PENDING_AND_WRITES_NOTHING()
    val guard = late("status test")
    val base = database()
    val m = await connectedTo(base)

    val s = await migrationStatus(m.db, Three)

    assert(s.ok)
    assert(s.value.applied.length == 0)
    assert(s.value.pending.map((a) -> a.version) == [1, 2, 10])
    assert(s.value.changed.length == 0)
    assert(s.value.missing.length == 0)
    assert(!base.table)

    // A version the database has and the directory does not is `missing`.
    assert((await migrate(m.db, Three)).ok)

    val other = await migrationStatus(m.db, Failing)

    // And one whose number is there with other contents is `changed`, whatever the file is called.
    assert(other.value.missing.map((a) -> a.version) == [10])
    assert(other.value.missing[0].name == "toys")
    assert(other.value.changed.map((a) -> a.file) == ["2_broken.up.sql"])
    assert(other.value.applied.map((a) -> a.version) == [1, 2])
    assert(other.value.pending.map((a) -> a.version) == [3])

    m.db.close()
    closeSocket(m.fake)
    clearTimeout(guard)

@test
async TWO_RUNNERS_AT_ONCE_ARE_SERIALISED_BY_THE_LOCK()
    val guard = late("concurrency test")
    val base = database()
    val one = await connectedTo(base)
    val two = await connectedTo(base)

    // Both started before either is awaited.
    val a = migrate(one.db, Three)
    val b = migrate(two.db, Three)
    val ra = await a
    val rb = await b

    assert(ra.ok)
    assert(rb.ok)

    // **Every migration was applied exactly once between them**, and the second found nothing to do.
    assert(ra.value.applied.length + rb.value.applied.length == 3)
    assert(base.rows.length == 3)
    assert(ranSql(base.log).length == 3)

    // And the second really did wait: its lock request came before the first let go.
    val locks = base.log.filter((s) -> s.startsWith("select pg_advisory"))

    assert(locks[0].startsWith("select pg_advisory_lock"))
    assert(locks[1].startsWith("select pg_advisory_lock"))
    assert(locks[2].startsWith("select pg_advisory_unlock"))

    one.db.close()
    two.db.close()
    closeSocket(one.fake)
    closeSocket(two.fake)
    clearTimeout(guard)

@test
async A_POOL_RUNS_THE_WHOLE_MIGRATION_ON_ONE_BORROWED_CONNECTION()
    val guard = late("pool test")
    val base = database()
    val fake = server(answering(base))
    val made = await pool({ host: "127.0.0.1", port: localPort(fake), user: "ada", password: "", database: "notes", min: 1, max: 2 })

    assert(made.ok)

    val p = made.value
    val r = await migrate(p, Three)

    assert(r.ok)
    assert(r.value.applied.length == 3)
    assert(base.rows.length == 3)

    val s = await migrationStatus(p, Three)

    assert(s.value.applied.length == 3)
    assert(p.size() == 1)

    await p.close()
    closeSocket(fake)
    clearTimeout(guard)

@test
async A_CONNECTION_INSIDE_A_TRANSACTION_IS_THE_PROGRAMS_OWN_MISTAKE()
    val guard = late("transaction test")
    val base = database()
    val m = await connectedTo(base)

    await m.db.query("begin")

    var said = ""

    try
        await migrate(m.db, Three)
    catch e
        said = string(e)

    assert(said.contains("outside a transaction"))

    m.db.close()
    closeSocket(m.fake)
    clearTimeout(guard)
