// Migrations: a directory of numbered SQL files, applied in order, once each.
//
//     import { pg, migrate, rollback, migrationStatus } from pg
//
//     val db = (await pg(env("PG_URL"))).value
//     val r = await migrate(db, "migrations")
//
//     if !r.ok then print(r.error)
//
// ## The files
//
// **`NNNN_name.up.sql`, and beside it an optional `NNNN_name.down.sql`.** The number is the order and
// the identity: it is compared as a number, so `10_toys` comes after `2_pets` however the names sort as
// text, and it is what `schema_migrations` records. Anything in the directory that does not end in
// `.sql` is not looked at, so a README can live there. A `.sql` file that is not named that way, two
// files claiming one number, and a `.down.sql` with no `.up.sql` are all refused, naming the file --
// each is a directory that does not say what it means, and guessing would be applying something nobody
// decided to apply.
//
// ## What is recorded, and the one thing that is never done
//
// `schema_migrations(version, name, checksum, applied_at)`, made where it is absent. The checksum is
// the SHA-256 of the `.up.sql` as it was applied. **A migration that was applied and whose file has
// changed since is REFUSED, by name, before anything else runs.** Re-running it would apply a change
// twice; skipping it would leave a database that is not what the files describe while every report
// says it is. Neither is a thing a tool may decide on a person's behalf, so the answer is a sentence
// and the decision goes back to them.
//
// ## One transaction per migration, and one lock per run
//
// **Each migration runs in a transaction of its own, together with the row that records it**, so a
// migration that fails leaves nothing behind -- not half its statements, not its row -- and every
// migration after it is still pending. The ones before it stay applied, which is what one transaction
// each buys over one transaction for the run: a fix to the broken file starts from where it broke.
//
// **`pg_advisory_lock` is held for the whole run**, so two processes started at once -- two replicas of
// one deployment -- apply each migration once between them. The second waits for the first and then
// finds nothing left to do. The lock is taken BEFORE the table is made, because two
// `create table if not exists` racing each other is itself an error in PostgreSQL.
//
// A migration that cannot run inside a transaction -- `create index concurrently`, `alter type ... add
// value` before PostgreSQL 12 -- cannot be written here, and a file that says `commit` itself ends the
// transaction this runner opened.
//
// ## What answers and what throws
//
// **Everything read from the directory or the database answers**, `{ ok: true, value }` or
// `{ ok: false, error }`, since the files are text from outside the program exactly as a query's
// answer is. A failure carries what was done before it under `applied` or `reverted`, and a refusal
// from the server carries its `code` and `info` as `query` does. **A value the program built itself
// faults**: a `steps` that is not a positive count, or a connection left inside a transaction.
//
// ## A connection or a pool
//
// Either may be given. A pool is asked for one connection through `with` and the whole run happens on
// it, because the lock belongs to a session -- taken on one connection and released on another, it
// would be released nowhere.

import { readDir, readFile } from slate:fs
import { sha256 } from slate:crypto
import { regex } from slate:regex
import { hex } from "./auth.sl"

// The lock's key. **Any constant would do, so long as every runner uses the same one**; this one is
// the first four bytes of SHA-256("pg migrations") read as a number, so it is not a value another
// tool is likely to have picked by hand. It is a `bigint` key, `pg_advisory_lock`'s one-argument form.
val Lock = 3745687175

val Named = regex("^([0-9]+)_(.+)\\.(up|down)\\.sql$")

// `migrate(db, dir, options)` -- every pending migration applied, in order, or why not.
//
// `value.applied` lists what this run applied, `{ version, name, file }` each, and is empty where
// there was nothing to do. `options.lock` replaces the advisory lock's key, for a database that holds
// two independent sets of migrations.
export async migrate(db, dir: string, options: object = { })
    await onOne(db, (c) -> applying(c, dir, options.lock ?? Lock))

// `rollback(db, dir, { steps })` -- the last `steps` migrations undone, newest first, or why not.
//
// **Every one of them needs its `.down.sql`, and that is checked for all of them before any runs**, so
// a refusal leaves the database exactly as it was rather than half-way back. `value.reverted` lists
// what was undone. `steps` is 1 where it is not given, and more than were applied undoes all of them.
export async rollback(db, dir: string, options: object = { })
    val steps = options.steps ?? 1

    if !(steps is integer) || steps < 1
        throw "a rollback's `steps` is a count of at least 1, and this is " + string(steps)

    await onOne(db, (c) -> reverting(c, dir, steps, options.lock ?? Lock))

// `migrationStatus(db, dir)` -- where the database stands against the directory.
//
// `value.applied`, `value.pending` and `value.changed` are lists of `{ version, name, file }`;
// `changed` are applied migrations whose file is not what was applied, and they are in `applied` too.
// `value.missing` are versions the database has and the directory does not. Nothing is written, so
// a database that has never been migrated answers everything pending rather than gaining a table.
export async migrationStatus(db, dir: string)
    await onOne(db, (c) -> standing(c, dir))

// -- the runs ----------------------------------------------------------------------------------------

async applying(db, dir, key)
    val read = await planned(dir)

    if !read.ok then return { ok: false, error: read.error, applied: [] }

    await locked(db, key, () -> applyAll(db, read.value))

async applyAll(db, files)
    val made = await db.query("create table if not exists schema_migrations (version bigint primary key, name text not null, checksum text not null, applied_at timestamptz not null default now())")

    if !made.ok then return refused(made, "the table `schema_migrations` could not be made: ", [], "applied")

    val have = await recorded(db)

    if !have.ok then return refused(have, "`schema_migrations` could not be read: ", [], "applied")

    val drift = changedOf(files, have.value)

    if drift.length > 0 then return { ok: false, error: changedSentence(drift), applied: [] }

    val done = []

    for m in pendingOf(files, have.value)
        val ran = await inTransaction(db, m.up, m.file, "insert into schema_migrations (version, name, checksum) values ($1, $2, $3)", [m.version, m.name, m.checksum])

        if !ran.ok
            ran.applied = done

            return ran

        push(done, entry(m))

    { ok: true, value: { applied: done } }

async reverting(db, dir, steps, key)
    val read = await planned(dir)

    if !read.ok then return { ok: false, error: read.error, reverted: [] }

    await locked(db, key, () -> revertAll(db, read.value, steps))

async revertAll(db, files, steps)
    val have = await recorded(db)

    if !have.ok then return refused(have, "`schema_migrations` could not be read: ", [], "reverted")

    // Newest first, and only as many as were asked for.
    val newest = have.value.sorted((a, b) -> a.version > b.version)
    val chosen = newest.slice(0, steps)

    // **Every one is checked before any runs**, so a refusal changes nothing.
    val todo = []

    for row in chosen
        val m = byVersion(files, row.version)

        if m == null
            return { ok: false, error: "migration " + string(row.version) + " (" + row.name + ") is applied and has no file in this directory, so there is nothing to undo it with", reverted: [] }

        if m.checksum != row.checksum
            return { ok: false, error: changedSentence([m]), reverted: [] }

        if m.down == null
            return { ok: false, error: m.file + " has no " + downName(m) + ", so it cannot be rolled back", reverted: [] }

        push(todo, m)

    val done = []

    for m in todo
        val ran = await inTransaction(db, m.down, downName(m), "delete from schema_migrations where version = $1", [m.version])

        if !ran.ok
            ran.reverted = done

            return ran

        push(done, entry(m))

    { ok: true, value: { reverted: done } }

async standing(db, dir)
    val read = await planned(dir)

    if !read.ok then return read

    val files = read.value
    val there = await db.query("select to_regclass('schema_migrations')::text as t")

    if !there.ok then return refused(there, "`schema_migrations` could not be looked for: ", null, null)

    var rows = []

    if there.value.rows[0].t != null
        val have = await recorded(db)

        if !have.ok then return refused(have, "`schema_migrations` could not be read: ", null, null)

        rows = have.value

    val applied = []
    val missing = []

    for row in rows
        val m = byVersion(files, row.version)

        if m == null
            push(missing, { version: row.version, name: row.name })
        else
            push(applied, entry(m))

    {
        ok: true,
        value: {
            applied: applied,
            pending: pendingOf(files, rows).map(entry),
            changed: changedOf(files, rows).map(entry),
            missing: missing,
        },
    }

// -- the pieces --------------------------------------------------------------------------------------

// A connection to run on: the one given, or one borrowed from a pool for the whole of `f`.
async onOne(db, f)
    if has(db, "with")
        val got = await db.with(f)

        return if got.ok then got.value else got

    // **A connection already inside a transaction is the program's own state**, and running here
    // would commit whatever it had started at the first migration's `commit`.
    if has(db, "status") && db.status() != "I"
        throw "migrations need a connection outside a transaction, and this one is inside one"

    await f(db)

// `f` run while this session holds the advisory lock, which is released however `f` ends.
async locked(db, key, f)
    val took = await db.query("select pg_advisory_lock($1)", key)

    if !took.ok then return refused(took, "the migration lock could not be taken: ", [], null)

    var out = null

    try
        out = await f()
    catch e
        await db.query("select pg_advisory_unlock($1)", key)

        throw e

    await db.query("select pg_advisory_unlock($1)", key)

    out

// One file's SQL and the statement that records it, as one transaction.
async inTransaction(db, sql, file, record, params)
    val began = await db.query("begin")

    if !began.ok then return refused(began, file + " could not be started: ", null, null)

    val ran = await db.query(sql)

    if !ran.ok
        await db.query("rollback")

        return refused(ran, file + " failed, and nothing it did was kept: ", null, null)

    val noted = await db.query(record, ...params)

    if !noted.ok
        await db.query("rollback")

        return refused(noted, file + " ran but could not be recorded, so nothing it did was kept: ", null, null)

    val kept = await db.query("commit")

    if !kept.ok then return refused(kept, file + " could not be committed: ", null, null)

    { ok: true }

// A refusal from the server, with a sentence saying what was being done in front of its own.
refused(answer, what, done, key)
    val out = { ok: false, error: what + answer.error }

    if has(answer, "code") then out.code = answer.code
    if has(answer, "info") then out.info = answer.info
    if key != null then out[key] = done

    out

// What `schema_migrations` holds, oldest first.
async recorded(db)
    val r = await db.query("select version, name, checksum from schema_migrations order by version")

    if !r.ok then return r

    { ok: true, value: r.value.rows }

// The directory, read and checked: every migration in it, in order, with its SQL and its checksum.
async planned(dir)
    val listed = await readDir(dir)

    if !listed.ok then return { ok: false, error: "the migrations directory could not be read: " + listed.error }

    val ups = []
    val downs = []

    for file in listed.value.sorted((a, b) -> a < b)
        if !file.endsWith(".sql") then continue

        val m = Named.find(file)

        if m == null
            return { ok: false, error: file + " is not a migration's name -- one is NNNN_name.up.sql or NNNN_name.down.sql" }

        val one = { version: integer(number(m.groups[1])), name: m.groups[2], file: file }

        push(if m.groups[3] == "up" then ups else downs, one)

    for i in 0..<ups.length
        for j in (i + 1)..<ups.length
            if ups[i].version == ups[j].version
                return { ok: false, error: ups[i].file + " and " + ups[j].file + " are both migration " + string(ups[i].version) + ", and a number may be used once" }

    val out = []

    for u in ups
        val text = await readFile(dir + "/" + u.file)

        if !text.ok then return { ok: false, error: "could not read " + u.file + ": " + text.error }

        push(out, { version: u.version, name: u.name, file: u.file, up: text.value, down: null, checksum: hex(sha256(text.value)) })

    for d in downs
        var matched = null

        for m in out
            if m.version == d.version && m.name == d.name then matched = m

        if matched == null
            return { ok: false, error: d.file + " has no " + string(d.version) + "_" + d.name + ".up.sql beside it" }

        val text = await readFile(dir + "/" + d.file)

        if !text.ok then return { ok: false, error: "could not read " + d.file + ": " + text.error }

        matched.down = text.value

    { ok: true, value: out.sorted((a, b) -> a.version < b.version) }

pendingOf(files, rows)
    files.filter((m) -> !rows.some((r) -> r.version == m.version))

changedOf(files, rows)
    val out = []

    for row in rows
        val m = byVersion(files, row.version)

        if m != null && m.checksum != row.checksum then push(out, m)

    out

changedSentence(ms)
    val names = ms.map((m) -> m.file).join(", ")
    val one = ms.length == 1

    (if one then names + " was applied and has changed since" else names + " were applied and have changed since") + ", so nothing was run: put back what was applied, or write the change as a new migration"

byVersion(files, version)
    for m in files
        if m.version == version then return m

    null

downName(m) = m.file.replace(".up.sql", ".down.sql")

entry(m) = { version: m.version, name: m.name, file: m.file }
