// The whole surface in one program: connect, write, read, handle a refusal, and close.
//
//     slate examples/notes.sl
//
// It expects a PostgreSQL to talk to. `DATABASE_URL` if you have one, or the defaults, which are
// the same ones `psql` uses -- `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`.

import { pg } from "../pg.sl"
import { env } from slate:process

async main()
    val url = env("DATABASE_URL")
    val made = await pg(url ?? { })

    if !made.ok
        print("could not connect:", made.error)

        return

    val db = made.value

    print("connected to PostgreSQL", db.parameters().server_version)

    await db.query("create table if not exists notes (" +
        "id serial primary key, " +
        "title text not null unique, " +
        "body text, " +
        "tags text[], " +
        "written timestamptz not null default now())")

    await db.query("delete from notes")

    // **A parameter is never interpolated into the SQL.** The server parses the statement before it
    // is given a single value, so nothing a parameter contains can become part of the query -- which
    // is why the title below is stored rather than executed.
    val put = await db.query(
        "insert into notes (title, body, tags) values ($1, $2, $3), ($4, $5, $6)",
        ["first", "a note", ["ideas", "slate"],
         "'; drop table notes; --", "a title that is not SQL", ["ideas"]])

    print("wrote", put.value.count, "rows")

    val all = await db.query("select id, title, tags, written from notes order by id")

    for note in all.value.rows
        print(note.id, "|", note.title, "|", note.tags, "|", note.written)

    // A refusal is an ANSWER, not a fault: this is what a server turns into a `409`.
    val clash = await db.query("insert into notes (title) values ($1)", "first")

    print("")
    print("the second `first`:", clash.ok, clash.code)
    print(clash.error)

    // A transaction is SQL, because it already is.
    await db.query("begin")
    await db.query("update notes set body = $1 where title = $2", "changed", "first")
    await db.query("rollback")

    val after = await db.query("select body from notes where title = $1", "first")

    print("")
    print("after the rollback:", after.value.rows[0].body)

    await db.query("drop table notes")

    db.close()

main()
