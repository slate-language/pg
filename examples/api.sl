// A JSON API over a database, which is what this package is for.
//
//     DATABASE_URL=postgres://... slate examples/api.sl
//
// **Every handler here awaits the database and none of them stops the server.** That is the whole
// argument for a client written on the loop: the query is a promise, so the request that is waiting
// for PostgreSQL is the only one waiting.

import { pg } from "../pg.sl"
import { serve, close, router } from slate:http
import { env } from slate:process

async main()
    val made = await pg(env("DATABASE_URL") ?? { })

    if !made.ok
        print("could not connect:", made.error)

        return

    val db = made.value

    await db.query("create table if not exists notes (" +
        "id serial primary key, title text not null unique, body text)")

    await db.query("delete from notes")

    val app = router()

    app.get("/notes", (req) ->
        answer(db.query("select id, title, body from notes order by id")))

    app.get("/notes/:id", (req) ->
        answer(one(db, req.params.id)))

    // **A constraint violation is an ANSWER, so this is a `409` rather than a crash.** That is the
    // reason a query answers a result: a server has something to say about a duplicate title, and
    // falling over is not it.
    app.post("/notes", async (req) ->
        val body = parseJSON(req.body)

        if !body.ok then return { status: 400, body: "that is not JSON" }

        val put = await db.query(
            "insert into notes (title, body) values ($1, $2) returning id, title, body",
            [body.value.title, body.value.body])

        if !put.ok
            return {
                status: if put.code == "23505" then 409 else 500,
                headers: { "Content-Type": "application/json" },
                body: toJSON({ error: put.error, code: put.code }),
            }

        { status: 201,
          headers: { "Content-Type": "application/json" },
          body: toJSON(put.value.rows[0]) })

    app.delete("/notes/:id", async (req) ->
        val gone = await db.query("delete from notes where id = $1", [req.params.id])

        if gone.value.count == 0 then { status: 404, body: "no such note" } else { status: 204 })

    val server = serve(8099, app)

    print("listening on 8099")

    // What a client would do, so that running this program shows something.
    val first = await fetch("http://127.0.0.1:8099/notes",
        { method: "POST", body: toJSON({ title: "first", body: "a note" }) })

    print(first.value.status, first.value.body)

    val again = await fetch("http://127.0.0.1:8099/notes",
        { method: "POST", body: toJSON({ title: "first", body: "the same title" }) })

    print(again.value.status, again.value.body)

    val all = await fetch("http://127.0.0.1:8099/notes")

    print(all.value.status, all.value.body)

    await db.query("drop table notes")

    db.close()
    close(server)

// A result as a JSON response, which is the same three lines in every handler.
async answer(query)
    val said = await query

    if !said.ok then return { status: 500, body: said.error }

    if len(said.value.rows) == 0 then return { status: 404, body: "nothing there" }

    { headers: { "Content-Type": "application/json" }, body: toJSON(said.value.rows) }

one(db, id) = db.query("select id, title, body from notes where id = $1", [id])

main()
