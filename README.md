# pg — PostgreSQL for slate

A PostgreSQL client written in slate, speaking the wire protocol itself. No libpq, no C binding, no
blocking call: it is `slate:net` and `slate:crypto` and about a thousand lines of slate.

```
slate add github.com/slate-language/pg
```

**It needs slate 0.0.6 or later.** 0.0.4 carried `slate:crypto` — a package cannot have a native of
its own, so SHA-256, HMAC, PBKDF2 and a nonce from the kernel all had to arrive in the language before
a client could log in to a modern PostgreSQL at all; 0.0.5 carries the two things TLS needs,
`startTls`, which upgrades an open socket, and a `connect` that takes a name rather than only an
address; and 0.0.6 carries `md5`, which an older server's login asks for and which this package used
to write out in slate.

**0.3.0 needs 0.0.9.** 0.0.8's rest parameters are what let `query` take its parameters as arguments
and its operator hooks are what let a `Decimal` answer for `+`; 0.0.9 is what the exported types
need — a `type` declaration could not name one imported from another file before it.

```
import { pg, Answer, Result } from pg
import { decimal, Decimal } from pg/decimal

// What a query answers, and what a program's own vocabulary is built on.
reported(a: Answer) -> string = if a.ok then string(len(a.value.rows)) + " rows" else a.error
```

**`Answer` has every field but `ok` optional**, which is the honest shape: a refusal has no `value`
at all, and reading one off it would be `undefined` — which slate refuses to carry anywhere.

```
import { pg } from pg

async main()
    val db = (await pg("postgres://ada@127.0.0.1/notes")).value
    val r = await db.query("select id, title from notes where author = $1", "ada")

    for row in r.value.rows
        print(row.id, row.title)

    db.close()

main()
```

## The client is on the loop, and that is the point

**A database call in a server must not stop the server.** Every query here is a promise on the same
event loop that is answering HTTP, so a handler waiting for PostgreSQL is the only thing waiting.
Binding libpq would have made that impossible rather than merely difficult — `PQexec` blocks, and a
blocking call on this loop stops the whole program.

## Connecting

`pg` takes a URL, an object, or nothing at all.

```
val db = (await pg("postgres://ada:secret@db.internal:5432/notes")).value
val db = (await pg({ host: "127.0.0.1", user: "ada", database: "notes", password: "secret" })).value
val db = (await pg({ })).value
```

With nothing given it reads what `psql` reads — `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`,
`PGDATABASE` — and falls back to `127.0.0.1`, `5432`, `$USER`, and a database named after the user.
So a program that takes none of them still connects wherever `psql` does.

**It answers a result rather than throwing**, which is slate's rule for anything that reaches the
network: a database that is not up, a password that is wrong and a role that does not exist are all
things a program handles.

```
val made = await pg(env("DATABASE_URL"))

if !made.ok then print("no database:", made.error)
```

### Logging in

**SCRAM-SHA-256, MD5 and cleartext**, and the first is the one that matters: PostgreSQL 14 and later
configure it by default, so a client without it cannot log in to a current server at all.

The exchange is RFC 7677's, checked in both directions — this client verifies the server's signature
as well as sending its own proof, so a server that cannot prove it knew the password is refused
rather than trusted.

## TLS

**PostgreSQL negotiates TLS rather than assuming it**, and that is why a secure `connect` would not
have done: a connection begins in the clear, sends eight bytes asking, and reads a single byte back —
`S` for yes, `N` for no. Only then does the handshake start. `sslmode` is libpq's, spelled the same
way, in an option or in the URL a provider hands out:

```
val db = await pg({ host: "db.example.com", sslmode: "require", trust: authority })
val db = await pg("postgres://user:secret@db.example.com/app?sslmode=require")
```

| mode | what happens |
|---|---|
| `disable` | nothing is sent; the connection is in the clear |
| `allow`, `prefer` | asks; a server that says no is spoken to in the clear |
| `require`, `verify-ca`, `verify-full` | asks; a server that says no is refused |

**`prefer` is the default**, which is libpq's. Every connection asks, and a server that will not speak
TLS is spoken to exactly as it was before.

**`require` verifies fully, which libpq's `require` does not.** libpq encrypts without checking who it
is talking to unless told `verify-full`; slate's TLS offers no way to skip verification, so the three
strict modes are one behaviour here. **The `host` is what the certificate is checked against**, which
is why it is a name and not an address — an address works too and is checked against the certificate's
addresses, but a hosted database is reached by name. A private authority is named with `trust`, as PEM
text, which is *added* to the machine's own store rather than put in place of it.

**A handshake that fails is not retried in the clear.** libpq drops to an unencrypted connection under
`prefer` when TLS fails after the server said `S`; a certificate that does not check out is a reason
to stop rather than a reason to continue quietly.

## Querying

```
val r = await db.query("select id, title from notes")
val r = await db.query("select * from notes where id = $1", 7)
val r = await db.query("select * from notes where id = any($1)", ids)
```

**The parameters are the arguments after the SQL**, and a list a program worked out is spread:
`db.query(sql, ...values)`. An array parameter is then an ordinary one — `$1::text[]` is given
`["a", "b"]` and nothing has to be wrapped twice.

**Parameters decide which protocol is spoken.** No parameters is a simple `Query`, which may hold
several statements; any parameters is `Parse`/`Bind`/`Execute`, which may hold one. That is not an
optimisation — a simple query cannot carry a parameter at all.

**A parameter is never interpolated into the SQL.** The server parses the statement before it is
given a single value, so nothing a parameter contains can become part of the query. `$1` is the
whole of the defence against injection and there is no escaping function here because there is
nothing to escape.

A query answers a result:

```
{ ok: true, value: { rows, values, fields, command, count, results } }
{ ok: false, error: "...", code: "23505", info: { ... } }
```

| | |
|---|---|
| `rows` | an array of objects, keyed by column name |
| `values` | the same rows as arrays, for a query with two columns of one name |
| `fields` | `{ name, oid }` per column |
| `command` | `"SELECT"`, `"INSERT"`, `"UPDATE"` … |
| `count` | how many rows it touched, or `null` |
| `results` | one entry per statement, for a simple query holding several |

**A refusal is an answer and not a fault**, because a unique violation, a syntax error and a table
that is not there are all things a server wants to turn into a status code:

```
val put = await db.query("insert into notes (title) values ($1)", title)

if !put.ok && put.code == "23505" then return { status: 409, body: "that title is taken" }
```

`code` is the SQLSTATE and `info` carries the whole `ErrorResponse` with its fields named —
`severity`, `detail`, `hint`, `table`, `column`, `constraint`, `position` and the rest.

**Calling `query` on a connection that is closed throws**, because that is the program's own mistake
rather than the database's answer. slate's two channels, used the way slate uses them.

## Pipelining is what happens when you do not await

Answers come back in the order the queries were written, which is the protocol's own guarantee — so
issuing several and awaiting them afterwards costs one round trip rather than several.

```
val a = db.query("select count(*) from notes")
val b = db.query("select count(*) from authors")

print((await a).value.rows[0].count, (await b).value.rows[0].count)
```

## Types

Everything crosses in the protocol's text format, in both directions. What comes back:

| PostgreSQL | slate |
|---|---|
| `bool` | `true` / `false` |
| `int2`, `int4`, `int8` | an integer |
| `float4`, `float8` | a real — `NaN` and `Infinity` included |
| `numeric` | **text**, because a double would round it |
| `text`, `varchar`, `char`, and anything unrecognised | text |
| `json`, `jsonb` | the parsed value |
| `bytea` | an array of bytes |
| `date`, `time`, `timestamp`, `timestamptz` | a slate temporal value |
| any array of the above | an array |
| `null` | `null`, which is never the empty string |

**A type this does not know comes back as the text the server sent**, which is never wrong — it is
what the server chose to send. PostgreSQL has hundreds of types and a program may have defined its
own, so refusing what it did not recognise would be a wall between a program and its own database.

**`numeric` staying text is the decision here worth defending.** It is an arbitrary-precision decimal
— it is what a money column is — and slate's `real` is a double. A program that wants arithmetic asks
for `::float8` and says so.

Going out: text as itself, numbers as numbers, `true` as `t`, `null` as absence (which is not the
empty string), an object as JSON, and an array as a PostgreSQL array literal. **For `bytea`, say so
with `bytea(bs)`** — slate has one array type and a database has both `int[]` and `bytea`, so that is
the one place the two cannot both be guessed at.

```
import { pg, bytea } from pg

await db.query("insert into files (name, body) values ($1, $2)", "a.png", bytea(bs))
```

## `numeric`, and the exact decimal beside it

**A `numeric` column comes back as TEXT by default**, and that loses nothing: it is an
arbitrary-precision decimal — which is what a money column is — and slate's `real` is a double, so
reading one as a number would quietly round values the database went to some trouble to keep exact.
node's `pg` answers a string for the same reason.

**What text cannot do is arithmetic**, so there is a `Decimal`:

```
import { decimal, Decimal } from pg/decimal

val total = decimal("19.99") + decimal("1.60")     // 21.59, exactly

print(total.toFixed(2))
```

It answers for `+`, `-`, `*`, `/`, `%`, unary `-` and the four orderings. A value is scaled integer
units, so every one of those is exact — **except `/`**, which keeps six places by default and
`divided(b, n)` where a program wants to say. A whole number mixes (`total + 1`); **a real is
refused**, because 0.1 is not 0.1 in a double and accepting one would put back the rounding this
type exists to keep out.

**A connection may be told to hand `numeric` columns over as Decimals**, which is the one option
that changes what a column *is*:

```
val db = (await pg({ ..., decimals: true })).value
val r = await db.query("select price, tax from sales")

print((r.value.rows[0].price + r.value.rows[0].tax).toFixed(2))
```

It is off by default because of what it costs: `toJSON(row)` renders an object where it used to
render a string, and `string(d)` is the object too — slate has no way for a class to say how it
prints. A program that turns it on writes `d.toFixed(2)` where it wrote nothing before.

**Eighteen significant digits is the ceiling**, and going past it is a fault rather than a wrap: a
slate integer is 64 bits and wraps, which is the one thing a money type may not do quietly. A
`numeric` a Decimal cannot hold — `NaN`, or two hundred digits — keeps its text, which is what every
value this driver cannot read already does.

## The rest of the connection

```
db.close()                      // and every query still waiting is answered
db.status()                     // "I" idle, "T" in a transaction, "E" in a failed one
db.parameters()                 // server_version, TimeZone, client_encoding, …
db.onNotice((n) -> ...)         // `raise notice`, and anything else the server says
db.onNotify((n) -> ...)         // `listen` / `notify`: { channel, payload, pid }
```

**A transaction is SQL, because it already is** — `begin`, `commit`, `rollback` and a savepoint are
statements, and `status()` is how a program asks where it stands.

**When a connection goes, every query waiting on it is settled with a result** rather than left. A
program awaiting an answer that will never come would otherwise wait for the rest of the run, which
in a server is a request that never finishes.

## What is not here

- **COPY**, which is refused with a sentence rather than left to desynchronise the connection.
- **Cursors**, `LISTEN` beyond delivering the notification, and named prepared statements.
- **A connection pool.** A pool is a program's own arrangement over several connections and needs
  nothing from the protocol; what it needs from a driver is that a connection is one object with a
  `close`, which is what this is.

## Tests

```
slate test tests
```

**Every test talks to a PostgreSQL server written in slate** — the fake under `tests/fake.sl` — whose
replies are written out longhand from the message formats. So what passes is this client agreeing
with the *protocol* rather than with whichever database happens to be installed, and the suite needs
no server. The SCRAM test goes further and does the server's half of the exchange, checking the
client's proof the way PostgreSQL would.

`check/live.sl` is the other half of that bargain: the same ground against a real PostgreSQL 16 over
SCRAM-SHA-256, run by hand, because a fixture cannot prove the two halves fit together.

## Licence

ISC. See `LICENSE`.
