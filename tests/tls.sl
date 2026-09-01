// TLS, which PostgreSQL negotiates in the clear before either end speaks it.
//
// **The whole negotiation is eight bytes out and one byte back**, and everything interesting about
// this client's TLS is what it does with that byte. So these talk to the same fake server the rest of
// the suite does, given a certificate or not, and what is under test is the client's decision rather
// than OpenSSL's handshake -- which `slate:net` has its own tests for.
//
// **The certificate is slate's own test pair**, generated once and committed. It names `localhost`
// and `127.0.0.1` and expires in a hundred years, so a suite that runs in ten years' time still runs.

import { pg } from "../pg.sl"
import { readFileSync } from slate:fs
import { close as closeSocket, localPort } from slate:net
import { server, authOk, describe, dataRow, commandComplete, readyFor, joined } from "./fake.sl"

val Guard = 3000

late(what) = setTimeout(() -> ranLong(what), Guard)

ranLong(what)
    throw "the " + what + " did not finish in time"

val TheCert = readFileSync("tests/tls/cert.pem").value
val TheKey = readFileSync("tests/tls/key.pem").value

// A server that answers a login and one row, and secures itself if it was given a certificate.
answering(seen)
    return (kind, r, sock) ->
        push(seen, kind)

        if kind == "startup" then return authOk()

        if kind == "Q"
            return joined([
                describe([{ name: "n", oid: 23 }]),
                dataRow(["1"]),
                commandComplete("SELECT 1"),
                readyFor("I"),
            ])

        null

@test
async A_CONNECTION_IS_UPGRADED_WHERE_THE_SERVER_SAYS_IT_WILL_SPEAK_TLS()
    // **The whole feature, end to end**: the request in the clear, the byte back, the handshake, and
    // then a startup packet and a query that the program cannot tell apart from an unencrypted one.
    val guard = late("upgrade test")

    var seen = []
    val fake = server(answering(seen), { cert: TheCert, key: TheKey })

    val made = await pg({
        host: "localhost",
        port: localPort(fake),
        user: "ada",
        password: "pencil",
        database: "notes",
        sslmode: "require",
        trust: TheCert,
    })

    assert(made.ok, "connecting over TLS: " + string(made.error ?? ""))

    val db = made.value
    val said = await db.query("select 1 as n")

    assert(said.ok)
    assert(len(said.value.rows) == 1)

    // The server was asked before it was spoken to, and only once.
    assert(seen[0] == "ssl")
    assert(seen[1] == "startup")

    db.close()
    closeSocket(fake)
    clearTimeout(guard)

@test
async require_REFUSES_A_SERVER_THAT_WILL_NOT_SPEAK_TLS()
    // **The point of `require` is that it stops rather than continues.** A client that fell back to
    // the clear here would be a deployment that believes it is encrypted and is not, which is worse
    // than one that fails to start.
    val guard = late("require test")

    var seen = []
    val fake = server(answering(seen))

    val made = await pg({
        host: "127.0.0.1",
        port: localPort(fake),
        user: "ada",
        database: "notes",
        sslmode: "require",
    })

    assert(!made.ok)
    assert(made.error.contains("`sslmode` is `require`"))
    assert(made.error.contains("will not speak TLS"))

    // It never got as far as a startup packet.
    assert(len(seen) == 1)
    assert(seen[0] == "ssl")

    closeSocket(fake)
    clearTimeout(guard)

@test
async prefer_ASKS_AND_CARRIES_ON_IN_THE_CLEAR_WHERE_THE_ANSWER_IS_NO()
    // **The default, and libpq's.** Every connection now asks; a server that says no is spoken to
    // exactly as it was before there was any TLS here at all.
    val guard = late("prefer test")

    var seen = []
    val fake = server(answering(seen))

    val made = await pg({ host: "127.0.0.1", port: localPort(fake), user: "ada", database: "notes" })

    assert(made.ok)
    assert(seen[0] == "ssl")
    assert(seen[1] == "startup")

    val db = made.value
    val said = await db.query("select 1 as n")

    assert(said.ok)
    db.close()
    closeSocket(fake)
    clearTimeout(guard)

@test
async disable_DOES_NOT_EVEN_ASK()
    // **`disable` is not "prefer, and take no for an answer".** It sends nothing at all, which is what
    // a server that would answer the question wrongly -- or a proxy that would choke on it -- needs.
    val guard = late("disable test")

    var seen = []
    val fake = server(answering(seen), { cert: TheCert, key: TheKey })

    val made = await pg({
        host: "127.0.0.1",
        port: localPort(fake),
        user: "ada",
        database: "notes",
        sslmode: "disable",
    })

    assert(made.ok)
    assert(seen[0] == "startup")

    db_close(made.value)
    closeSocket(fake)
    clearTimeout(guard)

db_close(db) = db.close()

@test
async A_CERTIFICATE_NOTHING_TRUSTS_STOPS_THE_CONNECTION_RATHER_THAN_DROPPING_TO_THE_CLEAR()
    // **libpq reconnects without TLS here and this does not.** Under `prefer`, a handshake that fails
    // after the server said `S` means the server offered a certificate that did not check out -- and
    // continuing unencrypted answers a question nobody asked. The program is told instead.
    val guard = late("untrusted test")

    var seen = []
    val fake = server(answering(seen), { cert: TheCert, key: TheKey })

    val made = await pg({
        host: "localhost",
        port: localPort(fake),
        user: "ada",
        database: "notes",
    })

    assert(!made.ok)
    assert(made.error.contains("certificate was not accepted"))

    closeSocket(fake)
    clearTimeout(guard)

// A connection URL, against a fake at whatever port it was given.
url(fake, tail) = "postgres://ada:pencil@127.0.0.1:" + string(localPort(fake)) + "/notes" + tail

@test
async A_URL_CARRIES_sslmode_AND_THE_PARAMETERS_BESIDE_IT_ARE_IGNORED()
    // **A provider's connection string has to work here unchanged.** `application_name` means nothing
    // to this driver and refusing it would make a URL that works with `psql` fail with slate -- while
    // the `sslmode` beside it has to be obeyed, which the refusal below is what proves.
    val guard = late("url test")

    var seen = []
    val fake = server(answering(seen))

    val made = await pg(url(fake, "?sslmode=require&application_name=web"))

    assert(!made.ok)
    assert(made.error.contains("`sslmode` is `require`"))

    closeSocket(fake)
    clearTimeout(guard)

@test
async A_URL_WITH_NO_QUERY_STRING_GETS_THE_DEFAULT_WHICH_IS_prefer()
    val guard = late("default test")

    var seen = []
    val fake = server(answering(seen))

    val made = await pg(url(fake, ""))

    assert(made.ok)
    assert(seen[0] == "ssl")

    db_close(made.value)
    closeSocket(fake)
    clearTimeout(guard)

@test
AN_sslmode_THIS_DOES_NOT_KNOW_IS_REFUSED_RATHER_THAN_TREATED_AS_THE_DEFAULT()
    // **A misspelling that quietly meant `prefer` is a connection a deployment believes is encrypted
    // and is not**, which is the one failure this whole feature exists to prevent.
    try
        pg("postgres://ada@127.0.0.1:1/notes?sslmode=requrie")
        assert(false, "a misspelled sslmode was accepted")
    catch e
        assert(string(e).contains("`sslmode` is one of"))

@test
async THE_MODES_THAT_COLLAPSE_BEHAVE_AS_WHAT_THEY_COLLAPSE_TO()
    // `verify-full` is `require` here, because slate's TLS has no way to encrypt without verifying --
    // so a deployment that already says `verify-full` gets what it asked for and is not refused for
    // spelling it that way. `allow` is `prefer`, which is a second connection libpq makes and this
    // does not.
    val guard = late("collapse test")

    var seen = []
    val strict = server(answering(seen))
    val refused = await pg(url(strict, "?sslmode=verify-full"))

    assert(!refused.ok)
    assert(refused.error.contains("`sslmode` is `require`"))

    closeSocket(strict)

    var alsoSeen = []
    val lax = server(answering(alsoSeen))
    val made = await pg(url(lax, "?sslmode=allow"))

    assert(made.ok)

    db_close(made.value)
    closeSocket(lax)
    clearTimeout(guard)
