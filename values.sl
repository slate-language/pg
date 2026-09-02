// What a column comes back as, and what a parameter goes out as.
//
// **Everything crosses in the protocol's TEXT format, in both directions, and that is a decision.**
// The binary format is faster and is what a driver reaches for once it is mature -- but it is a
// second encoding per type, it differs between server versions for some of them, and a client that
// asks for it must already know each column's type before it can read the row. Text is what `psql`
// sees, so a value that looks wrong here can be checked by typing the same query into a terminal.
//
// **A type this does not know about comes back as the string the server sent.** That is the whole
// fallback and it is deliberately not an error: PostgreSQL has hundreds of types and a program may
// have defined its own, so a driver that refused what it did not recognise would be a wall between a
// program and its own database. The text is never wrong -- it is what the server chose to send.
//
// **An array of a type this knows is an array**, element by element, and one of a type it does not
// is the literal. That follows from the fallback rather than being a second rule.

import { parseDate, parseTime, parseDateTime, parseTimestamp } from slate:time
import { Decimal, readDecimal } from "./decimal.sl"

// The type numbers this decodes into something other than text. They are `pg_type.oid`, stable since
// PostgreSQL 7 and the same on every installation, which is why they can be written down.
val Bool = 16
val Bytea = 17
val Int8 = 20
val Int2 = 21
val Int4 = 23
val Text = 25
val Json = 114
val Float4 = 700
val Float8 = 701
val Varchar = 1043
val Date = 1082
val Time = 1083
val Timestamp = 1114
val TimestampTz = 1184
val Numeric = 1700
val Jsonb = 3802

// One column's text as a slate value.
//
// **`null` is the absence of a value and is NOT the empty string**, which the wire format is careful
// about too: a column with no value arrives as a length of -1 rather than a length of zero. Losing
// that difference is how a driver turns a missing name into a name that is blank.
// **`decimals` is the one thing about a column a program gets to choose**, and it is off by default
// because turning it on changes what a `numeric` column IS. See the `Numeric` arm below.
export decoded(oid: integer, text: string | null, decimals: boolean = false)
    if text == null then return null

    if oid == Bool then return text == "t"

    if oid == Int2 || oid == Int4 || oid == Int8
        val n = number(text)

        return if n == null then text else integer(n)

    if oid == Float4 || oid == Float8
        // **`NaN`, `Infinity` and `-Infinity` are values a PostgreSQL float can hold**, and they
        // arrive spelled as those words -- which `number` reads, so they come back as the real
        // things they are rather than as text. Anything it cannot read at all keeps its text, since
        // a value the database has must not become a null it has not.
        val n = number(text)

        return if n == null then text else real(n)

    // **`numeric` stays TEXT unless the connection asked otherwise, and both halves are defended.**
    // It is an arbitrary-precision decimal -- which is what a money column is -- and slate's `real`
    // is a double, so reading one as a number would quietly round values the database went to some
    // trouble to keep exact. Text loses nothing and is what node's `pg` answers for the same reason.
    //
    // **`decimals: true` answers a `Decimal` instead**, which is exact AND does arithmetic --
    // `row.amount + row.tax` rather than `::float8` and a rounding. It is not the default because
    // it changes the type of a column: `toJSON(row)` renders an object where it used to render a
    // string, and `string(d)` is the object too. A program that turns it on writes `d.toFixed(2)`
    // where it used to write nothing, which is a trade it should make on purpose.
    //
    // **A `numeric` a Decimal cannot hold keeps its text**, which is this file's rule for every
    // value it cannot read: `NaN` is one a column may hold, and so is a number of two hundred
    // digits. A value the database has must not become a null it has not.
    if oid == Numeric
        if !decimals then return text

        return readDecimal(text) ?? text

    if oid == Json || oid == Jsonb
        val r = parseJSON(text)

        return if r.ok then r.value else text

    // `bytea` arrives as `\x` and hex, which is the modern output format.
    if oid == Bytea then return unhex(text)

    val element = elementOf(oid)

    if element != null then return asArray(text, element, decimals)

    if oid == Date then return temporal(parseDate(text), text)
    if oid == Time then return temporal(parseTime(text), text)
    if oid == Timestamp then return temporal(parseDateTime(isoish(text)), text)
    if oid == TimestampTz then return temporal(parseTimestamp(isoish(text)), text)

    text

// The element type of an array type, or nothing where this is not one.
//
// **An array type has an OID of its own for every element type there is**, and they are as stable as
// the element types are -- `text[]` is 1009 on every installation there has ever been. The list is
// the types this file decodes plus the ones a program is likely to have a column of; anything else
// keeps its literal, which is what an unknown type does everywhere here.
elementOf(oid: integer) -> integer | null
    if oid == 1000 then return Bool
    if oid == 1001 then return Bytea
    if oid == 1005 then return Int2
    if oid == 1007 then return Int4
    if oid == 1016 then return Int8
    if oid == 1009 then return Text
    if oid == 1015 then return Varchar
    if oid == 1021 then return Float4
    if oid == 1022 then return Float8
    if oid == 1231 then return Numeric
    if oid == 199 then return Json
    if oid == 3807 then return Jsonb
    if oid == 1182 then return Date
    if oid == 1183 then return Time
    if oid == 1115 then return Timestamp
    if oid == 1185 then return TimestampTz

    null

// `{1,2,3}` as an array, with every element decoded as the element type.
//
// **A quoted `"NULL"` is the four-letter word and a bare `NULL` is absence**, which is the whole
// reason the quoting has to be read rather than stripped -- and it is why the encoder here quotes
// every element it writes.
//
// **A dimension marker is not read.** A PostgreSQL array whose subscripts do not start at one is
// sent as `[0:2]={a,b,c}`, which no program that did not create such an array will ever see; the
// literal comes back as text rather than being half understood.
asArray(text, element, decimals)
    if !text.startsWith("{") then return text

    // An array of nothing, which is `{}` and never `{ }` -- and is the one case the loop below
    // would read as a single empty element.
    if text == "{}" then return []

    val out = []
    var i = 1
    var depth = 0

    // The elements of this level, each as the text between the separators.
    var piece = ""
    var quoted = false
    var wasQuoted = false
    var done = false

    while i < len(text) && !done
        val c = text[i]

        if quoted
            if c == "\\" && i + 1 < len(text)
                piece = piece + text[i + 1]
                i = i + 1
            elif c == "\""
                quoted = false
            else
                piece = piece + c
        elif c == "\""
            quoted = true
            wasQuoted = true
        elif c == "{"
            depth = depth + 1
            piece = piece + c
        elif c == "}" && depth > 0
            depth = depth - 1
            piece = piece + c
        elif (c == "," || c == "}") && depth == 0
            push(out, element_(piece, wasQuoted, element, decimals))

            piece = ""
            wasQuoted = false
            done = c == "}"
        else
            piece = piece + c

        i = i + 1

    out

element_(piece, wasQuoted, element, decimals)
    if !wasQuoted && piece == "NULL" then return null

    if !wasQuoted && piece.startsWith("{") then return asArray(piece, element, decimals)

    decoded(element, piece, decimals)

// A parsed temporal value, or the text where it could not be read.
//
// **`infinity`, `-infinity` and a date before the common era are all values a column may hold**, and
// none of them is a slate `date`. Answering the text keeps them rather than throwing away a row over
// a value the program may not even be looking at.
temporal(r, text) = if r.ok then r.value else text

// PostgreSQL's ISO output is nearly ISO 8601 and differs in two places, both fixed here.
//
// **A space where 8601 writes `T`, and an offset of `+00` where 8601 wants `+00:00`.** That is the
// `DateStyle = ISO` output every default installation produces, so this is not an edge case -- it is
// what every timestamp looks like.
isoish(text: string) -> string
    var out = text.replace(" ", "T")

    // An offset of `+HH` or `-HH` and nothing after it.
    val n = len(out)

    if n > 3
        val sign = out[n - 3]

        if (sign == "+" || sign == "-") && digits(out[(n - 2)..])
            out = out + ":00"

    out

digits(s: string) -> boolean
    if len(s) == 0 then return false

    for i in 0..<len(s)
        if "0123456789".indexOf(s[i]) == null then return false

    true

// `\x0001ff` as bytes.
unhex(text: string)
    val out = []

    if !text.startsWith("\\x") then return text

    var i = 2

    while i + 1 < len(text)
        val hi = "0123456789abcdef".indexOf(text[i].lower())
        val lo = "0123456789abcdef".indexOf(text[i + 1].lower())

        if hi == null || lo == null then return text

        push(out, (hi << 4) | lo)
        i = i + 2

    out

// -- parameters ---------------------------------------------------------------------------------------

// A slate value as the text a parameter travels as, or `null` for one that has none.
//
// **The type is left for the server to work out.** A parameter goes out with a type of zero, which
// asks PostgreSQL to infer it from where it is used -- so `where id = $1` reads the text as an
// integer and `where name = $1` reads the same text as a name. A client that guessed the type would
// be guessing at a query it did not parse.
export encoded(v)
    if v == null then return null

    if v is boolean then return if v then "t" else "f"

    if v is string then return v

    if v is number then return string(v)

    // **A Decimal goes out as its own exact text**, before the object arm below can turn it into
    // JSON: it is a number that happens to be held as an object, and `numeric` is what it is for.
    if v is Decimal then return v.text()

    // **An array is a PostgreSQL array literal, not bytes.** slate has one array type and a database
    // has both `int[]` and `bytea`, so this is the one place the two cannot both be guessed at:
    // `[1, 2, 3]` is an array of three numbers to everybody who writes it. `bytea(bs)` is how a
    // program says it meant bytes.
    if v is array then return literal(v)

    // An object is JSON, which is what a `json` or `jsonb` column takes.
    if v is object then return toJSON(v)

    // Everything else -- a date, a time, a timestamp, a duration -- renders as it prints, which is
    // ISO 8601, which is what PostgreSQL reads.
    string(v)

// `{"a","b"}`, with every element quoted and the two characters that matter escaped.
//
// **Quoting every element rather than only the ones that need it** costs nothing and removes the
// question: an unquoted `NULL`, an empty element, and an element with a comma in it are three
// different traps in one syntax.
literal(xs: array) -> string
    var out = "{"

    for i in 0..<len(xs)
        if i > 0 then out = out + ","

        val x = xs[i]

        if x == null
            out = out + "NULL"
        elif x is array
            out = out + literal(x)
        else
            out = out + "\"" + escaped(encoded(x)) + "\""

    out + "}"

escaped(s: string) -> string
    var out = ""

    for i in 0..<len(s)
        val c = s[i]

        out = out + (if c == "\"" || c == "\\" then "\\" + c else c)

    out

// Bytes as the text a `bytea` parameter takes.
//
// **This is what a program writes to say it meant bytes**, since an array of small numbers is an
// array of numbers to everybody who reads it and there is no second type to tell them apart by.
export bytea(bs: array) -> string
    var out = "\\x"

    for b in bs
        out = out + "0123456789abcdef"[b >> 4] + "0123456789abcdef"[b & 15]

    out

// -- what a command reports -----------------------------------------------------------------------

// How many rows a command touched, out of its `CommandComplete` tag.
//
// **`INSERT` writes an object id before its count and every other command does not**, which is the
// one irregularity in the tag: `INSERT 0 3`, `UPDATE 3`, `DELETE 3`, `SELECT 3`. Taking the last
// word rather than the second is what handles both.
export affected(tag: string) -> integer | null
    val parts = tag.split(" ")

    if len(parts) < 2 then return null

    val n = number(parts[len(parts) - 1])

    if n == null then null else integer(n)
