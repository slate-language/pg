// An exact decimal, for the one column type a double cannot hold.
//
// **`numeric` is why this exists.** It is an arbitrary-precision decimal -- which is what a money
// column is -- and slate's `real` is a double, so reading one as a number quietly rounds values the
// database went to some trouble to keep exact. `values.sl` said so and left `numeric` as text, and
// the honest cost of that was arithmetic: a program that wanted to add two amounts asked for
// `::float8` and accepted the rounding, or added the strings by hand.
//
// **What changed is that a slate class can answer for an operator.** `plus`, `minus`, `times`,
// `dividedBy`, `remainder`, `negated` and `compare` are methods here, so `a + b`, `a < b` and `-a`
// are ordinary slate written against ordinary values -- and every one of them is exact.
//
//     val total = decimal("19.99") + decimal("1.60")     // 21.59, not 21.589999999999996
//
// **A value is scaled INTEGER units**, so 1.50 is 15 units at a scale of 1. Everything below is
// integer arithmetic on those units, which is what makes it exact; what it is not is arbitrary
// precision, since the units are a slate integer and a slate integer is 64 bits. Eighteen
// significant digits is the ceiling and it is a fault rather than a wrap -- see `checkedTimes`.
//
// **This is `pg`'s and not the language's, for now.** It is here because `numeric` is here; nothing
// about it is specific to PostgreSQL, and if a second package ever wants one it should move out
// whole rather than be copied.

// The largest magnitude the scaled units may reach, which is a slate integer's own ceiling.
//
// **slate's integer WRAPS**, so an unchecked multiplication would answer a number that is wrong and
// looks perfectly ordinary. That is the one thing a money type may not do, so every product and
// every sum here is checked.
val MaxDigits = 18

// How many digits `/` keeps where the division does not come out exactly.
//
// **Division is the one operation here that is not exact**, because most of them are not: 1/3 has
// no decimal form at any scale. Six digits is the default and `divided(b, n)` is how a program says
// what it actually wants.
val DivisionDigits = 6

export class Decimal
    // `units` is the value multiplied by ten to the `scale`, and both are whole numbers.
    //
    // **Normalised here, and it has to be**: slate compares two objects by their fields and a class
    // cannot write its own `equals`, so 1.50 and 1.5 would be different values unless the trailing
    // zeros come off. What the database sent is a rendering; what this holds is the number, and
    // `toFixed` is how a program asks for the rendering back.
    new(var units, var scale)
        if !(self.units is integer)
            throw "a Decimal is made of whole scaled units, and this is " + string(self.units)

        if !(self.scale is integer) || self.scale < 0
            throw "a Decimal's scale is a count of digits after the point, and this is " + string(self.scale)

        while self.scale > 0 && self.units % 10 == 0
            self.units = self.units / 10
            self.scale = self.scale - 1

        if self.units == 0 then self.scale = 0

    // `a + b` and `a - b`, at the wider of the two scales, which loses nothing.
    plus(self, o) = combined(self, o, 1)
    minus(self, o) = combined(self, o, 0 - 1)

    // `a * b`. **The scales add**, which is the whole of decimal multiplication: two amounts to two
    // places make a product to four, and rounding it back is the program's decision rather than
    // this type's.
    times(self, o)
        val b = asDecimal(o)

        Decimal(checkedTimes(self.units, b.units), self.scale + b.scale)

    // `a / b`, to `DivisionDigits` places, rounded half away from zero.
    dividedBy(self, o) = self.divided(o, DivisionDigits)

    // The same division with the scale said out loud, which is what a program that cares writes.
    divided(self, o, digits: integer)
        val b = asDecimal(o)

        if b.units == 0 then throw "this Decimal was divided by zero"
        if digits < 0 || digits > MaxDigits then throw "a Decimal division keeps 0 to 18 digits, and this asked for " + string(digits)

        // One digit past what is wanted, so that the last one can be rounded rather than dropped.
        val shift = digits + 1 + b.scale - self.scale
        val top = if shift >= 0 then checkedTimes(self.units, pow10(shift)) else self.units / pow10(0 - shift)

        Decimal(rounded(top / b.units), digits)

    // `a % b`, exactly, at the wider of the two scales.
    remainder(self, o)
        val b = asDecimal(o)

        if b.units == 0 then throw "this Decimal was divided by zero"

        val s = wider(self, b)

        Decimal(at(self, s) % at(b, s), s)

    // `-a`.
    negated(self) = Decimal(0 - self.units, self.scale)

    // What `<`, `<=`, `>` and `>=` all read. **One hook and four operators**, so a Decimal cannot
    // order inconsistently with itself.
    compare(self, o)
        val b = asDecimal(o)
        val s = wider(self, b)
        val x = at(self, s)
        val y = at(b, s)

        if x < y then 0 - 1 elif x > y then 1 else 0

    // The number as text, at the scale it is held to. `decimal("1.50").text()` is `"1.5"`.
    //
    // **`string(d)` is NOT this.** slate renders an object as its fields and there is no hook for a
    // class to say otherwise, so a Decimal put in a message, a log line or a JSON document goes
    // through `text()` or `toFixed`. That is the one rough edge of holding a number as an object.
    text(self) = rendered(self.units, self.scale)

    // The number as text with exactly `n` digits after the point, rounded half away from zero.
    // This is what a money column is printed with -- `total.toFixed(2)` is `"21.59"`.
    toFixed(self, n: integer)
        if n < 0 || n > MaxDigits then throw "a Decimal is rendered to 0 to 18 places, and this asked for " + string(n)

        rendered(rescaled(self, n), n)

    // The value as a slate `real`. **Lossy on purpose and named so that it is asked for**, which is
    // the whole difference between this and reading the column as a `float8`.
    number(self) = real(self.units) / real(pow10(self.scale))

    isZero(self) = self.units == 0

    // -1, 0 or 1.
    sign(self) = if self.units < 0 then 0 - 1 elif self.units > 0 then 1 else 0

// `decimal("19.99")`, `decimal(7)`, and a Decimal unchanged.
//
// **A real is REFUSED rather than converted**, and the message says why: 0.1 is not 0.1 in a double,
// so accepting one would put back exactly the rounding this type exists to keep out.
export decimal(v)
    if v is Decimal then return v
    if v is integer then return Decimal(v, 0)

    if v is real
        throw "a real is not exact, so it is not a Decimal -- decimal(\"0.1\") is, where 0.1 is not"

    if v is string
        val r = read(v)

        // **The two ways text can fail are two sentences**, because they send a reader to different
        // places: one is a value that is not a number and the other is a number this cannot hold.
        if !r.ok then throw r.error

        return r.value

    throw "`decimal` takes decimal text, a whole number, or a Decimal, and this is " + string(v)

// The same, answering `null` for anything that does not read as one.
//
// **A result rather than a fault, because this is what reads a COLUMN.** `NaN` is a value a
// PostgreSQL `numeric` may hold, and so is a number of two hundred digits; neither is a Decimal and
// neither is a defect in the program looking at it. `values.sl` keeps the server's own text for
// those, which is what it already does for every value it cannot read.
export readDecimal(text)
    val r = read(text)

    if r.ok then r.value else null

// The reading itself, which answers WHY it could not rather than only that it could not.
read(text)
    if !(text is string) then return { ok: false, error: "a decimal is read from text, and this is " + string(text) }

    val s = trim(text)

    if len(s) == 0 then return no(s)

    var i = 0
    var neg = false

    if s[0] == "-" || s[0] == "+"
        neg = s[0] == "-"
        i = 1

    var whole = ""
    var frac = ""
    var seen = false

    while i < len(s) && isDigit(s[i])
        whole = whole + s[i]
        seen = true
        i = i + 1

    if i < len(s) && s[i] == "."
        i = i + 1

        while i < len(s) && isDigit(s[i])
            frac = frac + s[i]
            seen = true
            i = i + 1

    // **Anything left over is not a number**, which is what refuses `1.2.3`, `NaN`, `1e10` and the
    // two hundred digits of an exponent PostgreSQL writes for a very small `numeric`.
    if !seen || i != len(s) then return no(s)

    while len(whole) > 1 && whole[0] == "0"
        whole = whole[1..]

    val digits = (if whole == "0" then "" else whole) + frac

    if len(digits) > MaxDigits
        return { ok: false, error: "a Decimal holds 18 significant digits and " + s + " has " + string(len(digits)) }

    val n = number(if digits == "" then "0" else digits)

    if n == null then return no(s)

    { ok: true, value: Decimal(if neg then 0 - integer(n) else integer(n), len(frac)) }

no(s) = { ok: false, error: "this does not read as a decimal number: " + toJSON(s) }

// -- the arithmetic underneath ------------------------------------------------------------------------

// The other operand as a Decimal, for an operator whose left side is one.
//
// **A whole number is taken and a real is not**, which is the same line `decimal` draws: `total + 1`
// is exact and `total + 1.5` cannot be. `decimal("1.5")` is what that program writes.
asDecimal(v)
    if v is Decimal then return v
    if v is integer then return Decimal(v, 0)

    if v is real
        throw "a Decimal and a real do not mix -- decimal(\"0.1\") is exact where 0.1 is not"

    if v is string then return decimal(v)

    throw "a Decimal combines with a Decimal, a whole number or decimal text, and this is " + string(v)

combined(a, o, sign)
    val b = asDecimal(o)
    val s = wider(a, b)

    Decimal(checkedPlus(at(a, s), sign * at(b, s)), s)

wider(a, b) = if a.scale > b.scale then a.scale else b.scale

// This value's units read at a scale at least as large as its own.
at(d, scale) = checkedTimes(d.units, pow10(scale - d.scale))

// Ten to the `n`.
pow10(n)
    if n < 0 || n > MaxDigits
        throw "a Decimal holds at most 18 digits after the point, and this needed " + string(n)

    var out = 1

    for i in 0..<n
        out = out * 10

    out

// `a * b`, faulting rather than wrapping.
//
// **The check is a division back**, which is the standard one: where the product wrapped, dividing
// it by one operand does not give the other. Without it a total could come back negative and look
// like a number somebody meant.
checkedTimes(a, b)
    if a == 0 || b == 0 then return 0

    val out = a * b

    if out / b != a then throw "this Decimal is too large to hold -- 18 significant digits is the ceiling"

    out

// `a + b`, faulting rather than wrapping. Two numbers of one sign whose sum has the other sign is
// the whole of the test, there being no other way for an addition to leave 64 bits.
checkedPlus(a, b)
    val out = a + b

    if (a > 0 && b > 0 && out < 0) || (a < 0 && b < 0 && out > 0)
        throw "this Decimal is too large to hold -- 18 significant digits is the ceiling"

    out

// One digit too many, rounded away half up. `125` is `13` and `-125` is `-13`.
rounded(tenths)
    if tenths < 0 then return 0 - ((0 - tenths + 5) / 10)

    (tenths + 5) / 10

// This value's units at exactly `n` places, rounding where that is fewer than it has.
rescaled(d, n)
    if n >= d.scale then return at(d, n)

    var out = d.units
    var over = d.scale - n

    // Down to one digit past what is wanted, then round that one away.
    while over > 1
        out = out / 10
        over = over - 1

    rounded(out)

// Scaled units as the text of a number.
rendered(units, scale)
    val neg = units < 0
    var body = string(if neg then 0 - units else units)

    while len(body) <= scale
        body = "0" + body

    val cut = len(body) - scale
    val whole = body[0..<cut]

    (if neg then "-" else "") + whole + (if scale > 0 then "." + body[cut..] else "")

isDigit(c) = "0123456789".indexOf(c) != null
