// The types this package exports, from the outside.
//
// **`Answer` and `Result` are what a program annotates against**, and a type nobody can name from
// another file is a type that does nothing. slate could not build a declaration on an imported type
// until 0.0.9, so `type Reported = { answer: Answer }` below is as much a check of the language as
// of this package -- and it is the reason the floor moved.

import { Answer, Result } from "../pg.sl"
import { Decimal, decimal } from "../decimal.sl"

// A declaration BUILT on an imported type, which is the shape a program's own vocabulary takes.
type Reported = { answer: Answer, at: string }

@test
AN_ANSWER_IS_ONE_SHAPE_WHETHER_IT_WORKED_OR_NOT()
    // **Only the fields that apply are ever there**, which is what the optional keys are for: a
    // refusal has no `value` at all, and reading one off it would be `undefined` -- which slate
    // refuses to carry anywhere.
    said(a: Answer) = if a.ok then "ok" else a.error

    assertEq(said({ ok: true, value: {} }), "ok")
    assertEq(said({ ok: false, error: "gone" }), "gone")
    assertEq(said({ ok: false, error: "taken", code: "23505", info: {} }), "taken")

    assert({ answer: { ok: true }, at: "now" } is Reported)

@test
A_RESULT_ALWAYS_HAS_ALL_FIVE_AND_A_STATEMENT_THAT_REPORTS_NOTHING_SAYS_null()
    // **`command` and `count` are `null` rather than absent** for an empty query or a `BEGIN`,
    // because a field that is there only sometimes is one every caller has to test for.
    val empty = { command: null, count: null, rows: [], values: [], fields: [] }

    assert(empty is Result)
    assert({ command: "SELECT", count: 1, rows: [{ n: 1 }], values: [[1]], fields: [] } is Result)

    // The error path, which is what says the two above are asking anything at all.
    assert(!({ rows: [], values: [], fields: [] } is Result))
    assert(!(empty is Answer))
    assert(!("ok" is Answer))

@test
A_DECIMAL_IS_NAMEABLE_FROM_OUTSIDE_pg_decimal_TOO()
    // `pg/decimal` is a subpath module because a class is a value AND a type under one name, and
    // `pg.sl` could have re-exported only the value half.
    total(a: Decimal, b: Decimal) -> Decimal = a + b

    assertEq(total(decimal("19.99"), decimal("1.60")).toFixed(2), "21.59")
