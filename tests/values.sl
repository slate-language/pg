// What a column comes back as, and what a parameter goes out as.

import { decoded, encoded, bytea, affected } from "../values.sl"
import { Decimal, decimal } from "../decimal.sl"

@test
A_COLUMN_WITH_NO_VALUE_IS_null_AND_NOT_THE_EMPTY_STRING()
    // **The two are different values and the wire format is careful about it too** -- a column with
    // nothing in it arrives as a length of -1 rather than a length of zero. A driver that lost the
    // difference turns a name nobody filled in into a name that is blank.
    assert(decoded(25, null) == null)
    assert(decoded(25, "") == "")
    assert(decoded(23, null) == null)

@test
THE_TYPES_A_PROGRAM_ACTUALLY_USES_COME_BACK_AS_VALUES()
    assert(decoded(16, "t") == true)
    assert(decoded(16, "f") == false)
    assert(decoded(21, "7") == 7)
    assert(decoded(23, "42") == 42)
    assert(decoded(20, "12345678901234") == 12345678901234)
    assert(decoded(700, "1.5") == 1.5)
    assert(decoded(701, "-0.25") == -0.25)
    assert(decoded(25, "hi") == "hi")
    assert(decoded(1043, "hi") == "hi")

@test
AN_INTEGER_COMES_BACK_WHOLE_AND_NOT_AS_A_REAL()
    // **`number` reads text as a number and slate tells whole ones apart**, so an `int4` that came
    // back as `42.0` would print the same and behave differently -- indexing, `%` and `is integer`
    // are all the places that would then be wrong.
    assert(decoded(23, "42") is integer)
    assert(decoded(701, "42") is real)

@test
A_NUMERIC_STAYS_TEXT_BECAUSE_A_DOUBLE_WOULD_LOSE_IT()
    // **This is the decision in this file most worth defending.** `numeric` is arbitrary precision --
    // it is what a money column is -- and slate's `real` is a double, so decoding it would quietly
    // round values the database went to trouble to keep exact. A program that wants arithmetic asks
    // for `::float8` and says so.
    assert(decoded(1700, "2.50") == "2.50")
    assert(decoded(1700, "0.1") == "0.1")
    assert(decoded(1700, "123456789012345678901234567890.123") == "123456789012345678901234567890.123")

@test
A_FLOAT_THAT_IS_NOT_A_NUMBER_IS_STILL_A_FLOAT()
    // `NaN`, `Infinity` and `-Infinity` are values a PostgreSQL float can hold and arrive spelled as
    // those words -- which slate reads, so they come back as the real things they are. **`NaN` is
    // not equal to itself**, which is what the second assertion is saying and is why the first one
    // asks the question the other way round.
    assert(decoded(701, "NaN") is real)
    assert(decoded(701, "NaN") != decoded(701, "NaN"))
    assert(decoded(701, "Infinity") is real)
    assert(decoded(701, "Infinity") > 0)
    assert(decoded(701, "-Infinity") < 0)

@test
JSON_IS_PARSED_AND_A_DOCUMENT_THAT_WILL_NOT_PARSE_STAYS_TEXT()
    val doc = decoded(3802, "{\"a\":[1,2],\"b\":null}")

    assert(doc.a[1] == 2)
    assert(doc.b == null)
    assert(decoded(114, "[1,2,3]")[0] == 1)
    assert(decoded(3802, "not json at all") == "not json at all")

@test
BYTEA_IS_BYTES_IN_BOTH_DIRECTIONS()
    // The hex form is what a modern server sends and what one takes back, so these are the two
    // halves of one round trip.
    assert(toJSON(decoded(17, "\\x00ff10")) == "[0,255,16]")
    assert(toJSON(decoded(17, "\\x")) == "[]")
    assert(bytea([0, 255, 16]) == "\\x00ff10")
    assert(bytea([]) == "\\x")

@test
A_DATE_AND_A_TIMESTAMP_BECOME_TEMPORAL_VALUES()
    // **PostgreSQL's ISO output is nearly ISO 8601 and differs in two places** -- a space where 8601
    // writes `T`, and an offset of `+00` where 8601 wants `+00:00`. That is what every default
    // installation produces, so it is not an edge case.
    assert(string(decoded(1082, "2026-09-01")) == "2026-09-01")
    assert(string(decoded(1083, "05:30:00")) == "05:30:00")
    assert(string(decoded(1114, "2026-09-01 05:30:00")) == "2026-09-01T05:30:00")
    assert(string(decoded(1184, "2026-09-01 05:30:00+00")) == "2026-09-01T05:30:00Z")
    assert(string(decoded(1184, "2026-09-01 05:30:00.123456+00")) == "2026-09-01T05:30:00.123456Z")

@test
A_TEMPORAL_VALUE_THAT_IS_NOT_ONE_KEEPS_ITS_TEXT()
    // `infinity`, `-infinity` and a date before the common era are all values a column may hold and
    // none of them is a slate `date`. Answering the text keeps the row rather than throwing it away
    // over a value the program may not even be reading.
    assert(decoded(1184, "infinity") == "infinity")
    assert(decoded(1082, "4713-01-01 BC") == "4713-01-01 BC")

@test
A_TYPE_THIS_DOES_NOT_KNOW_COMES_BACK_AS_THE_TEXT_THE_SERVER_SENT()
    // **The fallback is deliberately not an error.** PostgreSQL has hundreds of types and a program
    // may have defined its own, so a driver that refused what it did not recognise would be a wall
    // between a program and its own database.
    assert(decoded(869, "192.168.0.1/32") == "192.168.0.1/32")
    assert(decoded(2950, "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11") == "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
    assert(decoded(790, "$1.50") == "$1.50")

@test
AN_ARRAY_COLUMN_COMES_BACK_AS_AN_ARRAY()
    // **The quoting has to be read rather than stripped**, because a bare `NULL` is absence and a
    // quoted `"NULL"` is the four-letter word -- and an element with a comma in it is one element.
    assert(toJSON(decoded(1009, "{a,\"b,c\",NULL,\"NULL\"}")) == "[\"a\",\"b,c\",null,\"NULL\"]")
    assert(toJSON(decoded(1007, "{1,2,3}")) == "[1,2,3]")
    assert(toJSON(decoded(1000, "{t,f}")) == "[true,false]")
    assert(toJSON(decoded(1009, "{}")) == "[]")
    assert(toJSON(decoded(1009, "{\"say \\\"hi\\\"\"}")) == "[\"say \\\"hi\\\"\"]")

@test
AN_ARRAY_OF_ARRAYS_KEEPS_ITS_SHAPE()
    assert(toJSON(decoded(1007, "{{1,2},{3,4}}")) == "[[1,2],[3,4]]")
    assert(toJSON(decoded(1009, "{{a},{b}}")) == "[[\"a\"],[\"b\"]]")

@test
AN_ARRAY_WITH_SUBSCRIPTS_OF_ITS_OWN_KEEPS_ITS_TEXT()
    // **A dimension marker is not read**, and no program that did not create such an array will see
    // one. Half-understanding it would be worse than handing over what the server sent.
    assert(decoded(1007, "[0:2]={1,2,3}") == "[0:2]={1,2,3}")

@test
AN_ARRAY_ROUND_TRIPS_THROUGH_THE_LITERAL_THIS_WRITES()
    // The encoder and the decoder are two halves of one format, and this is the assertion that keeps
    // them together: what a parameter goes out as is what a column comes back from.
    for xs in [["a", "b"], ["a,b"], [null], ["NULL"], [], ["say \"hi\"", "back\\slash"]]
        assert(toJSON(decoded(1009, encoded(xs))) == toJSON(xs))

@test
A_PARAMETER_GOES_OUT_AS_TEXT_AND_null_GOES_OUT_AS_ABSENCE()
    assert(encoded(null) == null)
    assert(encoded("") == "")
    assert(encoded(true) == "t")
    assert(encoded(false) == "f")
    assert(encoded(42) == "42")
    assert(encoded(1.5) == "1.5")
    assert(encoded("it's") == "it's")

@test
AN_ARRAY_GOES_OUT_AS_AN_ARRAY_LITERAL_WITH_EVERY_ELEMENT_QUOTED()
    // **Quoting every element rather than only the ones that need it** removes the question: an
    // unquoted `NULL`, an empty element and an element with a comma in it are three traps in one
    // syntax, and `NULL` unquoted is the value rather than the word.
    assert(encoded(["a", "b"]) == "{\"a\",\"b\"}")
    assert(encoded(["a,b"]) == "{\"a,b\"}")
    assert(encoded([null]) == "{NULL}")
    assert(encoded(["NULL"]) == "{\"NULL\"}")
    assert(encoded([1, 2]) == "{\"1\",\"2\"}")
    assert(encoded([["a"], ["b"]]) == "{{\"a\"},{\"b\"}}")
    assert(encoded(["say \"hi\""]) == "{\"say \\\"hi\\\"\"}")

@test
AN_OBJECT_GOES_OUT_AS_JSON()
    assert(encoded({ a: 1, b: "x" }) == "{\"a\":1,\"b\":\"x\"}")

@test
A_numeric_COLUMN_IS_TEXT_UNLESS_THE_CONNECTION_ASKED_FOR_A_DECIMAL()
    // **Text is the default and loses nothing**, which is what node's `pg` answers for the same
    // reason: `numeric` is arbitrary precision and a double is not, so reading one as a number
    // would round values the database went to some trouble to keep exact.
    assert(decoded(1700, "19.99") == "19.99")
    assert(decoded(1700, "19.99") is string)

    // **`decimals` answers a `Decimal` instead**, which is exact AND does arithmetic. It is an
    // option rather than the default because it changes the type of a column.
    val d = decoded(1700, "19.99", true)

    assert(d is Decimal)
    assert(d == decimal("19.99"))
    assert(d.toFixed(2) == "19.99")

    // An array of them, which goes through the same arm one level down.
    val xs = decoded(1231, "{1.50,2.25}", true)

    assert(len(xs) == 2)
    assert(xs[0] == decimal("1.5"))

@test
A_numeric_A_DECIMAL_CANNOT_HOLD_KEEPS_ITS_TEXT()
    // **This file's rule for every value it cannot read, applied to one more type.** `NaN` is a
    // value a PostgreSQL `numeric` may hold and so is a number of two hundred digits; a value the
    // database has must not become a null it has not.
    assert(decoded(1700, "NaN", true) == "NaN")
    assert(decoded(1700, "1234567890123456789012.5", true) == "1234567890123456789012.5")

@test
A_DECIMAL_PARAMETER_GOES_OUT_AS_ITS_OWN_EXACT_TEXT()
    // **Before the object arm can turn it into JSON**, which is what an object parameter is. A
    // Decimal is a number that happens to be held as an object, and `numeric` is what it is for.
    assert(encoded(decimal("19.99")) == "19.99")
    assert(encoded(decimal("1.50")) == "1.5")
    assert(encoded([decimal("1.5"), decimal("2")]) == "{\"1.5\",\"2\"}")

@test
HOW_MANY_ROWS_A_COMMAND_TOUCHED_IS_THE_LAST_WORD_OF_ITS_TAG()
    // **`INSERT` writes an object id before its count and nothing else does**, which is the one
    // irregularity in the tag. Taking the second word rather than the last is right for every
    // command except the one people use most.
    assert(affected("INSERT 0 3") == 3)
    assert(affected("UPDATE 2") == 2)
    assert(affected("DELETE 0") == 0)
    assert(affected("SELECT 17") == 17)
    assert(affected("BEGIN") == null)
    assert(affected("") == null)
