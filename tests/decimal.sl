// The exact decimal, which is what `numeric` needs and what a double cannot be.

import { Decimal, decimal, readDecimal } from "../decimal.sl"

@test
AN_AMOUNT_ADDS_UP_EXACTLY_WHERE_A_DOUBLE_DOES_NOT()
    // **This is the whole reason the type exists.** 19.99 and 1.60 are both unrepresentable as
    // doubles, so the sum a `float8` column gives back is 21.589999999999996 -- and the difference
    // shows the first time somebody renders it or compares it against a total worked out elsewhere.
    assertEq((decimal("19.99") + decimal("1.60")).text(), "21.59")
    assertEq((0.1 + 0.2 == 0.3), false)
    assertEq((decimal("0.1") + decimal("0.2") == decimal("0.3")), true)

@test
THE_FOUR_OPERATORS_AND_THE_TWO_BESIDE_THEM()
    val a = decimal("19.99")
    val b = decimal("1.60")

    assertEq((a + b).text(), "21.59")
    assertEq((a - b).text(), "18.39")

    // **The scales ADD on a product**, which is decimal multiplication: two places by one place is
    // three, and rounding it back is the program's decision rather than this type's.
    assertEq((a * b).text(), "31.984")
    assertEq((a % b).text(), "0.79")
    assertEq((-a).text(), "-19.99")

@test
DIVISION_IS_THE_ONE_OPERATION_THAT_IS_NOT_EXACT_AND_SAYS_SO()
    // Most divisions have no decimal form at any scale, so `/` keeps six places and rounds half
    // away from zero. `divided` is how a program says what it actually wants.
    assertEq((decimal("19.99") / decimal("1.60")).text(), "12.49375")
    assertEq((decimal("1") / decimal("3")).text(), "0.333333")
    assertEq((decimal("2") / decimal("3")).text(), "0.666667")
    assertEq(decimal("2").divided(decimal("3"), 2).text(), "0.67")
    assertEq(decimal("10").divided(4, 0).text(), "3")

@test
DIVIDING_BY_ZERO_IS_A_FAULT_AND_NOT_A_NUMBER()
    var said = ""

    try
        print(decimal("1") / decimal("0"))
    catch e
        said = e.message

    assertEq(said, "this Decimal was divided by zero")

@test
TWO_WRITINGS_OF_ONE_NUMBER_ARE_ONE_VALUE()
    // **Normalised where it is built, and it has to be**: slate compares two objects by their
    // fields and a class cannot write its own `equals`, so 1.50 and 1.5 would be different values
    // with nothing to tell a program otherwise. What the database sent is a rendering; `toFixed` is
    // how the rendering is asked for back.
    assert(decimal("1.50") == decimal("1.5"))
    assert(decimal("-0.00") == decimal("0"))
    assertEq(decimal("1.50").text(), "1.5")
    assertEq(decimal("1.50").toFixed(2), "1.50")
    assertEq(decimal("1.5").toFixed(4), "1.5000")

@test
THE_ORDERINGS_ALL_READ_ONE_HOOK()
    // `compare` answers a number and the four operators read its sign, so a Decimal cannot order
    // inconsistently with itself.
    assert(decimal("2.5") > decimal("2.45"))
    assert(decimal("2.5") >= decimal("2.50"))
    assert(decimal("-1") < decimal("0"))
    assert(decimal("10") <= decimal("10.000"))
    assertEq(decimal("1").compare(decimal("2")), 0 - 1)
    assertEq(decimal("2").compare(decimal("2.0")), 0)

@test
A_WHOLE_NUMBER_MIXES_AND_A_REAL_IS_REFUSED()
    // **A real is the rounding this type exists to keep out**, so it is refused with the sentence
    // that says what to write instead rather than quietly converted.
    assertEq((decimal("19.99") + 1).text(), "20.99")
    assertEq((decimal("19.99") * 2).text(), "39.98")
    assertEq((decimal("1.5") + "2.25").text(), "3.75")

    var said = ""

    try
        print(decimal("1.5") + 1.5)
    catch e
        said = e.message

    assert(said.contains("a Decimal and a real do not mix"))

@test
ROUNDING_IS_HALF_AWAY_FROM_ZERO_IN_BOTH_DIRECTIONS()
    assertEq(decimal("0.5").toFixed(0), "1")
    assertEq(decimal("-0.5").toFixed(0), "-1")
    assertEq(decimal("1.005").toFixed(2), "1.01")
    assertEq(decimal("2.675").toFixed(2), "2.68")
    assertEq(decimal("1.4").toFixed(0), "1")

@test
A_NUMBER_TOO_LARGE_TO_HOLD_IS_A_FAULT_AND_NOT_A_WRAP()
    // **slate's integer is 64 bits and WRAPS**, so an unchecked product would answer a number that
    // is wrong and looks perfectly ordinary -- which is the one thing a money type may not do.
    var said = ""

    try
        print(decimal("999999999999999999") * decimal("10"))
    catch e
        said = e.message

    assert(said.contains("too large to hold"))

    var also = ""

    try
        print(decimal("99999999999999999") + decimal("999999999999999999"))
    catch e
        also = e.message

    assertEq(also, "")

@test
TEXT_THAT_IS_NOT_A_DECIMAL_ANSWERS_NOTHING_RATHER_THAN_GUESSING()
    // `readDecimal` is what reads a COLUMN, so it answers rather than faulting: `NaN` is a value a
    // PostgreSQL `numeric` may hold, and so is a number of two hundred digits.
    assert(readDecimal("NaN") == null)
    assert(readDecimal("1e10") == null)
    assert(readDecimal("1.2.3") == null)
    assert(readDecimal("") == null)
    assert(readDecimal(7) == null)
    assert(readDecimal("1234567890123456789012") == null)

    assertEq(readDecimal("  12.50  ").text(), "12.5")
    assertEq(readDecimal("-.5").text(), "-0.5")
    assertEq(readDecimal("000123.400").text(), "123.4")

@test
decimal_SAYS_WHICH_OF_THE_TWO_WAYS_TEXT_CAN_FAIL_IT_WAS()
    // **Two sentences because they send a reader to different places**: one is a value that is not
    // a number and the other is a number this cannot hold.
    var notANumber = ""

    try
        decimal("NaN")
    catch e
        notANumber = e.message

    assert(notANumber.contains("does not read as a decimal number"))

    var tooBig = ""

    try
        decimal("9223372036854775807")
    catch e
        tooBig = e.message

    assert(tooBig.contains("18 significant digits"))

@test
A_DECIMAL_IS_A_TYPE_AND_A_NUMBER_IS_NOT_ONE()
    assert(decimal("1") is Decimal)
    assert(!(1 is Decimal))
    assert(!("1" is Decimal))
    assert(decimal(decimal("1")) is Decimal)

@test
number_IS_LOSSY_AND_IS_NAMED_SO_THAT_IT_IS_ASKED_FOR()
    // The whole difference between this and reading the column as a `float8` is that the rounding
    // happens where a program wrote a word for it.
    assertEq(decimal("19.99").number(), 19.99)
    assert(decimal("19.99").number() is real)
    assertEq(decimal("0").isZero(), true)
    assertEq(decimal("-2.5").sign(), 0 - 1)
    assertEq(decimal("2.5").sign(), 1)
    assertEq(decimal("0").sign(), 0)
