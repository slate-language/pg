{
    name: "pg",
    version: "0.3.0",

    // The whole package: a connection, and everything else as a method on it. `wire.sl`, `values.sl`
    // and `auth.sl` are reached from here and are deliberately not listed under `modules` -- what a
    // consumer imports is the client, and the message layout is this package's own business.
    main: "pg.sl",

    // **`pg/decimal` is the one exception, and it is one because of what a class is.** A `Decimal`
    // is a value and a type under one name; `pg.sl` could re-export the value and not the type, so
    // a program that could make one could not say what it was holding. A second door gives it both.
    modules: { decimal: "decimal.sl" },
}
