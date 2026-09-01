{
    name: "pg",
    version: "0.2.1",

    // The whole package: a connection, and everything else as a method on it. `wire.sl`, `values.sl`
    // and `auth.sl` are reached from here and are deliberately not listed under `modules` -- what a
    // consumer imports is the client, and the message layout is this package's own business.
    main: "pg.sl",
}
