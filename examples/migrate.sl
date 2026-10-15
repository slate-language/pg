// A migration command for a project, over `migrate`, `rollback` and `migrationStatus`.
//
//     PG_URL=postgres://ada@127.0.0.1/notes slate examples/migrate.sl up
//     PG_URL=postgres://ada@127.0.0.1/notes slate examples/migrate.sl down 2
//     PG_URL=postgres://ada@127.0.0.1/notes slate examples/migrate.sl status
//
// **A package cannot ship a command**, since the `scripts` `slate run` reads are a project's own, so
// this is the file a project copies -- importing `pg` rather than `../pg.sl` -- and names in its
// `scripts`. The directory is `MIGRATIONS`, or `migrations` beside where it is run; the database is
// `PG_URL`, or `DATABASE_URL`, or libpq's own `PGHOST` and the rest when neither is set.
//
// It answers 0 when the database is where it was asked to be, 1 when it is not, and 2 when the
// command itself made no sense.

import { pg, migrate, rollback, migrationStatus } from "../pg.sl"
import { args, env, exit } from slate:process

usage()
    print("usage: migrate up | down [steps] | status")
    exit(2)

listed(what, ms)
    for m in ms
        print("  " + what + "  " + m.file)

async main()
    if args.length == 0 then usage()

    val command = args[0]
    val dir = env("MIGRATIONS") ?? "migrations"

    var steps = 1

    if command == "down" && args.length > 1
        val n = number(args[1])

        if n == null || !(n is integer) || n < 1 then usage()

        steps = n

    if command != "up" && command != "down" && command != "status" then usage()

    val made = await pg(env("PG_URL") ?? (env("DATABASE_URL") ?? { }))

    if !made.ok
        print("could not connect:", made.error)
        exit(1)

    val db = made.value
    var failed = false

    if command == "up"
        val r = await migrate(db, dir)

        if r.ok
            listed("applied ", r.value.applied)

            if r.value.applied.length == 0 then print("nothing to apply")
        else
            listed("applied ", r.applied)
            print(r.error)

            failed = true
    else if command == "down"
        val r = await rollback(db, dir, { steps: steps })

        if r.ok
            listed("reverted", r.value.reverted)

            if r.value.reverted.length == 0 then print("nothing to roll back")
        else
            listed("reverted", r.reverted)
            print(r.error)

            failed = true
    else
        val r = await migrationStatus(db, dir)

        if r.ok
            listed("applied ", r.value.applied)
            listed("changed ", r.value.changed)
            listed("pending ", r.value.pending)

            for m in r.value.missing
                print("  missing  " + string(m.version) + "_" + m.name + " (applied, and no file here)")

            failed = r.value.changed.length > 0
        else
            print(r.error)

            failed = true

    db.close()

    if failed then exit(1)

main()
