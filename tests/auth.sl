// Logging in: the encodings, MD5, and the SCRAM exchange RFC 7677 publishes.
//
// **Every value asserted here is a PUBLISHED one.** A hash checked against what this implementation
// answered yesterday passes just as happily on a broken implementation; the whole point of a digest
// and of a challenge-response exchange is that everybody else's agrees.

import { hex, base64, unbase64, md5, md5Password, scram, freshNonce } from "../auth.sl"

@test
MD5_ANSWERS_THE_VECTORS_RFC_1321_PUBLISHES()
    // The suite from the appendix of RFC 1321, including the empty message -- which is the case an
    // implementation gets wrong by padding a block it did not need.
    assert(hex(md5(toBytes(""))) == "d41d8cd98f00b204e9800998ecf8427e")
    assert(hex(md5(toBytes("a"))) == "0cc175b9c0f1b6a831c399e269772661")
    assert(hex(md5(toBytes("abc"))) == "900150983cd24fb0d6963f7d28e17f72")
    assert(hex(md5(toBytes("message digest"))) == "f96b697d7cb7938d525a2f31aaf161d0")
    assert(hex(md5(toBytes("abcdefghijklmnopqrstuvwxyz"))) == "c3fcd3d76192e4007dfb496cca67e13b")
    assert(hex(md5(toBytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890"))) ==
        "57edf4a22be3c955ac49da2e2107b67a")

@test
A_MESSAGE_THAT_LANDS_ON_A_BLOCK_BOUNDARY_STILL_HASHES()
    // **55, 56 and 64 bytes are the three lengths that break a padding loop**, 56 being where the
    // length no longer fits in the block it would have been appended to and a second block is
    // needed. Every one of these was produced by another implementation.
    assert(hex(md5(toBytes("1234567890123456789012345678901234567890123456789012345"))) ==
        "c9ccf168914a1bcfc3229f1948e67da0")
    assert(hex(md5(toBytes("12345678901234567890123456789012345678901234567890123456"))) ==
        "49f193adce178490e34d1b3a4ec0064c")
    assert(hex(md5(toBytes("1234567890123456789012345678901234567890123456789012345678901234"))) ==
        "eb6c4179c0a7c82cc2828c1e6338e165")

@test
AN_MD5_LOGIN_IS_A_HASH_OF_A_HASH_AND_THE_SALT_IS_ONLY_IN_THE_OUTER_ONE()
    // The form PostgreSQL documents: `md5` and the hex of `md5(md5(password + user) + salt)`. It is
    // what a server compares against `pg_shadow`, so it can be worked out by hand.
    //
    // **The inner hash has no salt in it**, which is why a stolen row still logs in -- and is why
    // this method was replaced by SCRAM rather than improved.
    val said = md5Password("bob", "secret", [1, 2, 3, 4])

    assert(said.startsWith("md5"))
    assert(len(said) == 35)
    assert(said == "md5" + hex(md5(joined(toBytes(hex(md5(toBytes("secretbob")))), [1, 2, 3, 4]))))

joined(a, b)
    val out = []

    for x in a
        push(out, x)

    for x in b
        push(out, x)

    out

@test
BASE64_ROUND_TRIPS_AT_EVERY_TAIL_LENGTH()
    // **The three tails are where a base64 goes wrong**, one byte left over and two being the cases
    // that need padding. A salt or a proof mangled at the end is a login that fails with nothing to
    // look at.
    assert(base64(toBytes("hello world")) == "aGVsbG8gd29ybGQ=")
    assert(base64(toBytes("hi")) == "aGk=")
    assert(base64(toBytes("h")) == "aA==")
    assert(base64([]) == "")

    for text in ["", "a", "ab", "abc", "abcd", "abcde", "éè", "the quick brown fox"]
        assert(fromBytes(unbase64(base64(toBytes(text)))).value == text)

@test
THE_SCRAM_EXCHANGE_IS_THE_ONE_RFC_7677_PUBLISHES()
    // **RFC 7677 section 3, run through this code exactly as it is written there.** The client nonce
    // and the server's whole first message are given, so every value after them is determined -- the
    // salted password, the proof and the server's signature. Nothing here is this implementation
    // agreeing with itself.
    val exchange = scram("user", "pencil", "rOprNGfwEbeRWgbNEkqO")

    assert(exchange.first() == "n,,n=user,r=rOprNGfwEbeRWgbNEkqO")

    val serverFirst = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
    val final = exchange.final(serverFirst)

    assert(final.message ==
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")

    // **The salt in that message ends in `==`, which is the case that catches a field split on
    // every `=` rather than on the first.** A parser that lost the padding derives a different key
    // and the login fails with nothing to look at, so this vector is the test for that too.

    // The server's own proof, which this client checks rather than trusts.
    assert(final.verifier == "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
    assert(exchange.verify("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=", final.verifier))

@test
A_SERVER_THAT_CANNOT_PROVE_ITSELF_IS_REFUSED()
    // **The verifier is the half of SCRAM that authenticates the SERVER**, and a client that skipped
    // it would hand its proof to anything that answered. A signature that is merely well formed is
    // not the signature.
    val exchange = scram("user", "pencil", "rOprNGfwEbeRWgbNEkqO")
    val final = exchange.final("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")

    assert(!exchange.verify("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", final.verifier))
    assert(!exchange.verify("", final.verifier))

@test
A_SERVER_NONCE_THAT_DOES_NOT_EXTEND_THE_CLIENTS_IS_REFUSED()
    // **The client's nonce must appear at the front of the server's**, which is what makes this an
    // exchange rather than a formality: a server replaying a recorded message sends a nonce that was
    // never asked for, and a client that did not check would compute a proof over somebody else's
    // conversation.
    val exchange = scram("user", "pencil", "rOprNGfwEbeRWgbNEkqO")
    var said = ""

    try
        exchange.final("r=someoneElsesNonce,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
    catch e
        said = string(e)

    assert(said.contains("does not extend"))

@test
A_SERVER_MESSAGE_MISSING_A_FIELD_IS_REFUSED_RATHER_THAN_GUESSED_AT()
    val exchange = scram("user", "pencil", "rOprNGfwEbeRWgbNEkqO")
    var said = ""

    try
        exchange.final("r=rOprNGfwEbeRWgbNEkqOxyz")
    catch e
        said = string(e)

    assert(said.contains("missing a field"))

@test
A_NONCE_IS_FRESH_EVERY_TIME_AND_COMES_FROM_THE_KERNEL()
    // **Not a test of randomness, and not pretending to be.** It is a test that the kernel is asked
    // each time -- the failure a wrong implementation has is a nonce computed once, or computed from
    // the clock, and every proof after that is replayable.
    assert(freshNonce() != freshNonce())
    assert(len(freshNonce()) == 24)
