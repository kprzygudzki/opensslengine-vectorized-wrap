# OpenSslEngine vectorized wrap reproducer

This reproducer repo is aimed at showcasing the difference in behaviour
between JDK's implementation of the `SSLEngine` interface
and the Netty's `OpenSslEngine` implementation
with regard to the _vectorized wrap_ operation.

Following is an excerpt from the `SSLEngine` javadoc of the
`SSLEngine#wrap(ByteBuffer [] srcs, int offset, int length, ByteBuffer dst)`
method:

> Attempts to encode plaintext bytes from a subsequence of data
> buffers into SSL/TLS/DTLS network data.  This <i>"gathering"</i>
> operation encodes, in a single invocation, a sequence of bytes
> from one or more of a given sequence of buffers.
> [...]
> This method will attempt to produce SSL/TLS/DTLS records, and will
> consume as much source data as possible [...]

As shown with a simple test,
the JDK's `SSLEngineImpl` implementation consumes multiple buffers from the array.  
The Netty's `OpenSslEngine` implementations only consumes the first buffer
leaving the following buffers untouched.
