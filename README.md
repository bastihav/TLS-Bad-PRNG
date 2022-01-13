# TLS Bad-PRNG
This projects implements a TLS Server using bad PRNG implementations supplied by https://github.com/bastihav/Java-PRNG.
The TLS Server implementation is https://github.com/tls-attacker/TLS-Attacker.

# Usage
Build the project using

``./gradlew build``

Build the docker container using

``docker build -t tls-bad-prng .``

Run the docker container using

``docker run -p 443:443 tls-bad-prng -p JAVA_RANDOM -s 5``

This will start the TLS server on port 443.

You can specify the PRNG using ``-p <PRNG>``, this supports all PRNGs implemented in https://github.com/bastihav/Java-PRNG/blob/main/src/main/java/de/skuld/prng/ImplementedPRNGs.java.

You can specify the seed using ``-s <SEED>``, this supports all Java longs. If omitted, will be seeded using the current UNIX time.