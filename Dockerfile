FROM openjdk:11
ADD build/distributions/TLS-Bad-PRNG-1.0-SNAPSHOT.tar /home
ENTRYPOINT ["/bin/sh", "/home/TLS-Bad-PRNG-1.0-SNAPSHOT/bin/TLS-Bad-PRNG"]