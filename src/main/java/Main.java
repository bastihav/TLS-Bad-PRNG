import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
import de.rub.nds.tlsattacker.server.TlsServer;
import de.skuld.prng.ImplementedPRNGs;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;
import java.util.Random;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class Main {
  public static void main(String[] args) {

    Security.addProvider(new BouncyCastleProvider());

    Options options = new Options();

    Option seedOption = new Option("s", "seed", true, "The seed that the PRNG will be seeded with. Must be a Java long.");
    seedOption.setRequired(false);
    options.addOption(seedOption);

    Option prngOption = new Option("p", "prng", true, "The PRNG that will be used to generate random values. Must be one of " + Arrays
        .toString(ImplementedPRNGs.values()));
    prngOption.setRequired(true);
    options.addOption(prngOption);

    CommandLineParser parser = new DefaultParser();
    HelpFormatter formatter = new HelpFormatter();
    CommandLine cmd = null;

    try {
      cmd = parser.parse(options, args);
    } catch (ParseException e) {
      System.out.println(e.getMessage());
      formatter.printHelp("help", options);

      System.exit(1);
    }
    long seed;

    String seedString = cmd.getOptionValue(seedOption);

    if (seedString != null) {
       seed = Long.parseLong(seedString);
    } else {
      seed = new Date().getTime();
    }
    System.out.println(seed);
    ImplementedPRNGs prng = ImplementedPRNGs.valueOf(cmd.getOptionValue(prngOption).toUpperCase(
        Locale.ROOT));

    System.out.println(ImplementedPRNGs.getPRNG(prng));

    try {
      SecureRandom random = (SecureRandom) ImplementedPRNGs.getPRNG(prng).getConstructor(long.class).newInstance(seed);

      KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, new BadRandom());
      KeyStore ks = KeyStoreGenerator.createKeyStore(k, new BadRandom());

      CustomRandomTlsServer tlsServer = new CustomRandomTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", 443, random);
      tlsServer.start();

    } catch (NoSuchMethodException | InvocationTargetException | InstantiationException | IllegalAccessException | UnrecoverableKeyException | CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException | KeyManagementException | SignatureException | InvalidKeyException | NoSuchProviderException | OperatorCreationException e) {
      e.printStackTrace();
    }

  }
}
