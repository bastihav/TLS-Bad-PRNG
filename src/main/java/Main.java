import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.server.TlsServer;
import de.skuld.prng.ImplementedPRNGs;
import java.util.Random;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class Main {
  public static void main(String[] args) {

    Options options = new Options();

    Option seedOption = new Option("s", "seed", true, "seed (long)");
    seedOption.setRequired(false);
    options.addOption(seedOption);

    Option prngOption = new Option("p", "prng", true, "PRNG");
    prngOption.setRequired(true);
    options.addOption(prngOption);

    CommandLineParser parser = new DefaultParser();
    HelpFormatter formatter = new HelpFormatter();
    CommandLine cmd = null;

    try {
      cmd = parser.parse(options, args);
    } catch (ParseException e) {
      System.out.println(e.getMessage());
      formatter.printHelp("utility-name", options);

      System.exit(1);
    }

    long seed = Long.parseLong(cmd.getOptionValue(seedOption));
    ImplementedPRNGs prng = ImplementedPRNGs.valueOf(cmd.getOptionValue(prngOption));

    //ImplementedPRNGs.

    CustomRandomTlsServer tlsServer = new CustomRandomTlsServer();
    Config config = Config.createConfig();
    tlsServer.run(config, new Random(), seed);

  }
}
