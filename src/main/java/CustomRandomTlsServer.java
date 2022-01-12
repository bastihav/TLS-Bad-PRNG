import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.server.TlsServer;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CustomRandomTlsServer extends TlsServer {

  private static final Logger LOGGER = LogManager.getLogger();

  public void run(Config config, Random random, long seed) {
    State state = new State(config);

    state.getTlsContext().setRandom(random);

    WorkflowExecutor workflowExecutor =
        WorkflowExecutorFactory.createWorkflowExecutor(config.getWorkflowExecutorType(), state);

    try {
      workflowExecutor.executeWorkflow();
    } catch (WorkflowExecutionException ex) {
      LOGGER.info(
          "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
      LOGGER.debug(ex.getLocalizedMessage(), ex);
    }
  }
}
