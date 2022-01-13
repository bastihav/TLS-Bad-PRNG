import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.BasicTlsServer;
import de.rub.nds.tlsattacker.core.util.ConnectionHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.server.TlsServer;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Random;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Copied from TLS-Attacker, modified to allow for SecureRandom specification
 */
public class CustomRandomTlsServer extends Thread {

  private static final Logger LOGGER = LogManager.getLogger();

  private String[] cipherSuites = null;
  private final int port;
  private final SSLContext sslContext;
  private ServerSocket serverSocket;
  private boolean shutdown;
  boolean closed = true;

  /**
   * Very dirty but ok for testing purposes
   */
  private volatile boolean initialized;

  public CustomRandomTlsServer(KeyStore keyStore, String password, String protocol, int port, SecureRandom random) throws KeyStoreException,
      IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, KeyManagementException {

    this.port = port;

    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
    keyManagerFactory.init(keyStore, password.toCharArray());
    KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
    trustManagerFactory.init(keyStore);
    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
    sslContext = SSLContext.getInstance(protocol);
    sslContext.init(keyManagers, trustManagers, random);

    cipherSuites = sslContext.getServerSocketFactory().getSupportedCipherSuites();

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Provider: " + sslContext.getProvider());
      LOGGER.debug("Supported cipher suites ("
          + sslContext.getServerSocketFactory().getSupportedCipherSuites().length + ")");
      for (String c : sslContext.getServerSocketFactory().getSupportedCipherSuites()) {
        LOGGER.debug(" " + c);
      }
    }
  }

  @Override
  public void run() {
    try {
      preSetup();
      closed = false;
      while (!shutdown) {
        try {
          LOGGER.info("Listening on port " + port + "...\n");
          final Socket socket = serverSocket.accept();
          if (socket != null) {
            ConnectionHandler ch = new ConnectionHandler(socket);
            Thread t = new Thread(ch);
            t.start();
          }

        } catch (IOException ex) {
          LOGGER.debug(ex.getLocalizedMessage(), ex);
        }
      }
      closed = true;
    } catch (IOException ex) {
      LOGGER.debug(ex.getLocalizedMessage(), ex);
    } finally {
      try {
        if (serverSocket != null && !serverSocket.isClosed()) {
          serverSocket.close();
          serverSocket = null;
        }
      } catch (IOException e) {
        LOGGER.debug(e);
      }
      LOGGER.info("Shutdown complete");
    }
  }

  private void preSetup() throws SocketException, IOException {
    SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();

    serverSocket = serverSocketFactory.createServerSocket(port);
    serverSocket.setReuseAddress(true);
    // TODO:
    // if (cipherSuites != null) {
    // ((SSLServerSocket)
    // serverSocket).setEnabledCipherSuites(cipherSuites);
    // }
    LOGGER.debug("Pre-setup successful");
    initialized = true;
  }

  public void shutdown() {
    this.shutdown = true;
    LOGGER.debug("Shutdown signal received");
    try {
      if (!serverSocket.isClosed()) {
        serverSocket.close();
      }
    } catch (IOException ex) {
      LOGGER.error(ex);
    }
  }

  public String[] getCipherSuites() {
    return cipherSuites;
  }

  public boolean isInitialized() {
    return initialized;
  }

  public int getPort() {
    if (serverSocket != null) {
      return serverSocket.getLocalPort();
    } else {
      return port;
    }
  }
}
