package portscout;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * WHAT:   Tests for PortProbe and Scanner against tiny servers on localhost.
 * WHY:    Real networks are slow and unpredictable; local servers give the
 *         same answer every run and never scan anyone else's machine.
 */
class PortProbeTest
{
	/**
	 * WHAT:   A server that greets first, like SSH.
	 * WHY:    Checks an open port is found and its greeting becomes the banner.
	 *
	 * @throws Exception if the local test server cannot be started
	 */
	@Test
	void openPortWithBanner() throws Exception
	{
		try (ServerSocket server = new ServerSocket(0))
		{
			serveOnce(server, "SSH-2.0-OpenSSH_9.6 test\r\n");
			ScanResult r = PortProbe.probe("127.0.0.1", server.getLocalPort(), 1000);
			assertEquals(ScanResult.State.OPEN, r.state());
			assertEquals("SSH-2.0-OpenSSH_9.6 test", r.banner());
		}
	}

	/**
	 * WHAT:   A server that stays silent until it gets a request, like HTTP.
	 * WHY:    Checks the probe sends a HEAD request and reads the status line.
	 *
	 * @throws Exception if the local test server cannot be started
	 */
	@Test
	void openPortThatWaitsForHttp() throws Exception
	{
		try (ServerSocket server = new ServerSocket(0))
		{
			Thread.ofVirtual().start(() -> {
				try (Socket s = server.accept())
				{
					s.getInputStream().read(new byte[64]); // wait for the HEAD request
					s.getOutputStream().write("HTTP/1.0 200 OK\r\nServer: test\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
				}
				catch (IOException ignored)
				{
				}
			});
			ScanResult r = PortProbe.probe("127.0.0.1", server.getLocalPort(), 500);
			assertEquals(ScanResult.State.OPEN, r.state());
			assertEquals("HTTP/1.0 200 OK", r.banner());
		}
	}

	/**
	 * WHAT:   A port nobody listens on.
	 * WHY:    Checks a refused connection is CLOSED, not FILTERED.
	 *
	 * @throws Exception if a free local port cannot be found
	 */
	@Test
	void closedPort() throws Exception
	{
		int port;
		try (ServerSocket server = new ServerSocket(0))
		{
			port = server.getLocalPort();
		}
		// nothing listens there now, so localhost answers with a RST.
		// Windows retries a refused SYN for about 2 s before giving up, hence the long timeout.
		assertEquals(ScanResult.State.CLOSED, PortProbe.probe("127.0.0.1", port, 3000).state());
	}

	/**
	 * WHAT:   Two open ports given to the scanner highest first.
	 * WHY:    Threads finish in any order, so the scanner must sort before returning.
	 *
	 * @throws Exception if the local test servers cannot be started
	 */
	@Test
	void scannerSortsResults() throws Exception
	{
		try (ServerSocket a = new ServerSocket(0); ServerSocket b = new ServerSocket(0))
		{
			List<Integer> ports = List.of(b.getLocalPort(), a.getLocalPort());
			List<ScanResult> results = Scanner.scan(List.of("127.0.0.1"), ports, 500, 10);
			assertEquals(2, results.size());
			assertEquals(Math.min(a.getLocalPort(), b.getLocalPort()), results.get(0).port());
			results.forEach(r -> assertEquals(ScanResult.State.OPEN, r.state()));
		}
	}

	/**
	 * WHAT:   Accepts one connection on server and sends greeting.
	 * WHY:    Fakes a service that talks first, without installing a real one.
	 * PRE:    server is bound and open
	 * PRE:    greeting is not null
	 * POST:   a virtual thread serves one client, then closes its socket
	 *
	 * @param server   the bound server socket to accept on
	 * @param greeting the text to send as soon as a client connects
	 */
	private static void serveOnce(ServerSocket server, String greeting)
	{
		Thread.ofVirtual().start(() -> {
			try (Socket s = server.accept(); OutputStream out = s.getOutputStream())
			{
				out.write(greeting.getBytes(StandardCharsets.US_ASCII));
				out.flush();
				Thread.sleep(200);
			}
			catch (IOException | InterruptedException ignored)
			{
			}
		});
	}
}
