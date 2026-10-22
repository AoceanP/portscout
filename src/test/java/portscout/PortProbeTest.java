package portscout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
		// nothing listens there now, so localhost answers with a RST
		assertEquals(ScanResult.State.CLOSED, PortProbe.probe("127.0.0.1", port, 1000).state());
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
	 * WHAT:   A banner with control characters and a second line.
	 * WHY:    Banners are untrusted remote data; only the first line of
	 *         printable text may reach the report. Control characters at the
	 *         edges are trimmed away, ones inside become '.'.
	 *
	 * @throws Exception if the local test server cannot be started
	 */
	@Test
	void bannerIsCleaned() throws Exception
	{
		try (ServerSocket server = new ServerSocket(0))
		{
			serveOnce(server, "\u0007220 FTP\u001b ready\r\nsecond line\r\n");
			ScanResult r = PortProbe.probe("127.0.0.1", server.getLocalPort(), 1000);
			assertEquals("220 FTP. ready", r.banner());
		}
	}

	/**
	 * WHAT:   An address that never answers.
	 * WHY:    192.0.2.1 is TEST-NET-1 (RFC 5737), reserved for documentation and
	 *         never routed, so the SYN gets no reply, just like behind a firewall.
	 */
	@Test
	void silentHostIsFiltered()
	{
		ScanResult r = PortProbe.probe("192.0.2.1", 80, 300);
		assertEquals(ScanResult.State.FILTERED, r.state());
		assertEquals("", r.banner());
	}

	/**
	 * WHAT:   Hosts given out of order, including .9 and .10.
	 * WHY:    Sorting addresses as text would put .10 before .9.
	 *
	 * @throws Exception if the local test server cannot be started
	 */
	@Test
	void scannerSortsHostsNumerically() throws Exception
	{
		try (ServerSocket server = new ServerSocket(0))
		{
			int port = server.getLocalPort();
			List<ScanResult> results = Scanner.scan(List.of("127.0.0.10", "127.0.0.9", "127.0.0.1"), List.of(port), 300, 10);
			assertEquals(List.of("127.0.0.1", "127.0.0.9", "127.0.0.10"), results.stream().map(ScanResult::host).toList());
		}
	}

	/**
	 * WHAT:   A scan bigger than Scanner.MAX_PROBES, and a concurrency of 0.
	 * WHY:    Both must be refused before any thread or socket is created.
	 */
	@Test
	void scannerRejectsBadLimits()
	{
		List<String> hosts = TargetParser.parse("10.0.0.0/16");
		List<Integer> ports = PortParser.parse("1-100");
		assertThrows(IllegalArgumentException.class, () -> Scanner.scan(hosts, ports, 100, 10));
		assertThrows(IllegalArgumentException.class, () -> Scanner.scan(List.of("127.0.0.1"), List.of(80), 100, 0));
	}

	/**
	 * WHAT:   Nothing to scan.
	 * WHY:    Empty input should give an empty result, not an error or a hang.
	 */
	@Test
	void scannerHandlesEmptyInput()
	{
		assertTrue(Scanner.scan(List.of(), List.of(80), 100, 10).isEmpty());
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
