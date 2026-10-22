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
 * WHAT:   Edge cases across the whole scanner, each one listed in the
 *         README's "Edge cases" table.
 * WHY:    Boundaries and odd input are where scanners usually break, and
 *         where interviewers like to poke.
 */
class EdgeCaseTest
{
	// ---------------------------------------------------------------- ports

	/**
	 * WHAT:   The lowest and highest ports, and a one-port range.
	 * WHY:    Off-by-one mistakes show up at exactly 1 and 65535.
	 */
	@Test
	void portBoundaries()
	{
		assertEquals(List.of(1), PortParser.parse("1"));
		assertEquals(List.of(65535), PortParser.parse("65535"));
		assertEquals(List.of(443), PortParser.parse("443-443"));
	}

	/**
	 * WHAT:   A port with a leading zero.
	 * WHY:    "080" means port 80; it must not be read as octal or refused.
	 */
	@Test
	void portWithLeadingZero()
	{
		assertEquals(List.of(80), PortParser.parse("080"));
	}

	/**
	 * WHAT:   A negative port.
	 * WHY:    "-5" looks like a range with no start, so it must fail, not scan 1 to 5.
	 */
	@Test
	void negativePort()
	{
		assertThrows(IllegalArgumentException.class, () -> PortParser.parse("-5"));
	}

	// -------------------------------------------------------------- targets

	/**
	 * WHAT:   The largest block allowed, a /16.
	 * WHY:    The safety limit must accept its own boundary: 65,536 addresses
	 *         minus the network and broadcast addresses.
	 */
	@Test
	void largestAllowedBlock()
	{
		assertEquals(65534, TargetParser.parse("10.0.0.0/16").size());
		assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("10.0.0.0/15"));
	}

	/**
	 * WHAT:   Octets with leading zeros.
	 * WHY:    Some C libraries read "010" as octal 8, a known way to sneak
	 *         past address filters. portscout always reads decimal.
	 */
	@Test
	void octetWithLeadingZeroIsDecimal()
	{
		assertEquals(List.of("10.0.0.8"), TargetParser.parse("010.0.0.008"));
	}

	/**
	 * WHAT:   Spaces around the target.
	 * WHY:    Copy-pasted addresses often carry spaces; they should still work.
	 */
	@Test
	void targetWithSurroundingSpaces()
	{
		assertEquals(List.of("10.0.0.1"), TargetParser.parse("  10.0.0.1  "));
	}

	/**
	 * WHAT:   0.0.0.0 and 255.255.255.255 as single targets.
	 * WHY:    They are valid IPv4 text, so the parser accepts them; whether a
	 *         connect makes sense is up to the operating system.
	 */
	@Test
	void extremeAddresses()
	{
		assertEquals(List.of("0.0.0.0"), TargetParser.parse("0.0.0.0"));
		assertEquals(List.of("255.255.255.255"), TargetParser.parse("255.255.255.255"));
	}

	// -------------------------------------------------------------- banners

	/**
	 * WHAT:   A service that accepts and hangs up without sending anything.
	 * WHY:    The port is still open; an empty banner must not turn into an error.
	 *
	 * @throws Exception if the local test server cannot be started
	 */
	@Test
	void serviceThatHangsUpImmediately() throws Exception
	{
		try (ServerSocket server = new ServerSocket(0))
		{
			Thread.ofVirtual().start(() -> {
				try (Socket s = server.accept())
				{
					// close straight away
				}
				catch (IOException ignored)
				{
				}
			});
			ScanResult r = PortProbe.probe("127.0.0.1", server.getLocalPort(), 500);
			assertEquals(ScanResult.State.OPEN, r.state());
			assertEquals("", r.banner());
		}
	}

	/**
	 * WHAT:   A service that never sends and ignores the HEAD request.
	 * WHY:    The probe must give up after two read timeouts, never hang.
	 *
	 * @throws Exception if the local test server cannot be started
	 */
	@Test
	void serviceThatStaysSilent() throws Exception
	{
		try (ServerSocket server = new ServerSocket(0))
		{
			Thread.ofVirtual().start(() -> {
				try (Socket s = server.accept())
				{
					Thread.sleep(2000);
				}
				catch (IOException | InterruptedException ignored)
				{
				}
			});
			ScanResult r = PortProbe.probe("127.0.0.1", server.getLocalPort(), 200);
			assertEquals(ScanResult.State.OPEN, r.state());
			assertEquals("", r.banner());
			assertTrue(r.millis() < 1500, "probe took " + r.millis() + " ms");
		}
	}

	/**
	 * WHAT:   A banner longer than 256 bytes with no line break.
	 * WHY:    A hostile or chatty service must not be able to flood the report.
	 *
	 * @throws Exception if the local test server cannot be started
	 */
	@Test
	void longBannerIsCut() throws Exception
	{
		try (ServerSocket server = new ServerSocket(0))
		{
			serveOnce(server, "A".repeat(1000));
			ScanResult r = PortProbe.probe("127.0.0.1", server.getLocalPort(), 1000);
			assertTrue(r.banner().length() <= 256, "banner was " + r.banner().length() + " chars");
		}
	}

	/**
	 * WHAT:   A banner that is only a line break.
	 * WHY:    Whitespace is not a banner, so the result is "".
	 *
	 * @throws Exception if the local test server cannot be started
	 */
	@Test
	void blankBanner() throws Exception
	{
		try (ServerSocket server = new ServerSocket(0))
		{
			serveOnce(server, "\r\n");
			assertEquals("", PortProbe.probe("127.0.0.1", server.getLocalPort(), 1000).banner());
		}
	}

	// -------------------------------------------------------------- scanner

	/**
	 * WHAT:   A concurrency of 1, and one far bigger than the number of probes.
	 * WHY:    1 must still finish (fully sequential); a huge cap must not
	 *         create extra threads or break.
	 *
	 * @throws Exception if the local test servers cannot be started
	 */
	@Test
	void concurrencyExtremes() throws Exception
	{
		try (ServerSocket a = new ServerSocket(0); ServerSocket b = new ServerSocket(0))
		{
			List<Integer> ports = List.of(a.getLocalPort(), b.getLocalPort());
			assertEquals(2, Scanner.scan(List.of("127.0.0.1"), ports, 500, 1).size());
			assertEquals(2, Scanner.scan(List.of("127.0.0.1"), ports, 500, 10_000).size());
		}
	}

	/**
	 * WHAT:   A scan just over Scanner.MAX_PROBES.
	 * WHY:    A full /16 is allowed on its own, but times 16 ports it passes
	 *         the limit. Only the size check runs: no sockets are opened.
	 */
	@Test
	void probeLimitBoundary()
	{
		// 65,534 hosts x 16 ports = 1,048,544, just over the limit
		List<String> hosts = TargetParser.parse("10.0.0.0/16");
		assertThrows(IllegalArgumentException.class, () -> Scanner.scan(hosts, PortParser.parse("1-16"), 100, 10));
	}

	// --------------------------------------------------------------- report

	/**
	 * WHAT:   Reports of an empty scan.
	 * WHY:    "Nothing found" is a normal answer and must print cleanly.
	 */
	@Test
	void emptyReports()
	{
		assertTrue(Report.table(List.of(), false).contains("0 open of 0 probed"));
		assertEquals("[\n]\n", Report.json(List.of()));
	}

	/**
	 * WHAT:   Accepts one connection on server and sends text.
	 * WHY:    Fakes a service that talks first, without installing a real one.
	 * PRE:    server is bound and open
	 * PRE:    text is not null
	 * POST:   a virtual thread serves one client, then closes its socket
	 *
	 * @param server the bound server socket to accept on
	 * @param text   the text to send as soon as a client connects
	 */
	private static void serveOnce(ServerSocket server, String text)
	{
		Thread.ofVirtual().start(() -> {
			try (Socket s = server.accept(); OutputStream out = s.getOutputStream())
			{
				out.write(text.getBytes(StandardCharsets.US_ASCII));
				out.flush();
				Thread.sleep(200);
			}
			catch (IOException | InterruptedException ignored)
			{
			}
		});
	}
}
