package portscout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * WHAT:   Tests for scanning politely: the rate limit, connect-only probes,
 *         and IPv6 targets.
 * WHY:    A rate that bursts, or a "send nothing" mode that sends something,
 *         would break the promise these options make to whoever owns the target.
 */
class PoliteScanTest
{
	// ----------------------------------------------------------------- pacer

	/**
	 * WHAT:   A fake clock that only moves when the pacer sleeps.
	 * WHY:    The spacing is checked exactly, and the test never waits.
	 */
	private static final class FakeClock
	{
		/** WHAT: the current time, nanoseconds. */
		long now = 5_000;
		/** WHAT: every sleep the pacer asked for. */
		final List<Long> sleeps = new ArrayList<>();

		/**
		 * WHAT:   Records a sleep and moves the clock forward by it.
		 *
		 * @param nanos how long to sleep
		 */
		void sleep(long nanos)
		{
			sleeps.add(nanos);
			now += nanos;
		}
	}

	/**
	 * WHAT:   10 per second, five starts in a row.
	 * WHY:    The first starts at once; each next one waits exactly 100 ms.
	 */
	@Test
	void pacerSpacesStartsEvenly()
	{
		FakeClock clock = new FakeClock();
		Pacer pacer = new Pacer(10, () -> clock.now, clock::sleep);
		for (int i = 0; i < 5; i++)
		{
			pacer.await();
		}
		assertEquals(List.of(100_000_000L, 100_000_000L, 100_000_000L, 100_000_000L), clock.sleeps);
	}

	/**
	 * WHAT:   A long pause between starts.
	 * WHY:    After the pause the next start goes at once, and the one after
	 *         still waits a full interval: no burst to "catch up".
	 */
	@Test
	void pacerNeverBurstsAfterAPause()
	{
		FakeClock clock = new FakeClock();
		Pacer pacer = new Pacer(10, () -> clock.now, clock::sleep);
		pacer.await();
		clock.now += 5_000_000_000L; // 5 s pause
		pacer.await();
		pacer.await();
		assertEquals(List.of(100_000_000L), clock.sleeps);
	}

	/**
	 * WHAT:   A clock that reads negative.
	 * WHY:    System.nanoTime may be negative; the first start must still not wait.
	 */
	@Test
	void pacerHandlesANegativeClock()
	{
		FakeClock clock = new FakeClock();
		clock.now = -9_000_000_000L;
		Pacer pacer = new Pacer(2, () -> clock.now, clock::sleep);
		pacer.await();
		pacer.await();
		assertEquals(List.of(500_000_000L), clock.sleeps);
	}

	/**
	 * WHAT:   No limit, and a negative rate.
	 * WHY:    0 never sleeps; a negative rate is a bug, refused at once.
	 */
	@Test
	void pacerWithoutLimitNeverSleeps()
	{
		FakeClock clock = new FakeClock();
		Pacer pacer = new Pacer(0, () -> clock.now, clock::sleep);
		for (int i = 0; i < 1000; i++)
		{
			pacer.await();
		}
		assertTrue(clock.sleeps.isEmpty());
		assertThrows(IllegalArgumentException.class, () -> new Pacer(-1));
		assertThrows(IllegalArgumentException.class, () -> new ScanSettings(500, 10, -1, true));
	}

	/**
	 * WHAT:   A real scan of 20 closed local ports at 100 per second.
	 * WHY:    Closed ports answer at once, so without the limit this takes a
	 *         few milliseconds; with it, 20 starts need at least 190 ms.
	 *
	 * @throws Exception if no free ports can be found
	 */
	@Test
	void rateLimitSlowsARealScan() throws Exception
	{
		List<Integer> ports = closedPorts(20);
		long start = System.nanoTime();
		List<ScanResult> results = Scanner.scan(List.of("127.0.0.1"), ports, new ScanSettings(500, 200, 100, true),
			r -> { });
		long ms = (System.nanoTime() - start) / 1_000_000;
		assertEquals(20, results.size());
		assertTrue(ms >= 190, "20 probes at 100/s took only " + ms + " ms");
	}

	// ------------------------------------------------------------- no probe

	/**
	 * WHAT:   A silent open port probed with and without banners.
	 * WHY:    Normally portscout sends a HEAD request to a silent service;
	 *         with --no-probe the server must receive nothing at all.
	 *
	 * @throws Exception if the local test server cannot be started
	 */
	@Test
	void noProbeSendsNothing() throws Exception
	{
		try (ServerSocket server = new ServerSocket(0))
		{
			CompletableFuture<Integer> received = countBytesOnce(server);
			ScanResult quiet = PortProbe.probe("127.0.0.1", server.getLocalPort(), 300, false);
			assertEquals(ScanResult.State.OPEN, quiet.state());
			assertEquals("", quiet.banner());
			assertEquals(0, received.get(5, TimeUnit.SECONDS));

			CompletableFuture<Integer> asked = countBytesOnce(server);
			PortProbe.probe("127.0.0.1", server.getLocalPort(), 300, true);
			assertTrue(asked.get(5, TimeUnit.SECONDS) > 0, "the normal probe sends a HEAD request");
		}
	}

	/**
	 * WHAT:   --no-probe on a well-known port.
	 * WHY:    With no banner, the service is still guessed from the port, marked "?".
	 *
	 * @throws Exception if no free port can be found
	 */
	@Test
	void noProbeStillGuessesTheService() throws Exception
	{
		try (ServerSocket server = new ServerSocket(0))
		{
			ScanResult r = PortProbe.probe("127.0.0.1", server.getLocalPort(), 300, false);
			assertEquals(Service.identify(server.getLocalPort(), "").label(), r.service().label());
		}
	}

	// ------------------------------------------------------------------ IPv6

	/**
	 * WHAT:   IPv6 addresses written in different ways.
	 * WHY:    Each is normalised to the short standard form (RFC 5952), so
	 *         the same host is always written the same way.
	 */
	@Test
	void ipv6AddressesAreNormalised()
	{
		assertEquals(List.of("::1"), TargetParser.parse("::1"));
		assertEquals(List.of("::1"), TargetParser.parse("[0:0:0:0:0:0:0:1]"));
		assertEquals(List.of("2001:db8::1"), TargetParser.parse("2001:DB8:0:0:0:0:0:1"));
		assertEquals(List.of("2001:db8:0:1::"), TargetParser.parse("2001:db8:0:1:0:0:0:0"));
		// only the longest zero run is shortened, and a single zero group never is
		assertEquals(List.of("2001:0:0:1::1"), TargetParser.parse("2001:0:0:1:0:0:0:1"));
		assertEquals(List.of("2001:db8:0:1:1:1:1:1"), TargetParser.parse("2001:db8:0:1:1:1:1:1"));
		// an IPv4-mapped address is plain IPv4
		assertEquals(List.of("192.0.2.1"), TargetParser.parse("::ffff:192.0.2.1"));
	}

	/**
	 * WHAT:   IPv6 input that must be refused.
	 * WHY:    A subnet would never finish; anything that is not a literal
	 *         address could otherwise turn into a DNS lookup.
	 */
	@Test
	void ipv6RejectsSubnetsAndNonAddresses()
	{
		IllegalArgumentException subnet = assertThrows(IllegalArgumentException.class,
			() -> TargetParser.parse("2001:db8::/64"));
		assertTrue(subnet.getMessage().contains("quintillion"));
		for (String bad : new String[] {"2001:db8::g", "1:2:3:4:5:6:7:8:9", "fe80::1%eth0", "example.com:80",
			"192.0.2.1:80", ":::"})
		{
			assertThrows(IllegalArgumentException.class, () -> TargetParser.parse(bad), bad);
		}
	}

	/**
	 * WHAT:   Results for IPv4 and IPv6 hosts, out of order.
	 * WHY:    Hosts sort as numbers, IPv4 before IPv6.
	 */
	@Test
	void hostsSortAsNumbersIpv4First()
	{
		List<ScanResult> results = new ArrayList<>();
		for (String host : List.of("2001:db8::10", "10.0.0.10", "2001:db8::9", "10.0.0.9"))
		{
			results.add(new ScanResult(host, 80, ScanResult.State.CLOSED, "", 1));
		}
		results.sort(TargetParser.HOST_ORDER);
		assertEquals(List.of("10.0.0.9", "10.0.0.10", "2001:db8::9", "2001:db8::10"),
			results.stream().map(ScanResult::host).toList());
	}

	/**
	 * WHAT:   The table with a long IPv6 host.
	 * WHY:    The host column grows, so the columns still line up.
	 */
	@Test
	void tableFitsLongIpv6Hosts()
	{
		String host = "2001:db8:85a3:1234:5678:8a2e:370:7334";
		String table = Report.table(List.of(new ScanResult(host, 22, ScanResult.State.OPEN, "", 3)), false);
		String[] lines = table.split("\n");
		assertEquals(lines[0].indexOf("PORT"), lines[1].indexOf("22 "));
	}

	/**
	 * WHAT:   A real probe of an open port on the IPv6 loopback, ::1.
	 * WHY:    End to end: parse, connect over IPv6, read the banner.
	 *         Skipped on a machine with IPv6 turned off.
	 *
	 * @throws Exception if the local test server cannot be started
	 */
	@Test
	void probesOverIpv6Loopback() throws Exception
	{
		InetAddress loopback;
		try
		{
			loopback = InetAddress.getByName("::1");
			new ServerSocket(0, 1, loopback).close();
		}
		catch (Exception e)
		{
			loopback = null;
		}
		assumeTrue(loopback != null, "IPv6 is not available here");

		try (ServerSocket server = new ServerSocket(0, 1, loopback))
		{
			Thread.ofVirtual().start(() -> {
				try (Socket client = server.accept())
				{
					client.getOutputStream().write("SSH-2.0-OpenSSH_9.6 v6\r\n".getBytes());
				}
				catch (Exception ignored)
				{
					// the test fails on its own assertions if this does not happen
				}
			});
			String host = TargetParser.parse("[::1]").getFirst();
			List<ScanResult> results = Scanner.scan(List.of(host), List.of(server.getLocalPort()),
				new ScanSettings(1000, 1, 0, true), r -> { });
			assertEquals(ScanResult.State.OPEN, results.getFirst().state());
			assertEquals("SSH-2.0-OpenSSH_9.6 v6", results.getFirst().banner());
		}
	}

	// --------------------------------------------------------------- helpers

	/**
	 * WHAT:   Accepts one connection and counts the bytes the client sends before closing.
	 * PRE:    server is open
	 * RETURN: a future completed with the count
	 *
	 * @param server the listening socket
	 * @return the byte count, when the client has closed
	 */
	private static CompletableFuture<Integer> countBytesOnce(ServerSocket server)
	{
		CompletableFuture<Integer> count = new CompletableFuture<>();
		Thread.ofVirtual().start(() -> {
			try (Socket client = server.accept())
			{
				client.setSoTimeout(3000);
				InputStream in = client.getInputStream();
				int total = 0;
				int read;
				byte[] buffer = new byte[256];
				while ((read = in.read(buffer)) > 0)
				{
					total += read;
				}
				count.complete(total);
			}
			catch (Exception e)
			{
				count.completeExceptionally(e);
			}
		});
		return count;
	}

	/**
	 * WHAT:   Finds local ports that nothing listens on.
	 * WHY:    Opening a server on port 0 picks a free port; closing it leaves
	 *         that port closed, so probes get an instant RST.
	 * RETURN: the ports
	 *
	 * @param count how many
	 * @return closed local ports
	 * @throws Exception if no free ports can be found
	 */
	private static List<Integer> closedPorts(int count) throws Exception
	{
		List<Integer> ports = new ArrayList<>();
		for (int i = 0; i < count; i++)
		{
			try (ServerSocket server = new ServerSocket(0))
			{
				ports.add(server.getLocalPort());
			}
		}
		return ports;
	}
}
