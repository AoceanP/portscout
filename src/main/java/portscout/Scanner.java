package portscout;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.function.Consumer;

/**
 * WHAT:   Runs many port probes at the same time.
 * WHY:    Probes spend almost all their time waiting on the network, so
 *         running them one by one would make a 1,000 port scan take
 *         1,000 timeouts instead of about one.
 */
public final class Scanner
{
	/**
	 * WHAT:   The most probes one scan may run (hosts times ports).
	 * WHY:    Every probe keeps a result in memory; this stops a /16 with all
	 *         65,535 ports (4 billion probes) from exhausting memory.
	 */
	static final long MAX_PROBES = 1_000_000;

	/**
	 * WHAT:   Blocks creating a Scanner.
	 * WHY:    The class only holds static helpers, so an instance means nothing.
	 */
	private Scanner()
	{
	}

	/**
	 * WHAT:   Probes every host and port pair concurrently.
	 * WHY:    Virtual threads make one thread per probe cheap, and a cap on
	 *         concurrent probes keeps the scan from running out of sockets
	 *         or flooding the target like a DoS.
	 * PRE:    hosts is not null and holds dotted IPv4 addresses
	 * PRE:    ports is not null and holds ports between 1 and 65535
	 * PRE:    timeoutMs is a positive integer
	 * PRE:    maxConcurrent is a positive integer
	 * RETURN: one ScanResult per host and port pair, sorted by host, then port
	 * THROWS: IllegalArgumentException if maxConcurrent is below 1 or the scan
	 *         would need more than MAX_PROBES probes
	 *
	 * @param hosts         the IPv4 addresses to scan
	 * @param ports         the TCP ports to probe on every host
	 * @param timeoutMs     connect and read timeout per probe, in milliseconds
	 * @param maxConcurrent the most probes allowed to run at the same time
	 * @return every result, sorted by host, then port
	 * @throws IllegalArgumentException if maxConcurrent is below 1 or the scan is too big
	 */
	public static List<ScanResult> scan(List<String> hosts, List<Integer> ports, int timeoutMs, int maxConcurrent)
	{
		return scan(hosts, ports, timeoutMs, maxConcurrent, result -> { });
	}

	/**
	 * WHAT:   Like scan(hosts, ports, timeoutMs, maxConcurrent), and also hands
	 *         each result to onResult the moment its probe finishes.
	 * WHY:    Lets the recon view draw the scan while it runs, instead of
	 *         only after the last probe.
	 * PRE:    the same as the four-argument scan
	 * PRE:    onResult is not null and safe to call from many threads at once
	 * RETURN: one ScanResult per host and port pair, sorted by host, then port
	 * THROWS: IllegalArgumentException if maxConcurrent is below 1 or the scan is too big
	 *
	 * @param hosts         the IPv4 addresses to scan
	 * @param ports         the TCP ports to probe on every host
	 * @param timeoutMs     connect and read timeout per probe, in milliseconds
	 * @param maxConcurrent the most probes allowed to run at the same time
	 * @param onResult      called with each result as soon as it is known
	 * @return every result, sorted by host, then port
	 * @throws IllegalArgumentException if maxConcurrent is below 1 or the scan is too big
	 */
	public static List<ScanResult> scan(List<String> hosts, List<Integer> ports, int timeoutMs, int maxConcurrent,
		Consumer<ScanResult> onResult)
	{
		if (maxConcurrent < 1)
		{
			throw new IllegalArgumentException("concurrency must be at least 1");
		}
		long total = (long) hosts.size() * ports.size();
		if (total > MAX_PROBES)
		{
			throw new IllegalArgumentException(total + " probes is too many; the limit is " + MAX_PROBES
				+ ". Use a smaller subnet or fewer ports.");
		}

		Semaphore permits = new Semaphore(maxConcurrent);
		List<Future<ScanResult>> futures = new ArrayList<>((int) total);

		// closing the executor (end of the try block) waits for every task
		try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor())
		{
			for (String host : hosts)
			{
				for (int port : ports)
				{
					// take the permit before starting the thread, so at most
					// maxConcurrent probe threads exist at any moment
					permits.acquireUninterruptibly();
					futures.add(executor.submit(() -> {
						try
						{
							ScanResult result = PortProbe.probe(host, port, timeoutMs);
							onResult.accept(result);
							return result;
						}
						finally
						{
							permits.release();
						}
					}));
				}
			}
		}

		List<ScanResult> results = new ArrayList<>(futures.size());
		for (Future<ScanResult> future : futures)
		{
			results.add(future.resultNow());
		}

		// threads finish in any order; compare hosts as numbers so .9 comes before .10
		results.sort(Comparator
			.comparingLong((ScanResult r) -> Integer.toUnsignedLong(TargetParser.toInt(r.host())))
			.thenComparingInt(ScanResult::port));
		return results;
	}
}
