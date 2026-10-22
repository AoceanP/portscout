package portscout;

import java.util.List;

/**
 * WHAT:   Runs many port probes at the same time.
 * WHY:    Probes spend almost all their time waiting on the network, so
 *         running them one by one would make a 1,000 port scan take
 *         1,000 timeouts instead of about one.
 */
public final class Scanner
{
	/**
	 * WHAT:   Blocks creating a Scanner.
	 * WHY:    The class only holds a static helper, so an instance means nothing.
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
	 * HOW:    1. Create a Semaphore with maxConcurrent permits.
	 *         2. In try-with-resources, open
	 *            Executors.newVirtualThreadPerTaskExecutor() (Java 21).
	 *         3. For each host and port, submit a task that acquires a permit,
	 *            calls PortProbe.probe, and releases the permit in finally.
	 *            Keep every returned Future in a list.
	 *         4. Leaving the try block waits for every task to finish.
	 *         5. Collect each Future's result and sort by host, then port.
	 *            Compare hosts as numbers, not strings, or "10.0.0.10"
	 *            sorts before "10.0.0.9".
	 *
	 * @param hosts         the IPv4 addresses to scan
	 * @param ports         the TCP ports to probe on every host
	 * @param timeoutMs     connect and read timeout per probe, in milliseconds
	 * @param maxConcurrent the most probes allowed to run at the same time
	 * @return every result, sorted by host, then port
	 */
	public static List<ScanResult> scan(List<String> hosts, List<Integer> ports, int timeoutMs, int maxConcurrent)
	{
		throw new UnsupportedOperationException("TODO: implement Scanner.scan");
	}
}
