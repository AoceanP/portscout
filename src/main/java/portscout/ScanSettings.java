package portscout;

/**
 * WHAT:   How a scan behaves: timeout, concurrency, rate, and whether to talk to services.
 * WHY:    One value to pass around instead of a growing list of parameters,
 *         and one place that checks them all.
 * PRE:    timeoutMs and maxConcurrent are at least 1; ratePerSecond is 0 (no limit) or more
 *
 * @param timeoutMs     connect and read timeout per probe, in milliseconds
 * @param maxConcurrent the most probes allowed to run at the same time
 * @param ratePerSecond the most probes started per second, or 0 for no limit
 * @param grabBanners   true to read (and if needed ask for) each open port's banner;
 *                      false to only connect and close, sending nothing
 */
public record ScanSettings(int timeoutMs, int maxConcurrent, int ratePerSecond, boolean grabBanners)
{
	/**
	 * WHAT:   Checks the settings when they are created.
	 * WHY:    A bad setting is refused before any probe is sent.
	 * THROWS: IllegalArgumentException naming the first bad setting
	 *
	 * @throws IllegalArgumentException if a setting is out of range
	 */
	public ScanSettings
	{
		if (timeoutMs < 1)
		{
			throw new IllegalArgumentException("timeout must be at least 1 ms");
		}
		if (maxConcurrent < 1)
		{
			throw new IllegalArgumentException("concurrency must be at least 1");
		}
		if (ratePerSecond < 0)
		{
			throw new IllegalArgumentException("rate must be 0 (no limit) or more");
		}
	}
}
