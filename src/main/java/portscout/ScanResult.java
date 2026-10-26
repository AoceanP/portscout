package portscout;

/**
 * WHAT:   The result of probing one TCP port on one host.
 * WHY:    One immutable record per probe lets many threads produce results
 *         safely, and lets Report print them without knowing how they were made.
 * PRE:    host is a dotted IPv4 address
 * PRE:    port is between 1 and 65535
 * PRE:    state is not null
 * PRE:    banner is not null ("" when the service sent nothing)
 * PRE:    millis is 0 or more
 * PRE:    service is not null (Service.UNKNOWN when not identified)
 *
 * @param host    the IPv4 address that was scanned, e.g. "192.168.1.10"
 * @param port    the TCP port that was probed
 * @param state   whether the port was OPEN, CLOSED or FILTERED
 * @param banner  the first line the service sent, or "" if none
 * @param millis  how long the probe took, in milliseconds
 * @param service what is running there, if the port is open
 */
public record ScanResult(String host, int port, State state, String banner, long millis, Service service)
{
	/**
	 * WHAT:   Builds a result and identifies the service from the banner line.
	 * WHY:    Convenient when only the first line is known (tests, reports);
	 *         PortProbe uses the full constructor, because it has the whole
	 *         reply, including HTTP headers after the first line.
	 * PRE:    the same as the record's
	 *
	 * @param host   the IPv4 address that was scanned
	 * @param port   the TCP port that was probed
	 * @param state  OPEN, CLOSED or FILTERED
	 * @param banner the first line the service sent, or ""
	 * @param millis how long the probe took, in milliseconds
	 */
	public ScanResult(String host, int port, State state, String banner, long millis)
	{
		this(host, port, state, banner, millis,
			state == State.OPEN ? Service.identify(port, banner) : Service.UNKNOWN);
	}

	/**
	 * WHAT:   The three answers a TCP connect scan can get.
	 * WHY:    Each maps to a different packet exchange, which is what tells a
	 *         network engineer whether a service, a host or a firewall answered.
	 */
	public enum State
	{
		/** WHAT: the handshake completed (SYN, SYN-ACK, ACK). */
		OPEN,
		/** WHAT: the host refused with a reset (SYN, RST). */
		CLOSED,
		/** WHAT: nothing came back before the timeout, usually a firewall dropping packets. */
		FILTERED
	}
}
