package portscout;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/**
 * WHAT:   Turns a port spec like "22,80,443,8000-8100" into a list of ports.
 * WHY:    People type ports the way nmap accepts them, but the scanner
 *         needs plain numbers to loop over.
 */
public final class PortParser
{
	/** WHAT: the lowest valid TCP port. Port 0 is reserved and cannot be connected to. */
	private static final int MIN_PORT = 1;

	/** WHAT: the highest valid TCP port, the largest 16-bit number. */
	private static final int MAX_PORT = 65535;

	/**
	 * WHAT:   Blocks creating a PortParser.
	 * WHY:    The class only holds static helpers, so an instance means nothing.
	 */
	private PortParser()
	{
	}

	/**
	 * WHAT:   Parses a comma separated list of ports and ranges.
	 * WHY:    Validating here means the scanner never sees port 0 or 70000.
	 * PRE:    spec is not null
	 * RETURN: every port in spec, with no duplicates, sorted ascending
	 * THROWS: IllegalArgumentException if spec is empty, has text that is
	 *         not a number, a port outside 1 to 65535, or a range whose
	 *         start is bigger than its end
	 *
	 * @param spec ports and ranges separated by commas, e.g. "22,80,8000-8100"
	 * @return the ports in ascending order, without duplicates
	 * @throws IllegalArgumentException if spec is empty, not a number, out of
	 *         range 1 to 65535, or has a backwards range
	 */
	public static List<Integer> parse(String spec)
	{
		String cleaned = spec.replace(" ", "");
		if (cleaned.isEmpty())
		{
			throw new IllegalArgumentException("no ports given");
		}

		// a TreeSet keeps the ports sorted and drops duplicates for free
		TreeSet<Integer> ports = new TreeSet<>();
		for (String part : cleaned.split(",", -1))
		{
			String[] ends = part.split("-", -1);
			if (ends.length > 2)
			{
				throw new IllegalArgumentException("bad port range: " + part);
			}

			int start = toPort(ends[0]);
			int end = ends.length == 2 ? toPort(ends[1]) : start;
			if (start > end)
			{
				throw new IllegalArgumentException("range start is bigger than its end: " + part);
			}

			for (int port = start; port <= end; port++)
			{
				ports.add(port);
			}
		}
		return new ArrayList<>(ports);
	}

	/**
	 * WHAT:   Converts one piece of text into a port number.
	 * WHY:    Keeps the number and range checks in one place for both
	 *         single ports and the two ends of a range.
	 * PRE:    text is not null
	 * RETURN: the port number
	 * THROWS: IllegalArgumentException if text is not a number from 1 to 65535
	 *
	 * @param text the text to convert, e.g. "443"
	 * @return the port number
	 * @throws IllegalArgumentException if text is not a valid port
	 */
	private static int toPort(String text)
	{
		int port;
		try
		{
			port = Integer.parseInt(text);
		}
		catch (NumberFormatException e)
		{
			throw new IllegalArgumentException("not a port number: '" + text + "'");
		}

		if (port < MIN_PORT || port > MAX_PORT)
		{
			throw new IllegalArgumentException("port out of range 1-65535: " + port);
		}
		return port;
	}
}
