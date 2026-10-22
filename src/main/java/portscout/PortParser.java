package portscout;

import java.util.List;

/**
 * WHAT:   Turns a port spec like "22,80,443,8000-8100" into a list of ports.
 * WHY:    People type ports the way nmap accepts them, but the scanner
 *         needs plain numbers to loop over.
 */
public final class PortParser
{
	/**
	 * WHAT:   Blocks creating a PortParser.
	 * WHY:    The class only holds a static helper, so an instance means nothing.
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
	 * HOW:    1. Remove spaces and split on commas.
	 *         2. Each part is a single port ("80") or a range ("8000-8100");
	 *            split a range on "-" and parse both ends with Integer.parseInt.
	 *         3. Turn a NumberFormatException into IllegalArgumentException.
	 *         4. Add every port to a TreeSet, which sorts and removes
	 *            duplicates, then return it as a List.
	 *
	 * @param spec ports and ranges separated by commas, e.g. "22,80,8000-8100"
	 * @return the ports in ascending order, without duplicates
	 * @throws IllegalArgumentException if spec is empty, not a number, out of
	 *         range 1 to 65535, or has a backwards range
	 */
	public static List<Integer> parse(String spec)
	{
		throw new UnsupportedOperationException("TODO: implement PortParser.parse");
	}
}
