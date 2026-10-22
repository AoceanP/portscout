package portscout;

import java.util.List;

/**
 * WHAT:   Turns a target like "192.168.1.10" or "192.168.1.0/24" into a list
 *         of IPv4 addresses.
 * WHY:    Scanning a whole subnet is how you find every device on a network,
 *         and CIDR is the standard way network engineers write a subnet.
 */
public final class TargetParser
{
	/**
	 * WHAT:   Blocks creating a TargetParser.
	 * WHY:    The class only holds a static helper, so an instance means nothing.
	 */
	private TargetParser()
	{
	}

	/**
	 * WHAT:   Expands one address or CIDR block into the host addresses in it.
	 * WHY:    The network and broadcast addresses are not real hosts, so
	 *         skipping them saves two useless probes per subnet.
	 * PRE:    target is not null
	 * RETURN: a plain address returns a list holding just that address;
	 *         a CIDR block returns every usable host, lowest first
	 *         (for /24 that is .1 to .254; for /31 and /32 every address, RFC 3021)
	 * THROWS: IllegalArgumentException if target is not a valid IPv4 address,
	 *         the prefix is outside 0 to 32, or the block is bigger than a /16
	 *         (65,534 hosts), so nobody scans half the internet by accident
	 * HOW:    1. Split on "/". With no prefix, validate the address and return it.
	 *         2. Check there are 4 octets, each 0 to 255, and the prefix is 16 to 32.
	 *         3. Pack the octets into one int: {@code a << 24 | b << 16 | c << 8 | d}
	 *         4. Build the mask {@code -1 << (32 - n)}; then
	 *            {@code network = ip & mask} and {@code broadcast = network | ~mask}.
	 *         5. Loop from network + 1 to broadcast - 1 (or network to
	 *            broadcast for /31 and /32) and unpack each int back to
	 *            dotted form with {@code >>>} and {@code & 255}.
	 *
	 * @param target an IPv4 address ("10.0.0.5") or CIDR block ("10.0.0.0/24")
	 * @return the host addresses to scan, lowest first
	 * @throws IllegalArgumentException if target is not valid IPv4 or CIDR,
	 *         or the block is bigger than a /16
	 */
	public static List<String> parse(String target)
	{
		throw new UnsupportedOperationException("TODO: implement TargetParser.parse");
	}
}
