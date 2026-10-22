package portscout;

import java.util.ArrayList;
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
	 * WHAT:   The biggest block allowed, a /16 (65,534 hosts).
	 * WHY:    A typo like /8 would mean 16 million hosts; refusing it stops
	 *         anyone scanning a huge network by accident.
	 */
	private static final int SMALLEST_PREFIX = 16;

	/**
	 * WHAT:   Blocks creating a TargetParser.
	 * WHY:    The class only holds static helpers, so an instance means nothing.
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
	 *
	 * @param target an IPv4 address ("10.0.0.5") or CIDR block ("10.0.0.0/24")
	 * @return the host addresses to scan, lowest first
	 * @throws IllegalArgumentException if target is not valid IPv4 or CIDR,
	 *         or the block is bigger than a /16
	 */
	public static List<String> parse(String target)
	{
		String[] parts = target.trim().split("/", -1);
		if (parts.length > 2)
		{
			throw new IllegalArgumentException("not an IPv4 address or CIDR block: " + target);
		}

		int address = toInt(parts[0]);
		if (parts.length == 1)
		{
			return List.of(toDotted(address));
		}

		int prefix = toPrefix(parts[1]);
		// prefix is at least 16, so the shift is 0 to 16 and never hits Java's
		// "shift by 32 does nothing" trap
		int mask = -1 << (32 - prefix);
		int network = address & mask;
		int broadcast = network | ~mask;

		// work in long so addresses above 127.255.255.255 are not negative
		long first = Integer.toUnsignedLong(network);
		long last = Integer.toUnsignedLong(broadcast);
		if (prefix < 31)
		{
			first++;
			last--;
		}

		List<String> hosts = new ArrayList<>((int) (last - first + 1));
		for (long host = first; host <= last; host++)
		{
			hosts.add(toDotted((int) host));
		}
		return hosts;
	}

	/**
	 * WHAT:   Packs a dotted IPv4 address into one 32-bit int.
	 * WHY:    Subnet math is bitwise AND and OR on the whole address at once.
	 *         Scanner also uses it to sort hosts numerically.
	 * PRE:    address is not null
	 * RETURN: the address as an int, first octet in the highest 8 bits
	 * THROWS: IllegalArgumentException if address is not four octets of 0 to 255
	 *
	 * @param address a dotted address, e.g. "192.168.1.10"
	 * @return the address packed into an int
	 * @throws IllegalArgumentException if address is not valid IPv4
	 */
	static int toInt(String address)
	{
		String[] octets = address.split("[.]", -1);
		if (octets.length != 4)
		{
			throw new IllegalArgumentException("not an IPv4 address: " + address);
		}

		int packed = 0;
		for (String octet : octets)
		{
			// digits only, so "+1" or " 1" are refused even though parseInt allows them
			if (!octet.matches("[0-9]{1,3}") || Integer.parseInt(octet) > 255)
			{
				throw new IllegalArgumentException("not an IPv4 address: " + address);
			}
			packed = packed << 8 | Integer.parseInt(octet);
		}
		return packed;
	}

	/**
	 * WHAT:   Unpacks a 32-bit int back into dotted IPv4 form.
	 * WHY:    Sockets and people both expect "a.b.c.d" text.
	 * RETURN: the address as text, e.g. "192.168.1.10"
	 *
	 * @param address the packed address
	 * @return the dotted address
	 */
	private static String toDotted(int address)
	{
		// >>> shifts in zeros, so the first octet is never negative
		return (address >>> 24) + "." + (address >> 16 & 255) + "." + (address >> 8 & 255) + "." + (address & 255);
	}

	/**
	 * WHAT:   Reads and checks the prefix length after the "/".
	 * WHY:    Gives a clear error for both impossible and too-big prefixes.
	 * PRE:    text is not null
	 * RETURN: the prefix, 16 to 32
	 * THROWS: IllegalArgumentException if text is not 0 to 32, or is below 16
	 *
	 * @param text the prefix text, e.g. "24"
	 * @return the prefix length
	 * @throws IllegalArgumentException if the prefix is invalid or too big a block
	 */
	private static int toPrefix(String text)
	{
		int prefix;
		try
		{
			prefix = Integer.parseInt(text);
		}
		catch (NumberFormatException e)
		{
			throw new IllegalArgumentException("not a prefix length: '" + text + "'");
		}

		if (prefix < 0 || prefix > 32)
		{
			throw new IllegalArgumentException("prefix must be 0 to 32: /" + prefix);
		}
		if (prefix < SMALLEST_PREFIX)
		{
			throw new IllegalArgumentException("/" + prefix + " is too big to scan; use /16 or smaller");
		}
		return prefix;
	}
}
