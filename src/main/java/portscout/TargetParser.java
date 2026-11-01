package portscout;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * WHAT:   Turns a target like "192.168.1.10", "192.168.1.0/24" or "2001:db8::1"
 *         into a list of addresses.
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
	 *         (for /24 that is .1 to .254; for /31 and /32 every address, RFC 3021);
	 *         an IPv6 address returns just that address (see parseIpv6)
	 * THROWS: IllegalArgumentException if target is not a valid IPv4 or IPv6 address,
	 *         the prefix is outside 0 to 32, the block is bigger than a /16,
	 *         or it is an IPv6 subnet
	 *
	 * @param target an IPv4 address ("10.0.0.5"), CIDR block ("10.0.0.0/24") or IPv6 address ("2001:db8::1")
	 * @return the host addresses to scan, lowest first
	 * @throws IllegalArgumentException if target is not valid IPv4 or CIDR,
	 *         or the block is bigger than a /16
	 */
	public static List<String> parse(String target)
	{
		if (target.contains(":"))
		{
			return List.of(parseIpv6(target.trim()));
		}
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
	 * WHAT:   Orders results by address as numbers: IPv4 first, then IPv6.
	 * WHY:    Threads finish in any order, and as text ".10" would sort before ".9".
	 */
	static final Comparator<ScanResult> HOST_ORDER = Comparator.comparing(ScanResult::host, TargetParser::compareHosts);

	/**
	 * WHAT:   Checks and normalises one IPv6 address.
	 * WHY:    Only single addresses are accepted. An IPv6 subnet cannot be
	 *         swept: even the usual smallest one, a /64, holds about 18
	 *         quintillion addresses, so a "/64 scan" would never finish (this
	 *         is also why attackers find IPv6 hosts from DNS and logs, not by
	 *         sweeping). The address is parsed as a literal, never looked up
	 *         in DNS, and written the standard short way (RFC 5952), so
	 *         "2001:DB8:0:0::1" and "2001:db8::1" are the same target.
	 * PRE:    text is not null and contains ':'
	 * RETURN: the address in RFC 5952 form; an IPv4-mapped address
	 *         ("::ffff:192.0.2.1") is returned as plain IPv4
	 * THROWS: IllegalArgumentException if text is a subnet, has a zone ("%eth0"),
	 *         or is not a valid IPv6 address
	 *
	 * @param text the address, optionally in brackets, e.g. "[::1]"
	 * @return the normalised address
	 * @throws IllegalArgumentException if the address is invalid or a subnet
	 */
	static String parseIpv6(String text)
	{
		String literal = text.startsWith("[") && text.endsWith("]") ? text.substring(1, text.length() - 1) : text;
		if (literal.contains("/"))
		{
			throw new IllegalArgumentException("IPv6 subnets cannot be scanned (a /64 alone holds about "
				+ "18 quintillion addresses); give one IPv6 address instead: " + text);
		}
		// hex digits, colons and dots (for an embedded IPv4 tail) only: nothing that could become a DNS lookup
		if (!literal.matches("[0-9A-Fa-f:.]{2,45}"))
		{
			throw new IllegalArgumentException("not an IPv6 address: " + text);
		}
		InetAddress address;
		try
		{
			address = InetAddress.getByName(literal);
		}
		catch (UnknownHostException e)
		{
			throw new IllegalArgumentException("not an IPv6 address: " + text);
		}
		return address instanceof Inet4Address ? address.getHostAddress() : compress(address.getAddress());
	}

	/**
	 * WHAT:   Writes 16 address bytes the short standard way (RFC 5952).
	 * WHY:    Java writes "0:0:0:0:0:0:0:1"; people and every other tool
	 *         write "::1". Lowercase, no leading zeros, and the longest run
	 *         of two or more zero groups (the first, on a tie) becomes "::".
	 * PRE:    bytes has length 16
	 * RETURN: the address text
	 *
	 * @param bytes the address
	 * @return the short form
	 */
	static String compress(byte[] bytes)
	{
		int[] groups = new int[8];
		for (int i = 0; i < 8; i++)
		{
			groups[i] = (bytes[2 * i] & 0xFF) << 8 | bytes[2 * i + 1] & 0xFF;
		}

		// find the longest run of zero groups
		int bestStart = -1;
		int bestLength = 1; // a single zero group is never shortened
		for (int i = 0; i < 8; )
		{
			if (groups[i] != 0)
			{
				i++;
				continue;
			}
			int end = i;
			while (end < 8 && groups[end] == 0)
			{
				end++;
			}
			if (end - i > bestLength)
			{
				bestStart = i;
				bestLength = end - i;
			}
			i = end;
		}

		StringBuilder out = new StringBuilder();
		for (int i = 0; i < 8; i++)
		{
			if (i == bestStart)
			{
				out.append("::");
				i += bestLength - 1;
				continue;
			}
			if (!out.isEmpty() && out.charAt(out.length() - 1) != ':')
			{
				out.append(':');
			}
			out.append(Integer.toHexString(groups[i]));
		}
		return out.toString();
	}

	/**
	 * WHAT:   Compares two addresses as numbers.
	 * WHY:    Used by HOST_ORDER; IPv4 (4 bytes) sorts before IPv6 (16 bytes).
	 * PRE:    both are addresses this class produced
	 * RETURN: negative, zero or positive, like Comparator.compare
	 *
	 * @param a the first address
	 * @param b the second address
	 * @return the comparison
	 */
	private static int compareHosts(String a, String b)
	{
		byte[] x = toBytes(a);
		byte[] y = toBytes(b);
		return x.length != y.length ? Integer.compare(x.length, y.length) : Arrays.compareUnsigned(x, y);
	}

	/**
	 * WHAT:   The bytes of an IPv4 or IPv6 address.
	 * PRE:    host is an address this class produced
	 * RETURN: 4 or 16 bytes
	 *
	 * @param host the address
	 * @return its bytes
	 */
	private static byte[] toBytes(String host)
	{
		if (!host.contains(":"))
		{
			int packed = toInt(host);
			return new byte[] {(byte) (packed >>> 24), (byte) (packed >> 16), (byte) (packed >> 8), (byte) packed};
		}
		try
		{
			return InetAddress.getByName(host).getAddress(); // a literal: no DNS lookup
		}
		catch (UnknownHostException e)
		{
			throw new IllegalArgumentException("not an address: " + host, e);
		}
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
