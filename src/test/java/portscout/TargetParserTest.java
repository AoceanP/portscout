package portscout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * WHAT:   Tests for TargetParser.parse.
 * WHY:    Subnet math is easy to get off by one, and a wrong answer means
 *         scanning hosts you did not mean to scan.
 */
class TargetParserTest
{
	/**
	 * WHAT:   A plain address with no prefix.
	 * WHY:    Scanning one machine is the most common use.
	 */
	@Test
	void singleAddress()
	{
		assertEquals(List.of("10.0.0.5"), TargetParser.parse("10.0.0.5"));
	}

	/**
	 * WHAT:   A /24 home network.
	 * WHY:    Checks the network (.0) and broadcast (.255) addresses are skipped.
	 */
	@Test
	void slash24SkipsNetworkAndBroadcast()
	{
		List<String> hosts = TargetParser.parse("192.168.1.0/24");
		assertEquals(254, hosts.size());
		assertEquals("192.168.1.1", hosts.get(0));
		assertEquals("192.168.1.254", hosts.get(253));
	}

	/**
	 * WHAT:   A CIDR written with a host address instead of the network address.
	 * WHY:    "192.168.1.77/24" means the same subnet, so the mask must be applied.
	 */
	@Test
	void hostBitsInInputAreIgnored()
	{
		assertEquals(TargetParser.parse("192.168.1.0/24"), TargetParser.parse("192.168.1.77/24"));
	}

	/**
	 * WHAT:   A /30, the usual point-to-point link between two routers.
	 * WHY:    Smallest normal subnet: four addresses, two usable hosts.
	 */
	@Test
	void slash30()
	{
		assertEquals(List.of("10.0.0.1", "10.0.0.2"), TargetParser.parse("10.0.0.0/30"));
	}

	/**
	 * WHAT:   The /31 and /32 special cases.
	 * WHY:    They have no network or broadcast address (RFC 3021), so
	 *         skipping two addresses would leave nothing to scan.
	 */
	@Test
	void slash31And32()
	{
		assertEquals(List.of("10.0.0.0", "10.0.0.1"), TargetParser.parse("10.0.0.0/31"));
		assertEquals(List.of("10.0.0.9"), TargetParser.parse("10.0.0.9/32"));
	}

	/**
	 * WHAT:   A /23, which spans two third octets.
	 * WHY:    Catches code that only changes the last octet.
	 */
	@Test
	void crossesOctetBoundary()
	{
		List<String> hosts = TargetParser.parse("10.0.0.0/23");
		assertEquals(510, hosts.size());
		assertEquals("10.0.1.254", hosts.get(509));
	}

	/**
	 * WHAT:   An octet over 255, too few octets, a prefix over 32, a /8 and a hostname.
	 * WHY:    Each must be refused; the /8 is valid IPv4 but far too big to scan.
	 */
	@Test
	void rejectsBadInput()
	{
		assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("256.1.1.1"));
		assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("10.0.0"));
		assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("10.0.0.0/33"));
		assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("10.0.0.0/8"));
		assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("example"));
	}

	/**
	 * WHAT:   Addresses at the top of the IPv4 space.
	 * WHY:    Above 127.255.255.255 a Java int is negative, so the math must
	 *         stay unsigned or the loop would run backwards.
	 */
	@Test
	void highAddresses()
	{
		List<String> hosts = TargetParser.parse("255.255.255.0/30");
		assertEquals(List.of("255.255.255.1", "255.255.255.2"), hosts);
	}

	/**
	 * WHAT:   Octets with a sign, a space, or a missing number.
	 * WHY:    Integer.parseInt accepts "+1", so the parser must check digits itself.
	 */
	@Test
	void rejectsSneakyOctets()
	{
		assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("10.+1.0.1"));
		assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("10. 1.0.1"));
		assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("10..0.1"));
		assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("10.0.0.1/24/8"));
	}
}
