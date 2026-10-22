package portscout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * WHAT:   Tests for PortParser.parse.
 * WHY:    Bad port input is the most common user mistake, so every rule in
 *         the spec gets its own test.
 */
class PortParserTest
{
	/**
	 * WHAT:   One port on its own.
	 * WHY:    The simplest valid input must work before anything else.
	 */
	@Test
	void singlePort()
	{
		assertEquals(List.of(80), PortParser.parse("80"));
	}

	/**
	 * WHAT:   Single ports and a range mixed, given out of order.
	 * WHY:    Checks ranges expand and the output comes back sorted.
	 */
	@Test
	void listAndRange()
	{
		assertEquals(List.of(22, 80, 8000, 8001, 8002), PortParser.parse("80,22,8000-8002"));
	}

	/**
	 * WHAT:   Extra spaces and a repeated port.
	 * WHY:    People type "80, 443"; each port should be probed once.
	 */
	@Test
	void spacesAndDuplicates()
	{
		assertEquals(List.of(22, 80), PortParser.parse(" 80 , 22,80 "));
	}

	/**
	 * WHAT:   Every possible TCP port.
	 * WHY:    Checks both edges, 1 and 65535, are accepted.
	 */
	@Test
	void fullRange()
	{
		assertEquals(65535, PortParser.parse("1-65535").size());
	}

	/**
	 * WHAT:   Port 0, port 65536, a backwards range, text and empty input.
	 * WHY:    Each must fail loudly instead of scanning something unexpected.
	 */
	@Test
	void rejectsBadInput()
	{
		assertThrows(IllegalArgumentException.class, () -> PortParser.parse("0"));
		assertThrows(IllegalArgumentException.class, () -> PortParser.parse("65536"));
		assertThrows(IllegalArgumentException.class, () -> PortParser.parse("100-50"));
		assertThrows(IllegalArgumentException.class, () -> PortParser.parse("abc"));
		assertThrows(IllegalArgumentException.class, () -> PortParser.parse(""));
	}
}
