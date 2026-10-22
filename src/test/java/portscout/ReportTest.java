package portscout;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * WHAT:   Tests for Report.table and Report.json.
 * WHY:    The report is what the user actually reads, and the JSON is what
 *         other tools parse, so both must be exact.
 */
class ReportTest
{
	/** WHAT: one result in each state, reused by every test. */
	private static final List<ScanResult> RESULTS = List.of(
		new ScanResult("10.0.0.1", 22, ScanResult.State.OPEN, "SSH-2.0-OpenSSH_9.6", 3),
		new ScanResult("10.0.0.1", 23, ScanResult.State.CLOSED, "", 1),
		new ScanResult("10.0.0.1", 25, ScanResult.State.FILTERED, "", 500));

	/**
	 * WHAT:   The default table.
	 * WHY:    Only open ports are interesting, but the summary still counts everything.
	 */
	@Test
	void tableShowsOnlyOpenByDefault()
	{
		String table = Report.table(RESULTS, false);
		assertTrue(table.contains("SSH-2.0-OpenSSH_9.6"));
		assertFalse(table.contains("CLOSED"));
		assertFalse(table.contains("FILTERED"));
		assertTrue(table.contains("1 open of 3 probed"));
	}

	/**
	 * WHAT:   The table with --all.
	 * WHY:    Closed vs filtered is the firewall evidence, so --all must show both.
	 */
	@Test
	void tableShowsEverythingWithAll()
	{
		String table = Report.table(RESULTS, true);
		assertTrue(table.contains("CLOSED"));
		assertTrue(table.contains("FILTERED"));
	}

	/**
	 * WHAT:   A banner containing a quote and a backslash.
	 * WHY:    Banners come from remote servers; unescaped they would break
	 *         the JSON or let a server inject its own fields.
	 */
	@Test
	void jsonEscapesBanner()
	{
		String json = Report.json(List.of(
			new ScanResult("10.0.0.1", 80, ScanResult.State.OPEN, "evil\" \\ banner", 2)));
		assertTrue(json.contains("\"banner\": \"evil\\\" \\\\ banner\""));
	}

	/**
	 * WHAT:   JSON for every state.
	 * WHY:    Unlike the table, JSON is for tools, so it must include closed and filtered ports.
	 */
	@Test
	void jsonIncludesEveryResult()
	{
		String json = Report.json(RESULTS);
		assertTrue(json.contains("\"port\": 22"));
		assertTrue(json.contains("\"port\": 23"));
		assertTrue(json.contains("\"port\": 25"));
	}
}
