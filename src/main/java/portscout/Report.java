package portscout;

import java.util.List;

/**
 * WHAT:   Formats scan results as a readable table or as JSON.
 * WHY:    People read tables; scripts and other tools read JSON. Keeping
 *         output separate from scanning means either can change alone.
 */
public final class Report
{
	/**
	 * WHAT:   Blocks creating a Report.
	 * WHY:    The class only holds static helpers, so an instance means nothing.
	 */
	private Report()
	{
	}

	/**
	 * WHAT:   Builds a fixed-width table of results with a summary line.
	 * WHY:    Hiding closed ports by default keeps the useful findings on screen.
	 * PRE:    results is not null
	 * RETURN: the table as one string, ending with "N open of M probed"
	 *
	 * @param results    the scan results to print, already sorted
	 * @param showClosed true to also list CLOSED and FILTERED ports
	 * @return the formatted table
	 */
	public static String table(List<ScanResult> results, boolean showClosed)
	{
		StringBuilder sb = new StringBuilder();
		sb.append(String.format("%-16s %-6s %-9s %-6s %s%n", "HOST", "PORT", "STATE", "MS", "BANNER"));
		for (ScanResult r : results)
		{
			if (!showClosed && r.state() != ScanResult.State.OPEN)
			{
				continue;
			}
			sb.append(String.format("%-16s %-6d %-9s %-6d %s%n",
				r.host(), r.port(), r.state(), r.millis(), r.banner()));
		}
		long open = results.stream().filter(r -> r.state() == ScanResult.State.OPEN).count();
		sb.append(String.format("%d open of %d probed%n", open, results.size()));
		return sb.toString();
	}

	/**
	 * WHAT:   Builds a JSON array with one object per result.
	 * WHY:    Written by hand so the project needs no libraries; the banner
	 *         is escaped because it is text from a remote server.
	 * PRE:    results is not null
	 * RETURN: a JSON array of every result, including closed and filtered ones
	 *
	 * @param results the scan results to convert, already sorted
	 * @return the JSON text
	 */
	public static String json(List<ScanResult> results)
	{
		StringBuilder sb = new StringBuilder("[\n");
		for (int i = 0; i < results.size(); i++)
		{
			ScanResult r = results.get(i);
			sb.append(String.format("  {\"host\": \"%s\", \"port\": %d, \"state\": \"%s\", \"banner\": \"%s\", \"ms\": %d}",
				r.host(), r.port(), r.state(), escape(r.banner()), r.millis()));
			sb.append(i < results.size() - 1 ? ",\n" : "\n");
		}
		return sb.append("]\n").toString();
	}

	/**
	 * WHAT:   Escapes backslashes and double quotes for a JSON string.
	 * WHY:    A malicious banner could otherwise break or inject into the JSON.
	 * PRE:    s is not null
	 * RETURN: s safe to place between JSON double quotes
	 *
	 * @param s the raw text
	 * @return the escaped text
	 */
	private static String escape(String s)
	{
		return s.replace("\\", "\\\\").replace("\"", "\\\"");
	}
}
