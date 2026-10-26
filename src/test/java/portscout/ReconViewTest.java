package portscout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * WHAT:   Tests for the recon view's frames.
 * WHY:    The view is redrawn in place, so every frame must have the same
 *         number of lines, and every framed line the same width, or the
 *         picture tears.
 */
class ReconViewTest
{
	/**
	 * WHAT:   Removes ANSI escape codes, leaving what a person sees.
	 *
	 * @param text a frame
	 * @return the visible text
	 */
	private static String visible(String text)
	{
		return text.replaceAll("\u001b\\[[0-9;?]*[A-Za-z]", "");
	}

	/**
	 * WHAT:   Checks the frame's height and that every framed line is 78 columns.
	 *
	 * @param frame the frame
	 */
	private static void assertShape(String frame)
	{
		String[] lines = visible(frame).split("\n", -1);
		assertEquals(ReconView.LINES + 1, lines.length, "line count"); // the text after the last newline is empty
		for (int i = 0; i < ReconView.LINES; i++)
		{
			assertEquals(78, lines[i].length(), "width of line " + (i + 1) + ": " + lines[i]);
		}
	}

	/** WHAT: ports 1 to n. */
	private static List<Integer> ports(int n)
	{
		List<Integer> ports = new ArrayList<>();
		for (int p = 1; p <= n; p++)
		{
			ports.add(p);
		}
		return ports;
	}

	/** WHAT: a view before any answer has arrived. */
	@Test
	void emptyView()
	{
		ReconView view = new ReconView(List.of("127.0.0.1"), ports(1024), "127.0.0.1");
		String frame = view.render(0, false);
		assertShape(frame);
		assertTrue(visible(frame).contains("no open ports yet"));
		assertTrue(visible(frame).contains("SCANNING"));
	}

	/** WHAT: a finished scan with services, closed and filtered ports. */
	@Test
	void finishedScanShowsServices()
	{
		ReconView view = new ReconView(List.of("10.0.0.5"), ports(1024), "10.0.0.5");
		for (int port = 1; port <= 1024; port++)
		{
			ScanResult.State state = port == 137 ? ScanResult.State.FILTERED : ScanResult.State.CLOSED;
			String banner = "";
			if (port == 22)
			{
				state = ScanResult.State.OPEN;
				banner = "SSH-2.0-OpenSSH_9.6p1";
			}
			if (port == 445)
			{
				state = ScanResult.State.OPEN;
			}
			view.record(new ScanResult("10.0.0.5", port, state, banner, 1));
		}
		String frame = visible(view.render(5, true));
		assertShape(view.render(5, true));
		assertTrue(frame.contains("DONE"));
		assertTrue(frame.contains("22     ssh"));
		assertTrue(frame.contains("OpenSSH 9.6p1"));
		assertTrue(frame.contains("smb?"));
		assertTrue(frame.contains("guessed from the port"));
		assertTrue(frame.contains("OPEN 2"));
		assertTrue(frame.contains("CLOSED 1,021"));
		assertTrue(frame.contains("FILTERED 1"));
		assertTrue(frame.contains("1,024 / 1,024"));
	}

	/** WHAT: more probes than pixels: each pixel stands for several. */
	@Test
	void largeScanGroupsProbes()
	{
		ReconView view = new ReconView(List.of("10.0.0.1", "10.0.0.2", "10.0.0.3"), ports(1000), "10.0.0.0/30");
		String frame = view.render(0, false);
		assertShape(frame);
		assertTrue(visible(frame).contains("one pixel per 3 probes"));
	}

	/** WHAT: more open ports than cards: the rest are pointed to the table. */
	@Test
	void manyServicesAreCapped()
	{
		ReconView view = new ReconView(List.of("10.0.0.1"), ports(20), "10.0.0.1");
		for (int port = 1; port <= 20; port++)
		{
			view.record(new ScanResult("10.0.0.1", port, ScanResult.State.OPEN, "", 1));
		}
		String frame = view.render(0, true);
		assertShape(frame);
		assertTrue(visible(frame).contains("showing 6 of 20"));
	}

	/** WHAT: the same probe recorded twice is counted once. */
	@Test
	void duplicateResultIgnored()
	{
		ReconView view = new ReconView(List.of("10.0.0.1"), ports(2), "10.0.0.1");
		ScanResult r = new ScanResult("10.0.0.1", 1, ScanResult.State.CLOSED, "", 1);
		view.record(r);
		view.record(r);
		assertTrue(visible(view.render(0, false)).contains("1 / 2"));
	}

	/** WHAT: escape codes take no width; ordinary characters take one each. */
	@Test
	void widthIgnoresEscapes()
	{
		assertEquals(5, ReconView.width("\u001b[38;2;1;2;3mhello\u001b[0m"));
	}
}
