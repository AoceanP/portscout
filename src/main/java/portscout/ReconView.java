package portscout;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * WHAT:   The recon view: a live, pixel-art picture of a scan in the
 *         terminal. You on the left, the target on the right, probes moving
 *         along the wire, a map with one pixel per port filling in as answers
 *         arrive, and a card with a small icon for every service found.
 * WHY:    A table at the end shows the result; the view shows the scan
 *         itself, which makes "open", "closed" and "filtered" easy to
 *         understand at a glance. It matches the scan watch in wiresight,
 *         the same scan seen from the network's side.
 *         Pixels are drawn with half-block characters and 24-bit colour,
 *         two pixels per character cell. Every character used exists in
 *         code page 437, the Windows console default, so it shows correctly
 *         there as well as in UTF-8 terminals.
 */
public final class ReconView
{
	/** WHAT: lines in every frame, so the screen can be redrawn in place. */
	public static final int LINES = 28;

	/** WHAT: width inside the frame; the whole view is 78 columns. */
	private static final int INNER = 76;
	/** WHAT: the port map: 64 x 16 pixels, at most 1,024 cells. */
	private static final int GRID_W = 64;
	private static final int GRID_H = 16;
	private static final int GRID_CELLS = GRID_W * GRID_H;
	/** WHAT: sprite size in pixels (two pixel rows per text line). */
	private static final int SPRITE_W = 16;
	private static final int SPRITE_H = 12;
	/** WHAT: the wire between the sprites, in columns. */
	private static final int WIRE_W = 32;
	/** WHAT: service cards shown (two per line, three lines of cards). */
	private static final int CARDS = 6;
	/** WHAT: the progress bar, in cells. */
	private static final int BAR_W = 16;
	/** WHAT: activity this recent makes the wire animate, in nanoseconds. */
	private static final long ACTIVE_NANOS = 400_000_000L;

	// colours: dark slate scenery, amber for probes, green for open, red for closed
	private static final int[] FRAME = {107, 116, 132};
	private static final int[] SCREEN = {27, 32, 41};
	private static final int[] TEXT_GREEN = {91, 211, 138};
	private static final int[] AMBER = {232, 154, 60};
	private static final int[] SILVER = {154, 163, 177};
	private static final int[] PANEL = {43, 49, 60};
	private static final int[] VENT = {61, 69, 82};
	private static final int[] LED_OFF = {58, 66, 80};
	private static final int[] GREEN = {70, 208, 122};
	private static final int[] RED = {224, 96, 90};
	private static final int[] CLOSED = {72, 44, 50};
	private static final int[] FILTERED = {150, 110, 50};
	private static final int[] DIM = {120, 128, 140};
	private static final int[] WHITE = {245, 245, 240};
	private static final int[] BORDER = {70, 78, 92};

	/** WHAT: you, the scanner: a monitor with a terminal on it; '1' is the cursor. */
	private static final String[] SCANNER_ART = {
		"................",
		".kkkkkkkkkkkkkk.",
		".kddddddddddddk.",
		".kdggdgggggdddk.",
		".kddddddddddddk.",
		".kdgggdggdgggdk.",
		".kddddddddddddk.",
		".kdg1dddddddddk.",
		".kddddddddddddk.",
		".kkkkkkkkkkkkkk.",
		"......kkkk......",
		"....kkkkkkkk....",
	};

	/** WHAT: the target server. LEDs: 1 power, 2 being probed, 3 open port found, 4 something filtered. */
	private static final String[] SERVER_ART = {
		"................",
		"..ssssssssssss..",
		"..sKKKKKKKKKKs..",
		"..sK1K2KvvvvKs..",
		"..sKKKKKKKKKKs..",
		"..ssssssssssss..",
		"..sKKKKKKKKKKs..",
		"..sK3K4KvvvvKs..",
		"..sKKKKKKKKKKs..",
		"..ssssssssssss..",
		"...ss......ss...",
		"................",
	};

	/**
	 * WHAT:   6 x 4 pixel icons for the service cards, by kind of service.
	 * WHY:    A key for remote shells, a globe for web, a lock for encrypted
	 *         services, a folder for file sharing, an envelope for mail, a
	 *         cylinder for databases and a screen for remote desktops: the
	 *         kind of service is readable before the name.
	 */
	private static final Map<String, String[]> ICONS = Map.of(
		"key", new String[] {"yy....", "y.yyyy", "yy..y.", "......"},
		"globe", new String[] {".bbbb.", "bwbbwb", ".bbbb.", "......"},
		"lock", new String[] {".g..g.", "gggggg", "ggkggg", "......"},
		"folder", new String[] {"aa....", "aaaaaa", "aaaaaa", "......"},
		"mail", new String[] {"pwwwwp", "ppwwpp", "pppppp", "......"},
		"database", new String[] {".rrrr.", "rRRRRr", ".rrrr.", "......"},
		"screen", new String[] {"ssssss", "sccccs", "..ss..", "......"},
		"unknown", new String[] {".www..", "...w..", "..w...", "......"});

	/** WHAT: which icon each service name gets. */
	private static final Map<String, String> ICON_FOR = Map.ofEntries(
		Map.entry("ssh", "key"), Map.entry("telnet", "key"),
		Map.entry("http", "globe"), Map.entry("dns", "globe"), Map.entry("ipp", "globe"),
		Map.entry("https", "lock"), Map.entry("smtps", "lock"), Map.entry("imaps", "lock"), Map.entry("pop3s", "lock"),
		Map.entry("ftp", "folder"), Map.entry("smb", "folder"), Map.entry("netbios", "folder"), Map.entry("msrpc", "folder"),
		Map.entry("smtp", "mail"), Map.entry("pop3", "mail"), Map.entry("imap", "mail"), Map.entry("amqp", "mail"),
		Map.entry("mysql", "database"), Map.entry("postgresql", "database"), Map.entry("mssql", "database"),
		Map.entry("oracle", "database"), Map.entry("redis", "database"), Map.entry("mongodb", "database"),
		Map.entry("ldap", "database"), Map.entry("rdp", "screen"), Map.entry("vnc", "screen"));

	private final List<String> hosts;
	private final List<Integer> ports;
	private final String targetLabel;
	/** WHAT: (host, port) to its place in the scan order. */
	private final Map<String, Integer> index = new HashMap<>();
	/** WHAT: the result of each probe in scan order, null while it runs. */
	private final ScanResult[] slots;
	/** WHAT: open ports in the order they were found. */
	private final List<ScanResult> found = new ArrayList<>();
	private final long startNanos = System.nanoTime();
	private int done;
	private int open;
	private int closed;
	private int filtered;
	private long lastResultNanos;
	private long lastOpenNanos;

	/**
	 * WHAT:   Prepares a view for one scan.
	 * PRE:    hosts and ports are not empty; hosts.size() x ports.size()
	 *         fits in an int (Scanner caps scans at a million probes)
	 *
	 * @param hosts       the hosts, in scan order
	 * @param ports       the ports, in scan order
	 * @param targetLabel what the user typed as the target, shown under the server
	 */
	public ReconView(List<String> hosts, List<Integer> ports, String targetLabel)
	{
		this.hosts = List.copyOf(hosts);
		this.ports = List.copyOf(ports);
		this.targetLabel = targetLabel;
		this.slots = new ScanResult[hosts.size() * ports.size()];
		for (int h = 0; h < hosts.size(); h++)
		{
			for (int p = 0; p < ports.size(); p++)
			{
				index.put(hosts.get(h) + ":" + ports.get(p), h * ports.size() + p);
			}
		}
	}

	/**
	 * WHAT:   Records one finished probe.
	 * WHY:    Called from many scan threads at once, so it is synchronized
	 *         with render(), which reads the same counters.
	 * PRE:    result is for a host and port of this scan
	 * POST:   the counts, the map and the service list include it
	 *
	 * @param result the probe's result
	 */
	public synchronized void record(ScanResult result)
	{
		Integer at = index.get(result.host() + ":" + result.port());
		if (at == null || slots[at] != null)
		{
			return;
		}
		slots[at] = result;
		done++;
		lastResultNanos = System.nanoTime();
		switch (result.state())
		{
			case OPEN ->
			{
				open++;
				lastOpenNanos = lastResultNanos;
				found.add(result);
			}
			case CLOSED -> closed++;
			case FILTERED -> filtered++;
		}
	}

	/**
	 * WHAT:   Draws one frame of the view.
	 * PRE:    the terminal understands ANSI colour escapes
	 * RETURN: the frame, starting with "cursor home", LINES lines long
	 *
	 * @param tick     animation step, increased once per frame
	 * @param finished true for the last frame, after the scan ended
	 * @return the frame text
	 */
	public synchronized String render(int tick, boolean finished)
	{
		long now = System.nanoTime();
		boolean active = !finished && now - lastResultNanos < ACTIVE_NANOS;
		StringBuilder out = new StringBuilder("\u001b[H");

		// 1: title bar
		String state = finished ? fg(GREEN) + "■ DONE" : fg(AMBER) + "■ SCANNING";
		out.append(divider('┌', '┐', bold(WHITE, "portscout") + " " + fg(DIM) + "recon view" + RESET,
			state + RESET + "  " + fg(DIM) + group(slots.length) + (slots.length == 1 ? " probe" : " probes") + RESET));

		// 2-9: the scene
		Lights lights = new Lights(tick % 6 < 3, active && tick % 2 == 0, open > 0, filtered > 0);
		for (int line = 0; line < SPRITE_H / 2; line++)
		{
			out.append(boxed("    " + sprite(SCANNER_ART, line, lights, true) + "   " + wire(line, tick, active,
				now - lastOpenNanos < ACTIVE_NANOS && !finished) + "   " + sprite(SERVER_ART, line, lights, false)));
		}
		int gap = 3 + WIRE_W + 3;
		out.append(boxed("    " + fg(DIM) + centred("you", SPRITE_W) + " ".repeat(gap) + centred("target", SPRITE_W) + RESET));
		out.append(boxed("  " + bold(AMBER, centred("this computer", SPRITE_W + 4)) + " ".repeat(gap - 4)
			+ bold(WHITE, centred(targetLabel, SPRITE_W + 4))));

		// 10: progress
		double seconds = (now - startNanos) / 1e9;
		out.append(boxed("  " + bar() + " " + bold(WHITE, group(done)) + fg(DIM) + " / " + group(slots.length) + RESET
			+ "  " + tile("OPEN", open, GREEN) + "  " + tile("CLOSED", closed, RED) + "  " + tile("FILTERED", filtered, AMBER)
			+ "  " + fg(DIM) + String.format(Locale.ROOT, "%.1f s", seconds) + RESET));

		// 11-20: the port map
		int perCell = Math.max(1, (slots.length + GRID_CELLS - 1) / GRID_CELLS);
		String caption = perCell == 1 ? (hosts.size() == 1 ? "one pixel per port" : "one pixel per probe")
			: "one pixel per " + perCell + " probes";
		out.append(divider('├', '┤', bold(WHITE, "port map"), fg(DIM) + caption + RESET));
		for (int line = 0; line < GRID_H / 2; line++)
		{
			StringBuilder row = new StringBuilder("  ");
			for (int x = 0; x < GRID_W; x++)
			{
				row.append(cell(cellColour((line * 2 * GRID_W + x) * perCell, perCell),
					cellColour(((line * 2 + 1) * GRID_W + x) * perCell, perCell)));
			}
			out.append(boxed(row + RESET + " " + fg(DIM) + String.format("%9s", rowLabel(line, perCell)) + RESET));
		}
		out.append(boxed("  " + swatch(PANEL) + " waiting  " + swatch(GREEN) + " open  " + swatch(CLOSED) + " closed  "
			+ swatch(FILTERED) + " filtered (no answer)"));

		// 21-27: what is running on the open ports
		out.append(divider('├', '┤', bold(WHITE, "services found"),
			found.size() > CARDS ? fg(DIM) + "showing " + CARDS + " of " + found.size() + ", all are in the table" + RESET : ""));
		for (int row = 0; row < CARDS / 2; row++)
		{
			for (int line = 0; line < 2; line++)
			{
				out.append(boxed("  " + card(row * 2, line) + "  " + card(row * 2 + 1, line)));
			}
		}

		// 28: bottom
		out.append(fg(BORDER)).append('└').append("─".repeat(INNER)).append('┘').append(END_LINE);
		return out.toString();
	}

	/**
	 * WHAT:   The colour of one map cell, covering `count` probes from `first`.
	 * WHY:    With more than 1,024 probes a cell stands for several; it shows
	 *         the most interesting: open, then still waiting, then filtered,
	 *         then closed.
	 *
	 * @param first the first probe in the cell
	 * @param count probes in the cell
	 * @return the colour, or null past the end of the scan
	 */
	private int[] cellColour(int first, int count)
	{
		if (first >= slots.length)
		{
			return null;
		}
		boolean waiting = false;
		boolean silent = false;
		for (int i = first; i < Math.min(slots.length, first + count); i++)
		{
			ScanResult r = slots[i];
			if (r == null)
			{
				waiting = true;
			}
			else if (r.state() == ScanResult.State.OPEN)
			{
				return GREEN;
			}
			else if (r.state() == ScanResult.State.FILTERED)
			{
				silent = true;
			}
		}
		return waiting ? PANEL : silent ? FILTERED : CLOSED;
	}

	/**
	 * WHAT:   The label at the end of a map line: the ports (or probes) it covers.
	 *
	 * @param line    the text line, 0 to 7
	 * @param perCell probes per cell
	 * @return e.g. "1-128", or "" past the end
	 */
	private String rowLabel(int line, int perCell)
	{
		int first = line * 2 * GRID_W * perCell;
		if (first >= slots.length)
		{
			return "";
		}
		int last = Math.min(slots.length, first + 2 * GRID_W * perCell) - 1;
		String label = hosts.size() == 1 ? ports.get(first) + "-" + ports.get(last) : (first + 1) + "-" + (last + 1);
		// a label that does not fit beside the map is left out rather than breaking the frame
		return label.length() <= 9 ? label : "";
	}

	/**
	 * WHAT:   One text line of a service card: icon, port, service, software.
	 *
	 * @param n    which card, 0 to CARDS - 1
	 * @param line 0 for the top line, 1 for the bottom
	 * @return 36 columns of card, or blanks if there is no such service
	 */
	private String card(int n, int line)
	{
		if (n >= found.size())
		{
			if (n == 0 && line == 0)
			{
				return fg(DIM) + String.format("%-36s", "no open ports yet") + RESET;
			}
			return " ".repeat(36);
		}
		ScanResult r = found.get(n);
		Service service = r.service();
		String name = service.name().isEmpty() ? "unknown" : service.label();
		String[] icon = ICONS.get(ICON_FOR.getOrDefault(service.name(), "unknown"));
		StringBuilder pixels = new StringBuilder();
		for (int x = 0; x < 6; x++)
		{
			pixels.append(cell(iconColour(icon[line * 2].charAt(x)), iconColour(icon[line * 2 + 1].charAt(x))));
		}
		String text;
		if (line == 0)
		{
			String where = hosts.size() == 1 ? String.valueOf(r.port()) : r.host() + ":" + r.port();
			text = bold(GREEN, fit(where, 6)) + " " + bold(WHITE, fit(name, 22));
		}
		else
		{
			String software = service.software();
			text = fg(DIM) + fit(software.isEmpty()
				? (service.source() == Service.Source.PORT ? "guessed from the port" : "no version shown") : software, 29) + RESET;
		}
		return pixels + RESET + " " + text;
	}

	/**
	 * WHAT:   One text line of the wire: probes go right, answers come left.
	 *
	 * @param line      0 to 5
	 * @param tick      animation step
	 * @param active    answers are arriving now
	 * @param foundOpen an open port was found a moment ago (answers turn green)
	 * @return WIRE_W columns
	 */
	private String wire(int line, int tick, boolean active, boolean foundOpen)
	{
		if (line == 1)
		{
			return fg(DIM) + fit("SYN probes » " + group(done), WIRE_W) + RESET;
		}
		if (line == 4)
		{
			return fg(DIM) + String.format("%" + WIRE_W + "s", group(open + closed) + " answers «") + RESET;
		}
		if (line != 2 && line != 3)
		{
			return " ".repeat(WIRE_W);
		}
		boolean[] dot = new boolean[WIRE_W];
		if (active)
		{
			for (int i = 0; i < 4; i++)
			{
				int step = (tick * 2 + i * 8 + (line == 3 ? 4 : 0)) % WIRE_W;
				dot[line == 2 ? step : WIRE_W - 1 - step] = true;
			}
		}
		StringBuilder out = new StringBuilder();
		int[] colour = line == 2 ? AMBER : foundOpen ? GREEN : RED;
		for (int x = 0; x < WIRE_W; x++)
		{
			out.append(dot[x] ? fg(colour) + "■" : fg(PANEL) + "─");
		}
		return out + RESET;
	}

	/** WHAT: the blinking and steady lights in the sprites. */
	private record Lights(boolean cursor, boolean probed, boolean open, boolean filtered)
	{
	}

	/**
	 * WHAT:   One text line (two pixel rows) of a sprite.
	 *
	 * @param art    the sprite
	 * @param line   0 to SPRITE_H / 2 - 1
	 * @param lights the light states
	 * @param cursor true for the scanner, whose '1' is a blinking cursor
	 * @return SPRITE_W cells
	 */
	private static String sprite(String[] art, int line, Lights lights, boolean cursor)
	{
		StringBuilder out = new StringBuilder();
		for (int x = 0; x < SPRITE_W; x++)
		{
			out.append(cell(spriteColour(art[line * 2].charAt(x), lights, cursor),
				spriteColour(art[line * 2 + 1].charAt(x), lights, cursor)));
		}
		return out + RESET;
	}

	/**
	 * WHAT:   The colour of one sprite pixel.
	 *
	 * @param code   the sprite character
	 * @param lights the light states
	 * @param cursor true for the scanner sprite
	 * @return the colour, or null for see-through
	 */
	private static int[] spriteColour(char code, Lights lights, boolean cursor)
	{
		return switch (code)
		{
			case 'k' -> FRAME;
			case 'd' -> SCREEN;
			case 'g' -> TEXT_GREEN;
			case 's' -> SILVER;
			case 'K' -> PANEL;
			case 'v' -> VENT;
			case '1' -> cursor ? (lights.cursor() ? AMBER : SCREEN) : GREEN;
			case '2' -> lights.probed() ? AMBER : LED_OFF;
			case '3' -> lights.open() ? GREEN : LED_OFF;
			case '4' -> lights.filtered() ? FILTERED : LED_OFF;
			default -> null;
		};
	}

	/**
	 * WHAT:   The colour of one icon pixel.
	 *
	 * @param code the icon character
	 * @return the colour, or null for see-through
	 */
	private static int[] iconColour(char code)
	{
		return switch (code)
		{
			case 'y' -> AMBER;
			case 'b' -> new int[] {88, 150, 230};
			case 'w' -> WHITE;
			case 'g' -> GREEN;
			case 'k' -> SCREEN;
			case 'a' -> new int[] {230, 190, 80};
			case 'p' -> new int[] {170, 120, 220};
			case 'r' -> RED;
			case 'R' -> new int[] {240, 160, 150};
			case 's' -> SILVER;
			case 'c' -> new int[] {90, 200, 220};
			default -> null;
		};
	}

	/**
	 * WHAT:   Two pixels in one character cell, with the upper-half block.
	 * WHY:    A cell is about twice as tall as wide, so splitting it gives
	 *         two square pixels: text colour on top, background below.
	 *
	 * @param top    the upper pixel, or null
	 * @param bottom the lower pixel, or null
	 * @return the cell
	 */
	private static String cell(int[] top, int[] bottom)
	{
		if (top == null && bottom == null)
		{
			return RESET + " ";
		}
		if (top == null)
		{
			return RESET + fg(bottom) + "▄";
		}
		if (bottom == null)
		{
			return RESET + fg(top) + "▀";
		}
		return fg(top) + bg(bottom) + "▀";
	}

	/** WHAT: the progress bar, amber while running and green when done. */
	private String bar()
	{
		int full = slots.length == 0 ? 0 : (int) ((long) done * BAR_W / slots.length);
		int[] colour = done == slots.length ? GREEN : AMBER;
		return fg(colour) + bg(PANEL) + "█".repeat(full) + " ".repeat(BAR_W - full) + RESET;
	}

	/** WHAT: a dim label and a bold coloured number. */
	private static String tile(String label, int value, int[] colour)
	{
		return fg(DIM) + label + " " + bold(colour, group(value));
	}

	/** WHAT: a two-cell colour sample for the legend. */
	private static String swatch(int[] colour)
	{
		return fg(colour) + "██" + RESET;
	}

	/**
	 * WHAT:   A frame line with a title on the left and a note on the right.
	 *
	 * @param left  the left corner or junction
	 * @param right the right corner or junction
	 * @param title the title (may contain colour)
	 * @param note  the note, or ""
	 * @return the line
	 */
	private static String divider(char left, char right, String title, String note)
	{
		String head = " " + title + " ";
		String tail = note.isEmpty() ? "" : " " + note + " ";
		int fill = Math.max(1, INNER - 1 - width(head) - width(tail) - (tail.isEmpty() ? 0 : 1));
		return fg(BORDER) + left + "─" + RESET + head + fg(BORDER) + "─".repeat(fill) + RESET + tail
			+ (tail.isEmpty() ? "" : fg(BORDER) + "─") + fg(BORDER) + right + END_LINE;
	}

	/**
	 * WHAT:   A line inside the frame, padded so the right edge lines up.
	 *
	 * @param content the line's content
	 * @return the framed line
	 */
	private static String boxed(String content)
	{
		int pad = Math.max(0, INNER - width(content));
		return fg(BORDER) + "│" + RESET + content + RESET + " ".repeat(pad) + fg(BORDER) + "│" + END_LINE;
	}

	/**
	 * WHAT:   Columns text takes on screen: escape codes take none, every
	 *         other character one (the view only uses single-width ones).
	 *
	 * @param text text with escape codes
	 * @return the width
	 */
	static int width(String text)
	{
		int width = 0;
		for (int i = 0; i < text.length(); i++)
		{
			if (text.charAt(i) == '\u001b')
			{
				while (i < text.length() && !Character.isLetter(text.charAt(i)))
				{
					i++;
				}
				continue;
			}
			width++;
		}
		return width;
	}

	/** WHAT: text cut or padded to exactly n columns. */
	private static String fit(String text, int n)
	{
		return text.length() > n ? text.substring(0, n - 1) + "~" : String.format("%-" + n + "s", text);
	}

	/** WHAT: text centred in n columns. */
	private static String centred(String text, int n)
	{
		String cut = text.length() > n ? text.substring(0, n) : text;
		int left = (n - cut.length()) / 2;
		return " ".repeat(left) + cut + " ".repeat(n - left - cut.length());
	}

	/** WHAT: a number with thousands separators. */
	private static String group(long value)
	{
		return String.format(Locale.ROOT, "%,d", value);
	}

	/** WHAT: bold text in a colour, then back to normal. */
	private static String bold(int[] colour, String text)
	{
		return "\u001b[1m" + fg(colour) + text + RESET;
	}

	/** WHAT: "set text colour". */
	private static String fg(int[] c)
	{
		return "\u001b[38;2;" + c[0] + ";" + c[1] + ";" + c[2] + "m";
	}

	/** WHAT: "set background colour". */
	private static String bg(int[] c)
	{
		return "\u001b[48;2;" + c[0] + ";" + c[1] + ";" + c[2] + "m";
	}

	/** WHAT: back to the terminal's own colours. */
	private static final String RESET = "\u001b[0m";
	/** WHAT: end of a line: reset, clear what is left of the old frame, newline. */
	private static final String END_LINE = "\u001b[0m\u001b[K\n";
}
