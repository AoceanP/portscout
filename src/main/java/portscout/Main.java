package portscout;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * WHAT:   Command line entry point for portscout.
 * WHY:    Keeps argument handling apart from the scanning code, so the
 *         scanner can be tested without a command line.
 */
public final class Main
{
	/**
	 * WHAT:   Help text printed for -h, --help or bad arguments.
	 * WHY:    One place to keep the options and the permission warning.
	 */
	private static final String USAGE = """
		usage: portscout <target> [options]
		  target              an IPv4 address or CIDR, e.g. 192.168.1.10 or 192.168.1.0/24
		  -p, --ports SPEC    ports to scan, e.g. 22,80,443,8000-8100 (default 1-1024)
		  -t, --timeout MS    connect timeout in milliseconds (default 500)
		  -c, --concurrency N probes running at once (default 200)
		  --json              print JSON instead of a table
		  --all               also list closed and filtered ports
		  -w, --watch         show the recon view: a live pixel-art picture of the scan

		Only scan hosts you own or have written permission to scan.
		""";

	/** WHAT: terminal code that clears the screen, for the recon view. */
	private static final String CLEAR_SCREEN = "\u001b[2J";
	/** WHAT: terminal code that hides the cursor while the view redraws. */
	private static final String HIDE_CURSOR = "\u001b[?25l";
	/** WHAT: terminal code that shows the cursor again. */
	private static final String SHOW_CURSOR = "\u001b[?25h";

	/**
	 * WHAT:   Blocks creating a Main.
	 * WHY:    The class is only an entry point, so an instance means nothing.
	 */
	private Main()
	{
	}

	/**
	 * WHAT:   Parses arguments, runs the scan and prints the report.
	 * WHY:    Defaults (ports 1-1024, 500 ms, 200 at once) give a fast,
	 *         polite scan of the well-known ports with no options at all.
	 * PRE:    args is not null
	 * POST:   prints the report to stdout, or an error and usage to stderr
	 *         and exits with status 2 on bad input
	 *
	 * @param args the target first, then any options, e.g.
	 *             {"192.168.1.0/24", "-p", "22,80", "--json"}
	 */
	public static void main(String[] args)
	{
		if (args.length == 0 || args[0].equals("-h") || args[0].equals("--help"))
		{
			System.out.print(USAGE);
			return;
		}

		String target = args[0];
		String ports = "1-1024";
		int timeout = 500;
		int concurrency = 200;
		boolean json = false;
		boolean all = false;
		boolean watch = false;

		try
		{
			for (int i = 1; i < args.length; i++)
			{
				switch (args[i])
				{
					case "-p", "--ports" -> ports = args[++i];
					case "-t", "--timeout" -> timeout = toNumber(args[i], args[++i]);
					case "-c", "--concurrency" -> concurrency = toNumber(args[i], args[++i]);
					case "--json" -> json = true;
					case "--all" -> all = true;
					case "-w", "--watch" -> watch = true;
					default -> throw new IllegalArgumentException("unknown option " + args[i]);
				}
			}

			if (timeout < 1 || concurrency < 1)
			{
				throw new IllegalArgumentException("timeout and concurrency must be at least 1");
			}
			if (watch && json)
			{
				throw new IllegalArgumentException("--watch draws a picture, so it cannot be combined with --json");
			}

			List<String> hosts = TargetParser.parse(target);
			List<Integer> portList = PortParser.parse(ports);

			long start = System.nanoTime();
			List<ScanResult> results = watch
				? scanWatched(hosts, portList, timeout, concurrency, target)
				: Scanner.scan(hosts, portList, timeout, concurrency);
			long ms = (System.nanoTime() - start) / 1_000_000;

			System.out.print(json ? Report.json(results) : Report.table(results, all));
			if (!json)
			{
				System.out.printf("scanned %d host(s) x %d port(s) in %d ms%n", hosts.size(), portList.size(), ms);
			}
		}
		catch (ArrayIndexOutOfBoundsException e)
		{
			// an option like -p was the last argument, with no value after it
			System.err.println("error: " + args[args.length - 1] + " needs a value");
			System.err.print(USAGE);
			System.exit(2);
		}
		catch (IllegalArgumentException e)
		{
			// NumberFormatException is a subclass, so "-t abc" lands here too
			System.err.println("error: " + e.getMessage());
			System.err.print(USAGE);
			System.exit(2);
		}
	}

	/**
	 * WHAT:   Runs the scan while drawing the recon view about 12 times a second.
	 * WHY:    The scan threads only record results; one drawing thread
	 *         redraws the screen in place, so a fast scan never floods the
	 *         terminal. The last frame stays on screen above the table.
	 * PRE:    the same as Scanner.scan
	 * POST:   the final frame is printed and the cursor is visible again,
	 *         even if the scan throws or the user presses Ctrl+C
	 * RETURN: the scan results, sorted
	 *
	 * @param hosts       the hosts to scan
	 * @param ports       the ports to probe
	 * @param timeout     the probe timeout, in milliseconds
	 * @param concurrency the most probes at once
	 * @param target      the target as typed, shown in the view
	 * @return every result, sorted by host, then port
	 */
	private static List<ScanResult> scanWatched(List<String> hosts, List<Integer> ports, int timeout, int concurrency,
		String target)
	{
		ReconView view = new ReconView(hosts, ports, target);
		AtomicBoolean scanning = new AtomicBoolean(true);
		// Ctrl+C skips the finally block below, but shutdown hooks still run
		Thread showCursor = new Thread(() -> System.out.print(SHOW_CURSOR));
		Runtime.getRuntime().addShutdownHook(showCursor);

		System.out.print(CLEAR_SCREEN + HIDE_CURSOR);
		Thread drawer = Thread.ofPlatform().daemon().start(() -> {
			int tick = 0;
			while (scanning.get())
			{
				System.out.print(view.render(tick++, false));
				System.out.flush();
				try
				{
					Thread.sleep(80);
				}
				catch (InterruptedException e)
				{
					return;
				}
			}
		});

		try
		{
			return Scanner.scan(hosts, ports, timeout, concurrency, view::record);
		}
		finally
		{
			scanning.set(false);
			try
			{
				drawer.join();
			}
			catch (InterruptedException e)
			{
				Thread.currentThread().interrupt();
			}
			System.out.print(view.render(0, true));
			System.out.println(SHOW_CURSOR);
			System.out.flush();
			Runtime.getRuntime().removeShutdownHook(showCursor);
		}
	}

	/**
	 * WHAT:   Reads the whole-number value of an option such as -t or -c.
	 * WHY:    Java's own message ("For input string: abc") does not say which
	 *         option was wrong; this one does.
	 * PRE:    option and value are not null
	 * RETURN: the value as an int
	 * THROWS: IllegalArgumentException if value is not a whole number
	 *
	 * @param option the option name, used in the error message, e.g. "-t"
	 * @param value  the text after the option, e.g. "500"
	 * @return the number
	 * @throws IllegalArgumentException if value is not a whole number
	 */
	private static int toNumber(String option, String value)
	{
		try
		{
			return Integer.parseInt(value);
		}
		catch (NumberFormatException e)
		{
			throw new IllegalArgumentException(option + " needs a whole number, got '" + value + "'");
		}
	}
}
