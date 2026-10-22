package portscout;

import java.util.List;

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

		Only scan hosts you own or have written permission to scan.
		""";

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

		try
		{
			for (int i = 1; i < args.length; i++)
			{
				switch (args[i])
				{
					case "-p", "--ports" -> ports = args[++i];
					case "-t", "--timeout" -> timeout = Integer.parseInt(args[++i]);
					case "-c", "--concurrency" -> concurrency = Integer.parseInt(args[++i]);
					case "--json" -> json = true;
					case "--all" -> all = true;
					default -> throw new IllegalArgumentException("unknown option " + args[i]);
				}
			}

			List<String> hosts = TargetParser.parse(target);
			List<Integer> portList = PortParser.parse(ports);

			long start = System.nanoTime();
			List<ScanResult> results = Scanner.scan(hosts, portList, timeout, concurrency);
			long ms = (System.nanoTime() - start) / 1_000_000;

			System.out.print(json ? Report.json(results) : Report.table(results, all));
			if (!json)
			{
				System.out.printf("scanned %d host(s) x %d port(s) in %d ms%n", hosts.size(), portList.size(), ms);
			}
		}
		catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e)
		{
			System.err.println("error: " + e.getMessage());
			System.err.print(USAGE);
			System.exit(2);
		}
	}
}
