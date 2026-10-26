package portscout;

import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WHAT:   What is running behind an open port: the service (ssh, http...),
 *         the software (OpenSSH, nginx...) and its version, and how that was
 *         worked out.
 * WHY:    "Port 22 is open" says little; "OpenSSH 9.6p1" says which software
 *         to patch or look up in a vulnerability database. A guess from the
 *         port number alone is marked as a guess, because anything can listen
 *         on any port.
 * PRE:    name, product, version and source are not null ("" when unknown)
 *
 * @param name    the protocol, e.g. "ssh", or "" if unknown
 * @param product the software, e.g. "OpenSSH", or ""
 * @param version the software's version, e.g. "9.6p1", or ""
 * @param source  how it was identified
 */
public record Service(String name, String product, String version, Source source)
{
	/**
	 * WHAT:   How a service was identified.
	 * WHY:    A banner is evidence; a port number is only a convention.
	 */
	public enum Source
	{
		/** WHAT: from what the service itself sent back. */
		BANNER,
		/** WHAT: guessed from the port number only. */
		PORT,
		/** WHAT: not identified (closed, filtered, or an unknown silent port). */
		NONE
	}

	/** WHAT: the answer for ports that are not open, or not recognised at all. */
	public static final Service UNKNOWN = new Service("", "", "", Source.NONE);

	/** WHAT: the longest product or version kept. WHY: banners are untrusted and can be any length. */
	private static final int MAX_FIELD = 40;

	/**
	 * WHAT:   Usual service on well-known ports, used when the banner says nothing.
	 * WHY:    These are the IANA assignments people expect to see in a scan.
	 */
	private static final Map<Integer, String> WELL_KNOWN = Map.ofEntries(
		Map.entry(21, "ftp"), Map.entry(22, "ssh"), Map.entry(23, "telnet"), Map.entry(25, "smtp"),
		Map.entry(53, "dns"), Map.entry(80, "http"), Map.entry(110, "pop3"), Map.entry(135, "msrpc"),
		Map.entry(139, "netbios"), Map.entry(143, "imap"), Map.entry(389, "ldap"), Map.entry(443, "https"),
		Map.entry(445, "smb"), Map.entry(465, "smtps"), Map.entry(587, "smtp"), Map.entry(631, "ipp"),
		Map.entry(993, "imaps"), Map.entry(995, "pop3s"), Map.entry(1433, "mssql"), Map.entry(1521, "oracle"),
		Map.entry(3306, "mysql"), Map.entry(3389, "rdp"), Map.entry(5672, "amqp"), Map.entry(5432, "postgresql"), Map.entry(5900, "vnc"),
		Map.entry(6379, "redis"), Map.entry(8080, "http"), Map.entry(8443, "https"), Map.entry(27017, "mongodb"));

	/** WHAT: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3": the software is the third dash-separated part. */
	private static final Pattern SSH = Pattern.compile("^SSH-[0-9.]+-(\\S+)");
	/** WHAT: the Server header of an HTTP response. */
	private static final Pattern HTTP_SERVER = Pattern.compile("(?im)^server:[ \\t]*([^\\r\\n]+)");
	/** WHAT: a version number such as 1.24.0, 3.0.3 or 9.6p1. */
	private static final Pattern VERSION = Pattern.compile("(\\d+\\.\\d+(?:\\.\\d+)*[a-z0-9]*)");
	/** WHAT: software names commonly found in FTP and mail greetings. */
	private static final Pattern KNOWN_PRODUCT = Pattern.compile(
		"(?i)\\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|Microsoft FTP Service|Postfix|Exim|Sendmail"
			+ "|Microsoft ESMTP MAIL Service|Dovecot|Courier|Cyrus|MariaDB)\\b");

	/**
	 * WHAT:   Identifies the service on an open port from what it sent back.
	 * WHY:    Each protocol announces itself differently: SSH and FTP greet
	 *         first, HTTP answers our HEAD request with a Server header,
	 *         MySQL sends a binary greeting that contains its version.
	 *         Anything unrecognised falls back to the port number, marked
	 *         as a guess.
	 * PRE:    response is not null; it is the raw reply decoded one byte per
	 *         char (ISO-8859-1), possibly binary, possibly "" for silence
	 * RETURN: the service; Service.UNKNOWN if nothing matched and the port is
	 *         not a well-known one
	 *
	 * @param port     the port the reply came from
	 * @param response the raw reply
	 * @return what is running there
	 */
	public static Service identify(int port, String response)
	{
		Matcher ssh = SSH.matcher(response);
		if (ssh.find())
		{
			// "OpenSSH_9.6p1" and "dropbear_2022.83" put the version after an underscore
			String software = ssh.group(1);
			int cut = software.indexOf('_');
			return cut > 0
				? banner("ssh", software.substring(0, cut), software.substring(cut + 1))
				: banner("ssh", software, "");
		}

		if (response.startsWith("HTTP/"))
		{
			String name = port == 443 || port == 8443 ? "https" : "http";
			Matcher server = HTTP_SERVER.matcher(response);
			if (!server.find())
			{
				return banner(name, "", "");
			}
			// "nginx/1.24.0", "Apache/2.4.58 (Ubuntu)", "Microsoft-IIS/10.0"
			String header = server.group(1).trim();
			int slash = header.indexOf('/');
			if (slash > 0)
			{
				return banner(name, header.substring(0, slash), firstWord(header.substring(slash + 1)));
			}
			return banner(name, header, "");
		}

		String mysql = mysqlVersion(response);
		if (mysql != null)
		{
			return mysql.contains("MariaDB") ? banner("mysql", "MariaDB", mysql.replace("-MariaDB", ""))
				: banner("mysql", "MySQL", mysql);
		}

		String lower = response.toLowerCase(Locale.ROOT);
		if (response.startsWith("220"))
		{
			// FTP and SMTP both greet with 220; the text (or the port) tells them apart
			boolean ftp = lower.contains("ftp") || (port == 21 && !lower.contains("smtp"));
			return fromGreeting(ftp ? "ftp" : "smtp", response);
		}
		if (response.startsWith("+OK"))
		{
			return fromGreeting("pop3", response);
		}
		if (response.startsWith("* OK"))
		{
			return fromGreeting("imap", response);
		}
		if (response.startsWith("RFB "))
		{
			return banner("vnc", "RFB", response.substring(4, Math.min(response.length(), 11)).trim());
		}
		if (response.startsWith("AMQP"))
		{
			// RabbitMQ and other message brokers reject our HTTP request with the AMQP protocol header
			return banner("amqp", "", "");
		}
		if (response.startsWith("-ERR") || response.startsWith("-NOAUTH") || response.startsWith("-DENIED"))
		{
			// Redis stays silent, then rejects our HTTP request in its own error format
			return banner("redis", "Redis", "");
		}
		if (response.startsWith("HTTP") || lower.contains("<html"))
		{
			return banner("http", "", "");
		}

		String guess = WELL_KNOWN.get(port);
		return guess == null ? UNKNOWN : new Service(guess, "", "", Source.PORT);
	}

	/**
	 * WHAT:   The service as one short phrase, e.g. "OpenSSH 9.6p1".
	 * RETURN: product and version, or "" if neither is known
	 *
	 * @return the software description
	 */
	public String software()
	{
		return (product + " " + version).trim();
	}

	/**
	 * WHAT:   The service name for a table, with "?" when it is only a guess.
	 * RETURN: e.g. "ssh", "https?" or ""
	 *
	 * @return the name to display
	 */
	public String label()
	{
		return source == Source.PORT ? name + "?" : name;
	}

	/**
	 * WHAT:   Builds a Service identified from a banner, cleaning the text.
	 *
	 * @param name    the protocol
	 * @param product the software, untrusted
	 * @param version the version, untrusted
	 * @return the service
	 */
	private static Service banner(String name, String product, String version)
	{
		return new Service(name, clean(product), clean(version), Source.BANNER);
	}

	/**
	 * WHAT:   Reads the software and version out of an FTP or mail greeting.
	 * WHY:    "220 (vsFTPd 3.0.3)" and "220 mail.example.com ESMTP Postfix"
	 *         name the software in free text, so known names are searched for
	 *         and the version is the first version-like number after it.
	 *
	 * @param name     the protocol
	 * @param greeting the first lines the service sent
	 * @return the service, with product and version when found
	 */
	private static Service fromGreeting(String name, String greeting)
	{
		String line = firstLine(greeting);
		Matcher product = KNOWN_PRODUCT.matcher(line);
		if (!product.find())
		{
			return banner(name, "", "");
		}
		Matcher version = VERSION.matcher(line.substring(product.end()));
		return banner(name, product.group(1), version.find() ? version.group(1) : "");
	}

	/**
	 * WHAT:   Finds the version in a MySQL or MariaDB greeting packet.
	 * WHY:    MySQL speaks first with a binary packet: 3 bytes of length, a
	 *         sequence number, protocol version 10, then the server version
	 *         as text ending in a zero byte.
	 * RETURN: the version text, or null if this is not a MySQL greeting
	 *
	 * @param response the raw reply, one byte per char
	 * @return the version, or null
	 */
	private static String mysqlVersion(String response)
	{
		if (response.length() < 7 || response.charAt(4) != 10)
		{
			return null;
		}
		int end = response.indexOf('\0', 5);
		if (end < 0 || end - 5 > MAX_FIELD)
		{
			return null;
		}
		String version = response.substring(5, end);
		return VERSION.matcher(version).lookingAt() ? version : null;
	}

	/**
	 * WHAT:   The text before the first space.
	 *
	 * @param text the text
	 * @return its first word
	 */
	private static String firstWord(String text)
	{
		int space = text.indexOf(' ');
		return space < 0 ? text : text.substring(0, space);
	}

	/**
	 * WHAT:   The text before the first line break.
	 *
	 * @param text the text
	 * @return its first line
	 */
	private static String firstLine(String text)
	{
		int end = 0;
		while (end < text.length() && text.charAt(end) != '\r' && text.charAt(end) != '\n')
		{
			end++;
		}
		return text.substring(0, end);
	}

	/**
	 * WHAT:   Makes untrusted text safe to print: printable ASCII only, and short.
	 * WHY:    A hostile service could send terminal escape codes or a huge name.
	 *
	 * @param text the raw text
	 * @return the cleaned text, at most MAX_FIELD characters
	 */
	private static String clean(String text)
	{
		StringBuilder out = new StringBuilder();
		for (char c : text.trim().toCharArray())
		{
			if (out.length() == MAX_FIELD)
			{
				break;
			}
			out.append(c >= ' ' && c <= '~' ? c : '.');
		}
		return out.toString();
	}
}
