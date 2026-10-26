package portscout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * WHAT:   Tests for Service.identify with replies copied from real software.
 * WHY:    Each protocol announces itself in its own format; one test per
 *         format proves the rules read real-world text, not made-up shapes.
 */
class ServiceTest
{
	/**
	 * WHAT:   Asserts what identify finds.
	 *
	 * @param port     the port the reply came from
	 * @param reply    the raw reply
	 * @param name     the expected service name
	 * @param product  the expected software
	 * @param version  the expected version
	 * @param source   the expected source
	 */
	private static void expect(int port, String reply, String name, String product, String version, Service.Source source)
	{
		Service service = Service.identify(port, reply);
		assertEquals(name, service.name(), "name");
		assertEquals(product, service.product(), "product");
		assertEquals(version, service.version(), "version");
		assertEquals(source, service.source(), "source");
	}

	/** WHAT: OpenSSH on Ubuntu: the version follows an underscore. */
	@Test
	void openSsh()
	{
		expect(22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", "ssh", "OpenSSH", "9.6p1", Service.Source.BANNER);
	}

	/** WHAT: Dropbear, the small SSH server on routers. */
	@Test
	void dropbearOnAnOddPort()
	{
		expect(2222, "SSH-2.0-dropbear_2022.83\r\n", "ssh", "dropbear", "2022.83", Service.Source.BANNER);
	}

	/** WHAT: nginx answering the HEAD request: the Server header names it. */
	@Test
	void nginx()
	{
		expect(80, "HTTP/1.1 200 OK\r\nDate: Mon, 26 Oct 2026 10:00:00 GMT\r\nServer: nginx/1.24.0\r\n\r\n",
			"http", "nginx", "1.24.0", Service.Source.BANNER);
	}

	/** WHAT: Apache adds the operating system in brackets, which is dropped. */
	@Test
	void apacheWithOs()
	{
		expect(8080, "HTTP/1.1 200 OK\r\nserver: Apache/2.4.58 (Ubuntu)\r\n\r\n", "http", "Apache", "2.4.58",
			Service.Source.BANNER);
	}

	/** WHAT: Windows' own HTTP stack, as on port 5357 of most Windows PCs. */
	@Test
	void microsoftHttpApi()
	{
		expect(5357, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html\r\nServer: Microsoft-HTTPAPI/2.0\r\n",
			"http", "Microsoft-HTTPAPI", "2.0", Service.Source.BANNER);
	}

	/** WHAT: an HTTP server that hides its name is still http. */
	@Test
	void httpWithoutServerHeader()
	{
		expect(8000, "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n", "http", "", "", Service.Source.BANNER);
	}

	/** WHAT: vsftpd wraps its name in brackets. */
	@Test
	void vsftpd()
	{
		expect(21, "220 (vsFTPd 3.0.3)\r\n", "ftp", "vsFTPd", "3.0.3", Service.Source.BANNER);
	}

	/** WHAT: ProFTPD names itself and its version. */
	@Test
	void proftpd()
	{
		expect(21, "220 ProFTPD 1.3.8 Server (Debian) [::ffff:10.0.0.5]\r\n", "ftp", "ProFTPD", "1.3.8",
			Service.Source.BANNER);
	}

	/** WHAT: Postfix greets with ESMTP and its name, but no version. */
	@Test
	void postfix()
	{
		expect(25, "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", "smtp", "Postfix", "", Service.Source.BANNER);
	}

	/** WHAT: Exim on the submission port. */
	@Test
	void exim()
	{
		expect(587, "220 mx.example.org ESMTP Exim 4.97 Mon, 26 Oct 2026 10:00:00 +0000\r\n", "smtp", "Exim", "4.97",
			Service.Source.BANNER);
	}

	/** WHAT: Dovecot's POP3 and IMAP greetings. */
	@Test
	void dovecot()
	{
		expect(110, "+OK Dovecot (Ubuntu) ready.\r\n", "pop3", "Dovecot", "", Service.Source.BANNER);
		expect(143, "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS] Dovecot (Ubuntu) ready.\r\n", "imap", "Dovecot",
			"", Service.Source.BANNER);
	}

	/** WHAT: the binary MySQL greeting: length, sequence 0, protocol 10, version, zero byte. */
	@Test
	void mysql()
	{
		expect(3306, "J\0\0\0\n8.0.36\0\u0008\0\0\0abcdefgh\0mysql_native_password\0", "mysql", "MySQL", "8.0.36",
			Service.Source.BANNER);
	}

	/** WHAT: MariaDB uses the MySQL greeting with its own version text. */
	@Test
	void mariadb()
	{
		expect(3306, "Y\0\0\0\n5.5.5-10.11.6-MariaDB\0\u0003\0\0\0", "mysql", "MariaDB", "5.5.5-10.11.6",
			Service.Source.BANNER);
	}

	/** WHAT: VNC's RFB greeting holds the protocol version. */
	@Test
	void vnc()
	{
		expect(5900, "RFB 003.008\n", "vnc", "RFB", "003.008", Service.Source.BANNER);
	}

	/** WHAT: Redis stays silent, then rejects the HTTP request in its own error format. */
	@Test
	void redis()
	{
		expect(6379, "-ERR wrong number of arguments for 'head' command\r\n", "redis", "Redis", "",
			Service.Source.BANNER);
	}

	/** WHAT: RabbitMQ answers an HTTP request with the AMQP protocol header. */
	@Test
	void rabbitMqAmqp()
	{
		expect(5672, "AMQP\0\0\u0009\u0001", "amqp", "", "", Service.Source.BANNER);
	}

	/** WHAT: a silent well-known port is guessed from its number, and marked as a guess. */
	@Test
	void silentWellKnownPortIsAGuess()
	{
		expect(445, "", "smb", "", "", Service.Source.PORT);
		assertEquals("smb?", Service.identify(445, "").label());
	}

	/** WHAT: a silent unknown port stays unknown. */
	@Test
	void silentUnknownPort()
	{
		assertEquals(Service.UNKNOWN, Service.identify(49152, ""));
	}

	/** WHAT: binary junk on a well-known port is not mistaken for anything. */
	@Test
	void binaryJunkFallsBackToThePort()
	{
		expect(3389, "\u0003\0\0\u0013\u000eÐ\0\0\u00124\0\u0002\u001f\u0008\0\u0002\0\0\0", "rdp", "", "",
			Service.Source.PORT);
	}

	/** WHAT: a hostile Server header with escape codes and a huge name is cleaned and cut. */
	@Test
	void hostileServerHeaderIsCleaned()
	{
		Service service = Service.identify(80, "HTTP/1.1 200 OK\r\nServer: \u001b[31mevil" + "x".repeat(500) + "/1.0\r\n");
		assertEquals(40, service.product().length());
		assertTrue(service.product().chars().allMatch(c -> c >= ' ' && c <= '~'), "printable only");
	}

	/** WHAT: software() joins product and version. */
	@Test
	void softwareText()
	{
		assertEquals("OpenSSH 9.6p1", Service.identify(22, "SSH-2.0-OpenSSH_9.6p1\r\n").software());
		assertEquals("", Service.UNKNOWN.software());
	}
}
