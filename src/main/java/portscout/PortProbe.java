package portscout;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;

/**
 * WHAT:   Probes a single TCP port and, if it is open, grabs the service banner.
 * WHY:    Knowing a port is open is half the answer; the banner tells you
 *         which software and version is listening, which is what matters
 *         for security.
 */
public final class PortProbe
{
	/**
	 * WHAT:   The most reply bytes read.
	 * WHY:    Enough for a greeting or an HTTP status line plus its headers
	 *         (the Server header names the software), but a hostile service
	 *         cannot flood us.
	 */
	private static final int MAX_BANNER_BYTES = 1024;

	/** WHAT: the longest banner line kept, in characters. */
	private static final int MAX_LINE = 200;

	/**
	 * WHAT:   The request sent to services that stay silent.
	 * WHY:    HTTP is the most common silent service, and HEAD asks for the
	 *         status line and headers only, never a whole page.
	 */
	private static final byte[] HTTP_PROBE = "HEAD / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.US_ASCII);

	/**
	 * WHAT:   Blocks creating a PortProbe.
	 * WHY:    The class only holds static helpers, so an instance means nothing.
	 */
	private PortProbe()
	{
	}

	/**
	 * WHAT:   Runs a TCP connect scan of host:port.
	 * WHY:    A full connect needs no admin rights or raw sockets (unlike a SYN
	 *         scan), so it works anywhere Java runs.
	 * PRE:    host is a dotted IPv4 address
	 * PRE:    port is between 1 and 65535
	 * PRE:    timeoutMs is a positive integer
	 * RETURN: OPEN with the banner and the identified service if the connect succeeds,
	 *         CLOSED if the host refused (ConnectException),
	 *         FILTERED on a timeout or any other IOException;
	 *         millis is how long the probe took
	 * PACKETS: OPEN is SYN, SYN-ACK, ACK. CLOSED is SYN, RST.
	 *         FILTERED is SYN, then silence until the timeout.
	 * NOTE:   For an open port that stays silent, millis includes waiting
	 *         for the banner (up to two read timeouts), not just the handshake.
	 *
	 * @param host      the IPv4 address to connect to
	 * @param port      the TCP port to probe
	 * @param timeoutMs how long to wait for the handshake, in milliseconds
	 * @return the port's state, its banner if open, and how long the probe took
	 */
	public static ScanResult probe(String host, int port, int timeoutMs)
	{
		long start = System.nanoTime();
		ScanResult.State state = ScanResult.State.FILTERED;
		String reply = "";

		try (Socket socket = new Socket())
		{
			socket.connect(new InetSocketAddress(host, port), timeoutMs);
			state = ScanResult.State.OPEN;
			reply = grabReply(socket, timeoutMs);
		}
		catch (ConnectException e)
		{
			// the host answered the SYN with a RST: nothing listens there
			state = ScanResult.State.CLOSED;
		}
		catch (IOException e)
		{
			// a timeout or no route: leave FILTERED. If the port was already
			// OPEN and only closing the socket failed, it stays OPEN.
		}

		long millis = (System.nanoTime() - start) / 1_000_000;
		Service service = state == ScanResult.State.OPEN ? Service.identify(port, reply) : Service.UNKNOWN;
		return new ScanResult(host, port, state, firstPrintableLine(reply), millis, service);
	}

	/**
	 * WHAT:   Reads what a service sends on a connected socket.
	 * WHY:    SSH, FTP and SMTP greet you first; HTTP stays silent until asked,
	 *         so one small HEAD request covers the most common silent service.
	 * PRE:    socket is connected
	 * PRE:    timeoutMs is a positive integer
	 * RETURN: the raw reply (up to MAX_BANNER_BYTES, one char per byte, may
	 *         be binary), or "" if nothing came back; never throws
	 *
	 * @param socket    an open, connected socket; the caller closes it
	 * @param timeoutMs how long each read may wait, in milliseconds
	 * @return the raw reply, or ""
	 */
	static String grabReply(Socket socket, int timeoutMs)
	{
		try
		{
			// without a read timeout a silent service would block this thread forever
			socket.setSoTimeout(timeoutMs);
			InputStream in = socket.getInputStream();
			byte[] buffer = new byte[MAX_BANNER_BYTES];

			int read;
			try
			{
				read = in.read(buffer);
			}
			catch (SocketTimeoutException silent)
			{
				OutputStream out = socket.getOutputStream();
				out.write(HTTP_PROBE);
				out.flush();
				read = in.read(buffer);
			}

			// ISO-8859-1 maps every byte to one char, so binary junk cannot break decoding
			return read > 0 ? new String(buffer, 0, read, StandardCharsets.ISO_8859_1) : "";
		}
		catch (IOException e)
		{
			return "";
		}
	}

	/**
	 * WHAT:   Cuts raw service output down to its first line of plain text.
	 * WHY:    Banners are untrusted remote data; control characters could
	 *         mess up the terminal or the report, so they become '.'.
	 * PRE:    raw is not null
	 * RETURN: the text before the first line break, trimmed, printable ASCII only
	 *
	 * @param raw the bytes the service sent, decoded one byte per char
	 * @return the cleaned first line
	 */
	static String firstPrintableLine(String raw)
	{
		int end = 0;
		while (end < raw.length() && raw.charAt(end) != '\r' && raw.charAt(end) != '\n')
		{
			end++;
		}

		// the reply can be 1 KB of binary with no line break; a banner line stays short
		StringBuilder line = new StringBuilder();
		for (char c : raw.substring(0, end).trim().toCharArray())
		{
			if (line.length() == MAX_LINE)
			{
				break;
			}
			line.append(c >= ' ' && c <= '~' ? c : '.');
		}
		return line.toString();
	}
}
