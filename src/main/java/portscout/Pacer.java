package portscout;

import java.util.concurrent.locks.LockSupport;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

/**
 * WHAT:   Spaces events evenly so no more than a set number start per second.
 * WHY:    Concurrency alone limits how many probes are open at once, not how
 *         fast they start: against a host that answers instantly, 200 at once
 *         can mean thousands of SYNs a second, enough to overwhelm a small
 *         device (or Docker's port forwarding, which dropped connections at
 *         that speed). A rate limit is what makes a scan polite, and slow
 *         enough to stay under an intrusion detector's alarm if you choose.
 *         Starts are spread out evenly, and after a pause the pacer does not
 *         "catch up" with a burst.
 */
final class Pacer
{
	/** WHAT: nanoseconds between two starts; 0 means no limit. */
	private final long intervalNanos;
	/** WHAT: the clock, in nanoseconds (System.nanoTime, or a fake in tests). */
	private final LongSupplier clock;
	/** WHAT: waits a number of nanoseconds (parkNanos, or a fake in tests). */
	private final LongConsumer sleep;
	/** WHAT: the earliest time the next start may happen. */
	private long next;
	/** WHAT: true once the first start has happened. */
	private boolean started;

	/**
	 * WHAT:   Creates a pacer on the real clock.
	 * PRE:    perSecond is 0 (no limit) or more
	 *
	 * @param perSecond the most starts per second, or 0 for no limit
	 */
	Pacer(int perSecond)
	{
		this(perSecond, System::nanoTime, LockSupport::parkNanos);
	}

	/**
	 * WHAT:   Creates a pacer with a given clock and sleep.
	 * WHY:    Tests use a fake clock, so they check the spacing exactly and
	 *         never actually wait.
	 * PRE:    perSecond is 0 or more; clock and sleep are not null
	 * THROWS: IllegalArgumentException if perSecond is negative
	 *
	 * @param perSecond the most starts per second, or 0 for no limit
	 * @param clock     returns the time in nanoseconds
	 * @param sleep     waits the given number of nanoseconds
	 * @throws IllegalArgumentException if perSecond is negative
	 */
	Pacer(int perSecond, LongSupplier clock, LongConsumer sleep)
	{
		if (perSecond < 0)
		{
			throw new IllegalArgumentException("rate must be 0 (no limit) or more, got " + perSecond);
		}
		this.intervalNanos = perSecond == 0 ? 0 : 1_000_000_000L / perSecond;
		this.clock = clock;
		this.sleep = sleep;
	}

	/**
	 * WHAT:   Waits until the next start is allowed, then books the one after.
	 * WHY:    Called once before each probe starts.
	 * PRE:    called from one thread (the scan's submitting loop)
	 * POST:   at least one interval separates this start from the previous one
	 */
	void await()
	{
		if (intervalNanos == 0)
		{
			return;
		}
		long now = clock.getAsLong();
		if (started && next > now)
		{
			// parkNanos may wake early, so wait until the clock really reaches `next`
			while (next > now)
			{
				sleep.accept(next - now);
				now = clock.getAsLong();
			}
		}
		// from now, not from the old booking: a pause never turns into a burst afterwards
		// (System.nanoTime can be negative, so the first booking starts from `now`, not from 0)
		next = (started ? Math.max(next, now) : now) + intervalNanos;
		started = true;
	}
}
