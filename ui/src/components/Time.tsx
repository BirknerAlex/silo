import { useSyncExternalStore } from "react";
import { Tooltip } from "@patternfly/react-core";
import { formatRelative, formatTime } from "../format";

// One clock for every relative timestamp on the page, so "3 minutes ago"
// keeps counting on a page whose data loaded once, without a timer per
// label. It runs only while at least one label is mounted.
const TICK_MS = 30_000;
const listeners = new Set<() => void>();
let now = Date.now();
let timer: ReturnType<typeof setInterval> | undefined;

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  if (!timer) {
    timer = setInterval(() => {
      now = Date.now();
      listeners.forEach((l) => l());
    }, TICK_MS);
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      clearInterval(timer);
      timer = undefined;
    }
  };
}

// Refreshed on read as well as on the tick, so a label mounting between
// ticks, or after the clock was set back, starts from the current time.
// Two reads in the same second agree, which is what React asks of a
// snapshot.
function snapshot(): number {
  if (Math.abs(Date.now() - now) >= 1000) now = Date.now();
  return now;
}

function useNow(): number {
  return useSyncExternalStore(subscribe, snapshot);
}

/** A timestamp as "3 hours ago", with the exact time on hover. */
export function Time({ seconds, never = "—" }: { seconds: number; never?: string }) {
  const current = useNow();
  if (!seconds) return <>{never}</>;
  return (
    <Tooltip content={formatTime(seconds)}>
      <span>{formatRelative(seconds, current)}</span>
    </Tooltip>
  );
}
