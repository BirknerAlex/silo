import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { formatRelative } from "../format";
import { Time } from "./Time";

describe("Time", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps a relative label current on a page that stays open", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T12:00:00Z"));
    const fiveMinutesAgo = Date.parse("2026-01-01T11:55:00Z") / 1000;

    // Through `formatRelative`, so the expectation follows the runner's
    // locale the same way the component does.
    const label = () => formatRelative(fiveMinutesAgo, Date.now());

    render(<Time seconds={fiveMinutesAgo} />);
    const five = label();
    expect(screen.getByText(five)).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(2 * 60_000);
    });
    expect(label()).not.toBe(five);
    expect(screen.getByText(label())).toBeInTheDocument();
  });

  it("shows the placeholder for an unset timestamp", () => {
    render(<Time seconds={0} never="never" />);
    expect(screen.getByText("never")).toBeInTheDocument();
  });
});
