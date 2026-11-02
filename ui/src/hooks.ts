import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "./api/client";

export interface AsyncState<T> {
  data: T | undefined;
  error: ApiError | undefined;
  loading: boolean;
  reload: () => void;
}

/**
 * Runs `load` on mount and whenever `deps` change. A response that arrives
 * after a newer request was started is dropped, so quickly changing a
 * filter can never show stale rows.
 */
export function useAsync<T>(load: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<ApiError>();
  const [loading, setLoading] = useState(true);
  const generation = useRef(0);
  const loader = useRef(load);
  loader.current = load;

  const run = useCallback(() => {
    const mine = ++generation.current;
    setLoading(true);
    loader
      .current()
      .then((result) => {
        if (mine !== generation.current) return;
        setData(result);
        setError(undefined);
      })
      .catch((e: unknown) => {
        if (mine !== generation.current) return;
        setError(e instanceof ApiError ? e : new ApiError("unknown", String(e), 0));
      })
      .finally(() => {
        if (mine === generation.current) setLoading(false);
      });
  }, []);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(run, deps);
  return { data, error, loading, reload: run };
}

/** Calls `callback` every `ms` while `active`. */
export function useInterval(callback: () => void, ms: number, active: boolean): void {
  const saved = useRef(callback);
  saved.current = callback;
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => saved.current(), ms);
    return () => clearInterval(id);
  }, [ms, active]);
}

/** The rendered width of an element, for charts that must be given one. */
export function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T | null>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    setWidth(element.clientWidth);
    const observer = new ResizeObserver(([entry]) => {
      if (entry) setWidth(Math.floor(entry.contentRect.width));
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return [ref, width];
}

/** A value that only changes after `ms` without a new one; for search boxes. */
export function useDebounced<T>(value: T, ms = 250): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return debounced;
}
