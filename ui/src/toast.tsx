import { Alert, AlertActionCloseButton, AlertGroup } from "@patternfly/react-core";
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { ApiError } from "./api/client";

interface Toast {
  id: number;
  variant: "success" | "danger" | "warning" | "info";
  title: string;
  body?: string;
}

interface ToastApi {
  success: (title: string, body?: string) => void;
  /** Reports a failed action. Accepts anything thrown. */
  error: (title: string, cause: unknown) => void;
}

const ToastContext = createContext<ToastApi | undefined>(undefined);

let nextId = 1;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    (toast: Omit<Toast, "id">, timeoutMs: number) => {
      const id = nextId++;
      setToasts((current) => [...current, { ...toast, id }]);
      setTimeout(() => dismiss(id), timeoutMs);
    },
    [dismiss],
  );

  const api = useMemo<ToastApi>(
    () => ({
      success: (title, body) => push({ variant: "success", title, body }, 6000),
      error: (title, cause) =>
        push(
          {
            variant: "danger",
            title,
            body: cause instanceof ApiError ? cause.message : String(cause),
          },
          12000,
        ),
    }),
    [push],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <AlertGroup isToast isLiveRegion>
        {toasts.map((toast) => (
          <Alert
            key={toast.id}
            variant={toast.variant}
            title={toast.title}
            timeout={false}
            actionClose={<AlertActionCloseButton onClose={() => dismiss(toast.id)} />}
          >
            {toast.body}
          </Alert>
        ))}
      </AlertGroup>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const value = useContext(ToastContext);
  if (!value) throw new Error("useToast must be used inside <ToastProvider>");
  return value;
}
