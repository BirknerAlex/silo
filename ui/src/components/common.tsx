import {
  Alert,
  Bullseye,
  Button,
  Checkbox,
  ClipboardCopy,
  Content,
  EmptyState,
  EmptyStateActions,
  EmptyStateBody,
  EmptyStateFooter,
  Flex,
  FlexItem,
  Label,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  PageSection,
  Spinner,
  TextInput,
  Title,
  type LabelProps,
} from "@patternfly/react-core";
import { CubesIcon, ExclamationCircleIcon } from "@patternfly/react-icons";
import { useState, type ReactNode } from "react";
import { ApiError } from "../api/client";
import { RepoMode } from "../api/types";
import type { AsyncState } from "../hooks";
import { formatName, modeName } from "../format";

export function PageHeader({
  title,
  subtitle,
  actions,
  breadcrumb,
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
  breadcrumb?: ReactNode;
}) {
  return (
    <PageSection hasBodyWrapper={false} padding={{ default: "padding" }}>
      {breadcrumb}
      <Flex
        justifyContent={{ default: "justifyContentSpaceBetween" }}
        alignItems={{ default: "alignItemsFlexStart" }}
        flexWrap={{ default: "wrap" }}
        spaceItems={{ default: "spaceItemsMd" }}
      >
        <FlexItem>
          <Title headingLevel="h1" size="2xl">
            {title}
          </Title>
          {subtitle && <Content component="p">{subtitle}</Content>}
        </FlexItem>
        {actions && <FlexItem>{actions}</FlexItem>}
      </Flex>
    </PageSection>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <Bullseye style={{ minHeight: 160 }}>
      <Spinner size="xl" aria-label={label} />
    </Bullseye>
  );
}

export function ErrorState({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  const denied = error.code === "permission_denied";
  return (
    <EmptyState
      headingLevel="h4"
      icon={ExclamationCircleIcon}
      titleText={denied ? "Not permitted" : "Something went wrong"}
      status={denied ? "warning" : "danger"}
    >
      <EmptyStateBody>{error.message}</EmptyStateBody>
      {onRetry && !denied && (
        <EmptyStateFooter>
          <EmptyStateActions>
            <Button variant="primary" onClick={onRetry}>
              Retry
            </Button>
          </EmptyStateActions>
        </EmptyStateFooter>
      )}
    </EmptyState>
  );
}

export function Empty({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <EmptyState headingLevel="h4" icon={CubesIcon} titleText={title}>
      {children && <EmptyStateBody>{children}</EmptyStateBody>}
      {action && (
        <EmptyStateFooter>
          <EmptyStateActions>{action}</EmptyStateActions>
        </EmptyStateFooter>
      )}
    </EmptyState>
  );
}

/** Renders loading and error states, then `children` with the data. */
export function Query<T>({
  state,
  children,
}: {
  state: AsyncState<T>;
  children: (data: T) => ReactNode;
}) {
  if (state.error && state.data === undefined) {
    return <ErrorState error={state.error} onRetry={state.reload} />;
  }
  if (state.data === undefined) return <Loading />;
  return (
    <>
      {state.error && (
        <Alert isInline variant="danger" title="Could not refresh" style={{ marginBottom: 16 }}>
          {state.error.message}
        </Alert>
      )}
      {children(state.data)}
    </>
  );
}

export function FormatLabel({ format }: { format: number }) {
  const name = formatName(format);
  if (!name) return <>—</>;
  const colors: Record<string, LabelProps["color"]> = {
    rpm: "red",
    deb: "orangered",
    apk: "teal",
    npm: "orange",
    pacman: "blue",
    flatpak: "purple",
  };
  return (
    <Label isCompact color={colors[name] ?? "grey"}>
      {name}
    </Label>
  );
}

export function ModeLabel({ mode }: { mode: number }) {
  return (
    <Label isCompact color={mode === RepoMode.Public ? "green" : "grey"}>
      {modeName(mode)}
    </Label>
  );
}

/**
 * A confirmation for something that cannot be undone. With `confirmText`
 * the button stays disabled until that text is typed, which is how a
 * repo with packages in it is protected from a stray click.
 */
export function ConfirmModal({
  title,
  confirmLabel,
  confirmText,
  danger = true,
  onConfirm,
  onClose,
  children,
  extra,
}: {
  title: string;
  confirmLabel: string;
  confirmText?: string;
  danger?: boolean;
  onConfirm: () => Promise<void>;
  onClose: () => void;
  children: ReactNode;
  extra?: ReactNode;
}) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const blocked = confirmText !== undefined && typed !== confirmText;

  const run = async () => {
    setBusy(true);
    try {
      await onConfirm();
      onClose();
    } catch {
      // The caller reports the failure; keep the dialog open to retry.
      setBusy(false);
    }
  };

  return (
    <Modal variant="small" isOpen onClose={onClose} aria-label={title}>
      <ModalHeader title={title} titleIconVariant={danger ? "warning" : undefined} />
      <ModalBody>
        {children}
        {extra}
        {confirmText !== undefined && (
          <div style={{ marginTop: 16 }}>
            <Content component="p">
              Type <strong>{confirmText}</strong> to confirm.
            </Content>
            <TextInput
              aria-label="Confirmation"
              value={typed}
              onChange={(_, value) => setTyped(value)}
              autoFocus
            />
          </div>
        )}
      </ModalBody>
      <ModalFooter>
        <Button
          variant={danger ? "danger" : "primary"}
          onClick={run}
          isDisabled={blocked || busy}
          isLoading={busy}
        >
          {confirmLabel}
        </Button>
        <Button variant="link" onClick={onClose} isDisabled={busy}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}

/** Shows a secret the server will never show again. */
export function SecretModal({
  title,
  label,
  secret,
  hint,
  onClose,
}: {
  title: string;
  label: string;
  secret: string;
  hint?: ReactNode;
  onClose: () => void;
}) {
  const [saved, setSaved] = useState(false);
  return (
    <Modal variant="medium" isOpen onClose={saved ? onClose : undefined} aria-label={title}>
      <ModalHeader title={title} />
      <ModalBody>
        <Alert isInline variant="warning" title="This is the only time it is shown.">
          The server keeps only a hash. Copy it now and store it somewhere safe.
        </Alert>
        <Content component="p" style={{ marginTop: 16 }}>
          {label}
        </Content>
        <ClipboardCopy isReadOnly hoverTip="Copy" clickTip="Copied" variant="expansion">
          {secret}
        </ClipboardCopy>
        {hint && <div style={{ marginTop: 16 }}>{hint}</div>}
        <Checkbox
          id="secret-saved"
          label="I have saved it"
          isChecked={saved}
          onChange={(_, checked) => setSaved(checked)}
          style={{ marginTop: 16 }}
        />
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" onClick={onClose} isDisabled={!saved}>
          Done
        </Button>
      </ModalFooter>
    </Modal>
  );
}

/** A section wrapper that gives page bodies consistent padding. */
export function Body({ children }: { children: ReactNode }) {
  return (
    <PageSection hasBodyWrapper={false} isFilled>
      {children}
    </PageSection>
  );
}
