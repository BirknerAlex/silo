import {
  Alert,
  Button,
  Checkbox,
  Content,
  Form,
  FormGroup,
  FormHelperText,
  HelperText,
  HelperTextItem,
  Label,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  SearchInput,
  TextInput,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import { ActionsColumn, Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { PlusCircleIcon } from "@patternfly/react-icons";
import { useMemo, useState, type FormEvent } from "react";
import { api } from "../api";
import type { UserInfo } from "../api/types";
import { useAuth } from "../auth";
import { Body, ConfirmModal, Empty, PageHeader, Query } from "../components/common";
import { Time } from "../components/Time";
import { useAsync } from "../hooks";
import { useToast } from "../toast";

export function Users() {
  const toast = useToast();
  const { who } = useAuth();
  const users = useAsync(() => api.listUsers(), []);
  const info = useAsync(() => api.serverInfo().catch(() => undefined), []);
  const [search, setSearch] = useState("");
  const [creating, setCreating] = useState(false);
  const [passwordFor, setPasswordFor] = useState<UserInfo>();
  const [deleting, setDeleting] = useState<UserInfo>();

  const shown = useMemo(
    () =>
      (users.data ?? []).filter((u) => u.username.toLowerCase().includes(search.trim().toLowerCase())),
    [users.data, search],
  );

  const setDisabled = async (user: UserInfo, disabled: boolean) => {
    try {
      await api.setUserDisabled(user.username, disabled);
      toast.success(`${disabled ? "Disabled" : "Enabled"} ${user.username}`);
      users.reload();
    } catch (e) {
      toast.error(`Could not ${disabled ? "disable" : "enable"} ${user.username}`, e);
    }
  };

  return (
    <>
      <PageHeader
        title="Users"
        subtitle="People who sign in with a password or through single sign-on."
        actions={
          <Button icon={<PlusCircleIcon />} onClick={() => setCreating(true)}>
            Create user
          </Button>
        }
      />
      <Body>
        {info.data && info.data.oidc_exclusive && (
          <Alert isInline variant="info" title="Password sign-in is off" style={{ marginBottom: 16 }}>
            This server accepts only single sign-on, so a password set here cannot be used to sign in.
          </Alert>
        )}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <SearchInput
                placeholder="Filter by username"
                value={search}
                onChange={(_, v) => setSearch(v)}
                onClear={() => setSearch("")}
                aria-label="Filter users"
              />
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
        <Query state={users}>
          {(all) =>
            all.length === 0 ? (
              <Empty title="No users" />
            ) : (
              <Table aria-label="Users" variant="compact">
                <Thead>
                  <Tr>
                    <Th>Username</Th>
                    <Th>Role</Th>
                    <Th>Sign-in</Th>
                    <Th>Status</Th>
                    <Th>Created</Th>
                    <Th>Last sign-in</Th>
                    <Th screenReaderText="Actions" />
                  </Tr>
                </Thead>
                <Tbody>
                  {shown.map((u) => {
                    const me = u.username === who?.username;
                    return (
                      <Tr key={u.id}>
                        <Td dataLabel="Username">
                          {u.username} {me && <Label isCompact>you</Label>}
                        </Td>
                        <Td dataLabel="Role">
                          {u.is_admin ? <Label isCompact color="red">admin</Label> : "user"}
                        </Td>
                        <Td dataLabel="Sign-in">{u.oidc_only ? "single sign-on only" : "password"}</Td>
                        <Td dataLabel="Status">
                          <Label isCompact color={u.disabled ? "grey" : "green"}>
                            {u.disabled ? "disabled" : "active"}
                          </Label>
                        </Td>
                        <Td dataLabel="Created">
                          <Time seconds={u.created_at} />
                        </Td>
                        <Td dataLabel="Last sign-in">
                          <Time seconds={u.last_login_at} never="never" />
                        </Td>
                        <Td isActionCell>
                          <ActionsColumn
                            items={[
                              u.disabled
                                ? { title: "Enable", onClick: () => void setDisabled(u, false) }
                                : { title: "Disable", onClick: () => void setDisabled(u, true) },
                              { title: "Set password", onClick: () => setPasswordFor(u) },
                              { isSeparator: true },
                              { title: "Delete", onClick: () => setDeleting(u) },
                            ]}
                          />
                        </Td>
                      </Tr>
                    );
                  })}
                </Tbody>
              </Table>
            )
          }
        </Query>
        {users.data && shown.length === 0 && users.data.length > 0 && <Empty title="No matching users" />}
      </Body>

      {creating && (
        <CreateUserModal
          onClose={() => setCreating(false)}
          onCreated={(name) => {
            setCreating(false);
            toast.success(`Created ${name}`);
            users.reload();
          }}
        />
      )}
      {passwordFor && (
        <PasswordModal
          user={passwordFor}
          onClose={() => setPasswordFor(undefined)}
          onDone={() => {
            toast.success(`Password changed for ${passwordFor.username}`);
            setPasswordFor(undefined);
            users.reload();
          }}
        />
      )}
      {deleting && (
        <ConfirmModal
          title={`Delete ${deleting.username}?`}
          confirmLabel="Delete user"
          confirmText={deleting.username}
          onClose={() => setDeleting(undefined)}
          onConfirm={async () => {
            try {
              await api.deleteUser(deleting.username);
              toast.success(`Deleted ${deleting.username}`);
              users.reload();
            } catch (e) {
              toast.error("Could not delete the user", e);
              throw e;
            }
          }}
        >
          <Content component="p">
            Their sign-in sessions are deleted with the account. API tokens they created keep working
            until revoked; see Tokens.
          </Content>
        </ConfirmModal>
      )}
    </>
  );
}

function CreateUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: (name: string) => void }) {
  const toast = useToast();
  const [username, setUsername] = useState("");
  const [ssoOnly, setSsoOnly] = useState(false);
  const [password, setPassword] = useState("");
  const [admin, setAdmin] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.createUser(username.trim(), ssoOnly ? "" : password, admin);
      onCreated(username.trim());
    } catch (err) {
      toast.error("Could not create the user", err);
      setBusy(false);
    }
  };

  return (
    <Modal variant="small" isOpen onClose={onClose} aria-label="Create user">
      <ModalHeader title="Create user" />
      <Form id="create-user" onSubmit={submit}>
        <ModalBody>
          <FormGroup label="Username" isRequired fieldId="user-name">
            <TextInput id="user-name" value={username} onChange={(_, v) => setUsername(v)} autoFocus isRequired autoComplete="off" />
          </FormGroup>
          <FormGroup fieldId="user-sso" style={{ marginTop: 16 }}>
            <Checkbox
              id="user-sso"
              label="Single sign-on only (no password)"
              isChecked={ssoOnly}
              onChange={(_, v) => setSsoOnly(v)}
              description="For someone who will only ever sign in through the identity provider."
            />
          </FormGroup>
          {!ssoOnly && (
            <FormGroup label="Password" isRequired fieldId="user-pass" style={{ marginTop: 16 }}>
              <TextInput
                id="user-pass"
                type="password"
                value={password}
                onChange={(_, v) => setPassword(v)}
                autoComplete="new-password"
                isRequired
              />
              <FormHelperText>
                <HelperText>
                  <HelperTextItem>The server enforces a minimum length.</HelperTextItem>
                </HelperText>
              </FormHelperText>
            </FormGroup>
          )}
          <FormGroup fieldId="user-admin" style={{ marginTop: 16 }}>
            <Checkbox
              id="user-admin"
              label="Administrator"
              isChecked={admin}
              onChange={(_, v) => setAdmin(v)}
              description="Can manage users, tokens, repos and upstreams."
            />
          </FormGroup>
        </ModalBody>
        <ModalFooter>
          <Button
            type="submit"
            variant="primary"
            isLoading={busy}
            isDisabled={busy || !username.trim() || (!ssoOnly && !password)}
          >
            Create user
          </Button>
          <Button variant="link" onClick={onClose}>
            Cancel
          </Button>
        </ModalFooter>
      </Form>
    </Modal>
  );
}

function PasswordModal({
  user,
  onClose,
  onDone,
}: {
  user: UserInfo;
  onClose: () => void;
  onDone: () => void;
}) {
  const toast = useToast();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const mismatch = confirm !== "" && confirm !== password;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.setUserPassword(user.username, password);
      onDone();
    } catch (err) {
      toast.error("Could not set the password", err);
      setBusy(false);
    }
  };

  return (
    <Modal variant="small" isOpen onClose={onClose} aria-label="Set password">
      <ModalHeader title={`Set password for ${user.username}`} />
      <Form id="set-password" onSubmit={submit}>
        <ModalBody>
          {user.oidc_only && (
            <Alert isInline variant="info" title="This account signs in through single sign-on" style={{ marginBottom: 16 }}>
              Setting a password also lets them sign in with it.
            </Alert>
          )}
          <FormGroup label="New password" isRequired fieldId="pw-new">
            <TextInput id="pw-new" type="password" value={password} onChange={(_, v) => setPassword(v)} autoComplete="new-password" autoFocus isRequired />
          </FormGroup>
          <FormGroup label="Repeat password" isRequired fieldId="pw-confirm" style={{ marginTop: 16 }}>
            <TextInput
              id="pw-confirm"
              type="password"
              value={confirm}
              onChange={(_, v) => setConfirm(v)}
              autoComplete="new-password"
              validated={mismatch ? "error" : "default"}
              isRequired
            />
            {mismatch && (
              <FormHelperText>
                <HelperText>
                  <HelperTextItem variant="error">The passwords do not match.</HelperTextItem>
                </HelperText>
              </FormHelperText>
            )}
          </FormGroup>
        </ModalBody>
        <ModalFooter>
          <Button type="submit" variant="primary" isLoading={busy} isDisabled={busy || !password || password !== confirm}>
            Set password
          </Button>
          <Button variant="link" onClick={onClose}>
            Cancel
          </Button>
        </ModalFooter>
      </Form>
    </Modal>
  );
}
