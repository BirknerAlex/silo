import {
  Alert,
  Button,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Dropdown,
  DropdownItem,
  DropdownList,
  Label,
  LabelGroup,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadLogo,
  MastheadMain,
  MastheadToggle,
  MenuToggle,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  Nav,
  NavItem,
  NavList,
  Page,
  PageSidebar,
  PageSidebarBody,
  PageToggleButton,
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem,
  Content,
} from "@patternfly/react-core";
import {
  BarsIcon,
  MoonIcon,
  SunIcon,
  UserIcon,
} from "@patternfly/react-icons";
import { useState, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { useAsync } from "../hooks";
import { formatTime } from "../format";
import { currentTheme, setTheme, type Theme } from "../theme";
import logoUrl from "../assets/logo.svg";

function Logo() {
  // Decorative: the "silo" wordmark beside it already names the console.
  return <img src={logoUrl} width={28} height={28} alt="" style={{ verticalAlign: "middle" }} />;
}

function SessionModal({ onClose }: { onClose: () => void }) {
  const { who } = useAuth();
  const version = useAsync(() => api.version(), []);
  if (!who) return null;
  return (
    <Modal variant="small" isOpen onClose={onClose} aria-label="Session">
      <ModalHeader title="Session" />
      <ModalBody>
        <DescriptionList isHorizontal isCompact>
          <DescriptionListGroup>
            <DescriptionListTerm>User</DescriptionListTerm>
            <DescriptionListDescription>{who.username || "—"}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Token</DescriptionListTerm>
            <DescriptionListDescription>{who.token_name}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Permission</DescriptionListTerm>
            <DescriptionListDescription>{who.permission}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Repos</DescriptionListTerm>
            <DescriptionListDescription>
              {who.all_repos ? (
                "All repos"
              ) : (
                <LabelGroup>
                  {who.repos.map((r) => (
                    <Label key={r} isCompact>
                      {r}
                    </Label>
                  ))}
                </LabelGroup>
              )}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Expires</DescriptionListTerm>
            <DescriptionListDescription>
              {formatTime(who.expires_at, "Never")}
            </DescriptionListDescription>
          </DescriptionListGroup>
          {version.data && (
            <DescriptionListGroup>
              <DescriptionListTerm>Server</DescriptionListTerm>
              <DescriptionListDescription>
                {version.data.version} ({version.data.commit})
              </DescriptionListDescription>
            </DescriptionListGroup>
          )}
        </DescriptionList>
      </ModalBody>
      <ModalFooter>
        <Button variant="primary" onClick={onClose}>
          Close
        </Button>
      </ModalFooter>
    </Modal>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const { who, capabilities, signOut } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [showSession, setShowSession] = useState(false);
  const [theme, setThemeState] = useState<Theme>(currentTheme());

  const toggleTheme = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    setThemeState(next);
  };

  const masthead = (
    <Masthead>
      <MastheadMain>
        <MastheadToggle>
          <PageToggleButton variant="plain" aria-label="Navigation">
            <BarsIcon />
          </PageToggleButton>
        </MastheadToggle>
        <MastheadBrand>
          <MastheadLogo component="span">
            <Logo /> <strong style={{ marginLeft: 8 }}>silo</strong>
          </MastheadLogo>
        </MastheadBrand>
      </MastheadMain>
      <MastheadContent>
        <Toolbar isFullHeight isStatic>
          <ToolbarContent>
            <ToolbarGroup align={{ default: "alignEnd" }} variant="action-group-plain">
              <ToolbarItem>
                <Button
                  variant="plain"
                  aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
                  onClick={toggleTheme}
                >
                  {theme === "dark" ? <SunIcon /> : <MoonIcon />}
                </Button>
              </ToolbarItem>
              <ToolbarItem>
                <Dropdown
                  isOpen={menuOpen}
                  onOpenChange={setMenuOpen}
                  onSelect={() => setMenuOpen(false)}
                  popperProps={{ position: "right" }}
                  toggle={(ref) => (
                    <MenuToggle
                      ref={ref}
                      variant="plainText"
                      onClick={() => setMenuOpen(!menuOpen)}
                      isExpanded={menuOpen}
                      icon={<UserIcon />}
                    >
                      {who?.username || who?.token_name}
                    </MenuToggle>
                  )}
                >
                  <DropdownList>
                    <DropdownItem key="session" onClick={() => setShowSession(true)}>
                      Session details
                    </DropdownItem>
                    <DropdownItem key="out" onClick={signOut}>
                      Sign out
                    </DropdownItem>
                  </DropdownList>
                </Dropdown>
              </ToolbarItem>
            </ToolbarGroup>
          </ToolbarContent>
        </Toolbar>
      </MastheadContent>
    </Masthead>
  );

  const navigate = useNavigate();
  const { pathname } = useLocation();
  const link = (to: string, label: string, end = false) => {
    const active = end ? pathname === to : pathname === to || pathname.startsWith(`${to}/`);
    return (
      <NavItem
        key={to}
        to={`/admin${to === "/" ? "/" : to}`}
        isActive={active}
        onClick={(e) => {
          e.preventDefault();
          navigate(to);
        }}
      >
        {label}
      </NavItem>
    );
  };

  const sidebar = (
    <PageSidebar>
      <PageSidebarBody>
        <Nav aria-label="Main">
          <NavList>
            {capabilities.globalAdmin && link("/", "Dashboard", true)}
            {link("/repos", "Repositories")}
            {capabilities.admin && link("/tokens", "Tokens")}
            {capabilities.globalAdmin && link("/users", "Users")}
            {capabilities.admin && link("/audit", "Audit log")}
            {capabilities.admin && link("/prune", "Retention")}
            {capabilities.globalAdmin && link("/server", "Server")}
          </NavList>
        </Nav>
      </PageSidebarBody>
    </PageSidebar>
  );

  return (
    <Page masthead={masthead} sidebar={sidebar} isManagedSidebar>
      {!capabilities.admin && (
        <Alert
          isInline
          variant="info"
          title="Read-only view"
          style={{ margin: 16, marginBottom: 0 }}
        >
          <Content component="p">
            This credential does not have admin permission, so only browsing is available.
          </Content>
        </Alert>
      )}
      {children}
      {showSession && <SessionModal onClose={() => setShowSession(false)} />}
    </Page>
  );
}

