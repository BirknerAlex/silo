import { Bullseye } from "@patternfly/react-core";
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import { Loading } from "./components/common";
import { Shell } from "./components/Shell";
import { Audit } from "./pages/Audit";
import { Channel } from "./pages/Channel";
import { Dashboard } from "./pages/Dashboard";
import { Login } from "./pages/Login";
import { Prune } from "./pages/Prune";
import { Repo } from "./pages/Repo";
import { Repos } from "./pages/Repos";
import { Server } from "./pages/Server";
import { Tokens } from "./pages/Tokens";
import { Users } from "./pages/Users";

export function App() {
  const { ready, who, capabilities } = useAuth();

  if (!ready) {
    return (
      <Bullseye>
        <Loading />
      </Bullseye>
    );
  }
  if (!who) return <Login />;

  const { admin, globalAdmin } = capabilities;
  return (
    <Shell>
      <Routes>
        <Route path="/" element={globalAdmin ? <Dashboard /> : <Navigate to="/repos" replace />} />
        <Route path="/repos" element={<Repos />} />
        <Route path="/repos/:repo" element={<Repo />} />
        <Route path="/repos/:repo/:channel" element={<Channel />} />
        {admin && <Route path="/tokens" element={<Tokens />} />}
        {globalAdmin && <Route path="/users" element={<Users />} />}
        {admin && <Route path="/audit" element={<Audit />} />}
        {admin && <Route path="/prune" element={<Prune />} />}
        {globalAdmin && <Route path="/server" element={<Server />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Shell>
  );
}
