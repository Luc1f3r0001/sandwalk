import { useState, useEffect, createContext, useContext } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { Layout } from "./components/Layout";
import { DashboardPage } from "./pages/DashboardPage";
import { MachinesPage } from "./pages/MachinesPage";
import { MachinePage } from "./pages/MachinePage";
import { FindingsPage } from "./pages/FindingsPage";
import { LoginPage } from "./pages/LoginPage";
import { api } from "./api/client";

export type Theme = "dark" | "light";
export const ThemeContext = createContext<{ theme: Theme; toggle: () => void }>({ theme: "dark", toggle: () => {} });
export const useTheme = () => useContext(ThemeContext);

export default function App() {
  const [authed, setAuthed] = useState(api.hasCredentials());
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem("sw-theme") as Theme) ?? "light");

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("sw-theme", theme);
  }, [theme]);

  const toggle = () => setTheme(t => t === "dark" ? "light" : "dark");

  function handleLogout() {
    api.clearCredentials();
    setAuthed(false);
  }

  if (!authed) {
    return (
      <ThemeContext.Provider value={{ theme, toggle }}>
        <LoginPage onLogin={() => setAuthed(true)} />
      </ThemeContext.Provider>
    );
  }

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      <Layout onLogout={handleLogout}>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/machines" element={<MachinesPage />} />
          <Route path="/machines/:id" element={<MachinePage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </ThemeContext.Provider>
  );
}
