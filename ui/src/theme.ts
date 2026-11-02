const KEY = "silo.theme";
export type Theme = "light" | "dark";

function stored(): Theme | null {
  try {
    const value = localStorage.getItem(KEY);
    return value === "light" || value === "dark" ? value : null;
  } catch {
    return null;
  }
}

export function currentTheme(): Theme {
  return (
    stored() ?? (window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light")
  );
}

export function setTheme(theme: Theme): void {
  document.documentElement.classList.toggle("pf-v6-theme-dark", theme === "dark");
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // A theme that does not persist is a small loss.
  }
}

export function applyStoredTheme(): void {
  document.documentElement.classList.toggle("pf-v6-theme-dark", currentTheme() === "dark");
}
