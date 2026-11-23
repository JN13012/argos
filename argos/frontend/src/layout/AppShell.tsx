import { useEffect, useRef, useState } from "react";
import type { ReactNode, RefObject } from "react";
import { BrandLogo } from "../components/BrandLogo";
import { Button } from "../components/Button";
import { Icon } from "../components/Icon";
import { Sidebar } from "./Sidebar";
import "./AppShell.css";

interface AppShellProps {
  children: ReactNode;
  query: string;
  onQueryChange(query: string): void;
  ready: boolean;
  statusText: string;
  searchRef: RefObject<HTMLInputElement | null>;
}

export function AppShell({
  children,
  query,
  onQueryChange,
  ready,
  statusText,
  searchRef,
}: AppShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(
    () => window.matchMedia("(max-width: 700px)").matches,
  );
  const menuRef = useRef<HTMLButtonElement>(null);
  const shellRef = useRef<HTMLDivElement>(null);

  function closeSidebar() {
    if (
      shellRef.current
        ?.querySelector("#sidebar")
        ?.contains(document.activeElement)
    )
      menuRef.current?.focus();
    setSidebarOpen(false);
  }

  useEffect(() => {
    const breakpoint = window.matchMedia("(max-width: 700px)");
    const closeOnDesktop = () => {
      setIsMobile(breakpoint.matches);
      if (!breakpoint.matches) setSidebarOpen(false);
    };
    breakpoint.addEventListener("change", closeOnDesktop);
    return () => breakpoint.removeEventListener("change", closeOnDesktop);
  }, []);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") closeSidebar();
      if (
        (event.ctrlKey || event.metaKey) &&
        event.key.toLowerCase() === "k" &&
        ready &&
        !document.querySelector("dialog[open]") &&
        window.innerWidth > 700
      ) {
        event.preventDefault();
        searchRef.current?.focus();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [ready, searchRef]);

  return (
    <div className="app-shell" ref={shellRef}>
      <a className="skip-link" href="#main-content">
        Aller au contenu
      </a>
      <header className="topbar">
        <Button
          variant="icon"
          className="mobile-menu"
          ref={menuRef}
          aria-label={
            sidebarOpen ? "Fermer la navigation" : "Ouvrir la navigation"
          }
          aria-controls="sidebar"
          aria-expanded={sidebarOpen}
          onClick={() => setSidebarOpen(!sidebarOpen)}
        >
          <Icon name="menu" />
        </Button>
        <a className="brand" href="#dashboard" aria-label="ARGOS — accueil">
          <BrandLogo />
          <span>ARGOS</span>
        </a>
        <div className="environment">
          <span className="status-dot" />
          <span>
            <small>Environnement</small>Local · Archives
          </span>
        </div>
        <label className="global-search">
          <Icon name="search" />
          <input
            ref={searchRef}
            className="search-input"
            id="global-search"
            type="search"
            placeholder="Rechercher une mission, une cible…"
            aria-label="Rechercher une mission ou une cible"
            autoComplete="off"
            value={query}
            onChange={(event) => onQueryChange(event.target.value)}
            disabled={!ready}
          />
          <kbd>Ctrl K</kbd>
        </label>
        <div className="header-actions">
          <a
            href="#argos-chat"
            className="chat-shortcut"
            aria-label="Argos Chat · À venir"
          >
            <Icon name="chat" />
          </a>
          <span className="readonly-label">
            <Icon name="lock" /> Lecture seule
          </span>
        </div>
      </header>
      <Sidebar
        open={sidebarOpen}
        hiddenOnMobile={isMobile && !sidebarOpen}
        onNavigate={closeSidebar}
        statusText={statusText}
      />
      {sidebarOpen && (
        <button
          type="button"
          className="sidebar-backdrop"
          aria-label="Fermer la navigation"
          onClick={closeSidebar}
        />
      )}
      {children}
    </div>
  );
}
