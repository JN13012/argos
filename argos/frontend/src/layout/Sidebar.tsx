import { useEffect, useState } from "react";
import { Icon } from "../components/Icon";
import { navigationGroups } from "./navigation";

interface SidebarProps {
  open: boolean;
  hiddenOnMobile: boolean;
  onNavigate(): void;
  statusText: string;
}

export function Sidebar({
  open,
  hiddenOnMobile,
  onNavigate,
  statusText,
}: SidebarProps) {
  const [active, setActive] = useState(window.location.hash || "#dashboard");
  useEffect(() => {
    const update = () => setActive(window.location.hash || "#dashboard");
    window.addEventListener("hashchange", update);
    return () => window.removeEventListener("hashchange", update);
  }, []);
  return (
    <aside
      className={`sidebar ${open ? "open" : ""}`}
      id="sidebar"
      aria-label="Navigation principale"
      inert={hiddenOnMobile}
    >
      <p className="nav-section-label">ESPACE DE TRAVAIL</p>
      <nav className="navigation" aria-label="Espaces Argos">
        {navigationGroups.map((group, index) => (
          <div className="navigation-group" key={index}>
            {group.map((item) =>
              item.href ? (
                <a
                  key={item.label}
                  className={`nav-item ${active === item.href ? "active" : ""}`}
                  href={item.href}
                  aria-current={active === item.href ? "location" : undefined}
                  onClick={() => {
                    setActive(item.href!);
                    onNavigate();
                  }}
                >
                  <Icon name={item.icon} />
                  <span>{item.label}</span>
                  {active === item.href && <span className="active-dot" />}
                </a>
              ) : (
                <button
                  key={item.label}
                  type="button"
                  className="nav-item"
                  disabled
                  aria-label={`${item.label} · À venir`}
                  title="Cet espace sera disponible dans une prochaine version"
                >
                  <Icon name={item.icon} />
                  <span>{item.label}</span>
                  <span className="nav-soon" aria-hidden="true">
                    À venir
                  </span>
                </button>
              ),
            )}
          </div>
        ))}
      </nav>
      <div className="sidebar-bottom">
        <div className="local-status">
          <span className="eyebrow">STATUT PLATEFORME</span>
          <strong>
            <span className="status-dot" />
            {statusText}
          </strong>
          <p>Consultation locale des résultats persistés.</p>
          <a href="#main-content" onClick={onNavigate}>
            Voir le statut <Icon name="arrow" />
          </a>
        </div>
        <div className="sidebar-footer">
          <Icon name="lock" />
          <span>
            Argos <strong>M1.3</strong>
          </span>
        </div>
      </div>
    </aside>
  );
}
