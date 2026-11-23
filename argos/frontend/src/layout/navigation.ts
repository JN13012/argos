import type { IconName } from "../components/Icon";
interface NavigationItem {
  label: string;
  icon: IconName;
  href?: string;
}
export const navigationGroups: readonly (readonly NavigationItem[])[] = [
  [
    { label: "Dashboard", icon: "grid", href: "#dashboard" },
    { label: "Missions", icon: "target", href: "#missions" },
    { label: "Preuves", icon: "folder", href: "#evidence" },
    { label: "Rapports", icon: "file", href: "#reports" },
    { label: "Journal", icon: "terminal", href: "#events" },
  ],
  [
    { label: "Red Team", icon: "shield" },
    { label: "OSINT", icon: "globe" },
    { label: "Blue Team", icon: "monitor" },
    { label: "Agents", icon: "users" },
  ],
];
