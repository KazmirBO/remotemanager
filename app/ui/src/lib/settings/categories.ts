export type SettingsCategory = 'appearance' | 'terminal' | 'rdp' | 'sessions' | 'security' | 'sync' | 'shortcuts' | 'tools';

export const CATEGORIES: { id: SettingsCategory; label: string; icon: string }[] = [
  { id: 'appearance', label: 'Wygląd', icon: 'eye' },
  { id: 'terminal', label: 'Terminal', icon: 'terminal' },
  { id: 'rdp', label: 'RDP', icon: 'monitors' },
  { id: 'sessions', label: 'Sesje', icon: 'plug' },
  { id: 'security', label: 'Bezpieczeństwo', icon: 'shield' },
  { id: 'sync', label: 'Synchronizacja', icon: 'sync' },
  { id: 'shortcuts', label: 'Skróty', icon: 'keyboard' },
  { id: 'tools', label: 'Narzędzia', icon: 'more' },
];
