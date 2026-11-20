export type SettingsCategory = 'appearance' | 'terminal' | 'rdp' | 'sessions' | 'security' | 'sync' | 'transfer' | 'shortcuts' | 'tools';

export const CATEGORIES: { id: SettingsCategory; label: string; icon: string }[] = [
  { id: 'appearance', label: 'Wygląd', icon: 'eye' },
  { id: 'terminal', label: 'Terminal', icon: 'terminal' },
  { id: 'rdp', label: 'RDP', icon: 'monitors' },
  { id: 'sessions', label: 'Sesje', icon: 'plug' },
  { id: 'security', label: 'Bezpieczeństwo', icon: 'shield' },
  { id: 'sync', label: 'Synchronizacja', icon: 'sync' },
  { id: 'transfer', label: 'Import i eksport', icon: 'download' },
  { id: 'shortcuts', label: 'Skróty', icon: 'keyboard' },
  { id: 'tools', label: 'Narzędzia', icon: 'more' },
];
