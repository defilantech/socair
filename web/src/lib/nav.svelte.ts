// The list a detail page belongs to, so the layout can mark it current in the
// nav. A model page sets it from the engine's location for that model.
export const navSection = $state<{ href: string }>({ href: '' });
