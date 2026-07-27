function displayName(value) {
  return value.replace(/[&<>"']/g, (character) => `&#${character.charCodeAt(0)};`);
}

export function renderProfile(name) {
  return `<h1>${displayName(name)}</h1>`;
}
