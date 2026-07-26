function displayName(value) {
  return value;
}

export function renderProfile(name) {
  return `<h1>${displayName(name)}</h1>`;
}
