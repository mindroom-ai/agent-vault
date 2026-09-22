const basePathMetaName = "agent-vault-ui-base-path";

export function readUIBasePath(doc: Document = document): string {
  const value = doc.querySelector<HTMLMetaElement>(`meta[name="${basePathMetaName}"]`)?.content;
  if (!value || !value.startsWith("/") || value.includes("__AGENT_VAULT_")) {
    return "/";
  }
  return value;
}

export const uiBasePath = readUIBasePath();

export function uiURL(path: string, basePath: string = uiBasePath): string {
  if (!path.startsWith("/")) {
    throw new Error(`UI path must start with "/": ${path}`);
  }
  return basePath === "/" ? path : `${basePath}${path}`;
}
