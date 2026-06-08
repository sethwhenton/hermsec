export interface ProjectDirectory {
  id: string;
  name: string;
  path: string;
  root: string;
}

export interface ProjectActionResult {
  ok: boolean;
  message: string;
}
