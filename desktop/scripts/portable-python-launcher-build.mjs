import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";

export function findPortableLauncherCompiler(options = {}) {
  const platform = options.platform ?? process.platform;
  if (platform !== "win32") return undefined;
  const pathValue = options.pathValue ?? process.env.PATH ?? "";
  const cl = commandPath("cl", pathValue, platform);
  if (cl) return { kind: "msvc", command: cl };
  if (options.allowMinGw === true) {
    const gcc = commandPath("gcc", pathValue, platform);
    if (gcc) return { kind: "mingw", command: gcc };
  }
  return undefined;
}

export function buildPortablePythonLauncher(input) {
  const compiler = input.compiler ?? findPortableLauncherCompiler({ allowMinGw: input.allowMinGw });
  if (!compiler) {
    throw new Error("Windows portable scanner launchers require MSVC (cl.exe), or the explicit MinGW fallback.");
  }
  const output = input.outputPath;
  const objectPath = join(dirname(output), "hermsec-python-launcher.obj");
  const source = input.sourcePath;
  const environment = {
    ...process.env,
    SOURCE_DATE_EPOCH: process.env.SOURCE_DATE_EPOCH ?? "1",
    ...input.environment,
  };
  const args = compiler.kind === "msvc"
    ? [
        "/nologo",
        "/std:c11",
        "/O2",
        "/W4",
        "/DUNICODE",
        "/D_UNICODE",
        `/Fo${objectPath}`,
        source,
        "/link",
        "/Brepro",
        "/INCREMENTAL:NO",
        "/SUBSYSTEM:CONSOLE",
        `/OUT:${output}`,
      ]
    : [
        "-std=c11",
        "-O2",
        "-Wall",
        "-Wextra",
        "-mconsole",
        "-municode",
        "-frandom-seed=hermsec-portable-python-launcher",
        "-Wl,--no-insert-timestamp",
        source,
        "-o",
        output,
      ];
  const result = spawnSync(compiler.command, args, {
    cwd: input.cwd ?? dirname(output),
    shell: false,
    windowsHide: true,
    env: environment,
    encoding: "utf8",
  });
  if (result.error) throw result.error;
  if (result.status !== 0 || !existsSync(output)) {
    throw new Error(`${compiler.command} failed to build portable Python launcher: ${(result.stderr ?? result.stdout ?? "").trim()}`);
  }
  return { compiler, args, output };
}

function commandPath(command, pathValue, platform) {
  const suffixes = platform === "win32" ? [".exe"] : [""];
  for (const directory of pathValue.split(platform === "win32" ? ";" : ":").filter(Boolean)) {
    for (const suffix of suffixes) {
      const candidate = join(directory, `${command}${suffix}`);
      if (existsSync(candidate)) return candidate;
    }
  }
  return undefined;
}
