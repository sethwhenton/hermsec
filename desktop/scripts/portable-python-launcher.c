#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

/*
 * This launcher is deliberately tiny and accepts only the three scanner names
 * Hermsec stages. It resolves Python relative to its own bin directory so the
 * packaged tree can move without retaining an absolute build-machine path.
 */

#define PATH_CAPACITY 32768

static const wchar_t *module_for_executable(const wchar_t *name) {
  if (_wcsicmp(name, L"semgrep.exe") == 0) return L"semgrep.console_scripts.entrypoint";
  if (_wcsicmp(name, L"bandit.exe") == 0) return L"bandit";
  if (_wcsicmp(name, L"pip-audit.exe") == 0) return L"pip_audit";
  return NULL;
}

static const wchar_t *after_program_name(const wchar_t *command_line) {
  const wchar_t *cursor = command_line;
  if (*cursor == L'"') {
    cursor++;
    while (*cursor && *cursor != L'"') cursor++;
    if (*cursor == L'"') cursor++;
  } else {
    while (*cursor && *cursor != L' ' && *cursor != L'\t') cursor++;
  }
  while (*cursor == L' ' || *cursor == L'\t') cursor++;
  return cursor;
}

static int fail(const wchar_t *message) {
  fwprintf(stderr, L"Hermsec portable scanner launcher: %ls\n", message);
  return 127;
}

int wmain(void) {
  wchar_t executable[PATH_CAPACITY];
  DWORD executable_length = GetModuleFileNameW(NULL, executable, PATH_CAPACITY);
  if (executable_length == 0 || executable_length >= PATH_CAPACITY) return fail(L"could not resolve launcher path");

  wchar_t *name = wcsrchr(executable, L'\\');
  if (!name) return fail(L"launcher path has no file name");
  const wchar_t *module = module_for_executable(name + 1);
  if (!module) return fail(L"unsupported scanner launcher name");
  *name = L'\0'; /* bin */

  wchar_t *tools_root_end = wcsrchr(executable, L'\\');
  if (!tools_root_end) return fail(L"launcher is not under runtime-tools/bin");
  *tools_root_end = L'\0';

  wchar_t python[PATH_CAPACITY];
  int python_length = _snwprintf_s(
    python,
    PATH_CAPACITY,
    _TRUNCATE,
    L"%ls\\python-runtime\\python.exe",
    executable
  );
  if (python_length < 0 || GetFileAttributesW(python) == INVALID_FILE_ATTRIBUTES) {
    return fail(L"embedded Python was not found beside runtime-tools/bin");
  }

  const wchar_t *tail = after_program_name(GetCommandLineW());
  size_t command_capacity = wcslen(python) + wcslen(module) + wcslen(tail) + 32;
  wchar_t *child_command = calloc(command_capacity, sizeof(wchar_t));
  if (!child_command) return fail(L"could not allocate child command line");

  _snwprintf_s(
    child_command,
    command_capacity,
    _TRUNCATE,
    L"\"%ls\" -I -m %ls%ls%ls",
    python,
    module,
    *tail ? L" " : L"",
    tail
  );

  STARTUPINFOW startup = {0};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process = {0};
  if (!CreateProcessW(python, child_command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process)) {
    free(child_command);
    return fail(L"could not start embedded Python");
  }
  free(child_command);

  WaitForSingleObject(process.hProcess, INFINITE);
  DWORD exit_code = 1;
  GetExitCodeProcess(process.hProcess, &exit_code);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return (int)exit_code;
}
