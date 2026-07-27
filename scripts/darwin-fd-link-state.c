#define _DARWIN_C_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
  inherited_target_fd = 3,
};

int main(void) {
  char probe_name[96];
  struct stat descriptor_stat;

  if (fstat(inherited_target_fd, &descriptor_stat) != 0) {
    fprintf(stderr, "fstat failed: %d\n", errno);
    return 2;
  }
  if (!S_ISDIR(descriptor_stat.st_mode)) {
    fputs("inherited target is not a directory\n", stderr);
    return 2;
  }

  const int written = snprintf(
    probe_name,
    sizeof(probe_name),
    ".hermsec-link-probe-%ld",
    (long)getpid()
  );
  if (written < 0 || (size_t)written >= sizeof(probe_name)) {
    fputs("failed to create the namespace probe name\n", stderr);
    return 2;
  }

  /*
   * APFS keeps a stale F_GETPATH result after rmdir and does not decrease a
   * directory's reported link count. Probe the descriptor itself instead:
   * creating a child succeeds while the directory still has a namespace
   * link, but APFS returns ENOENT once the open directory has been removed.
   * An attacker can make this check fail closed, but cannot redirect a
   * descriptor-relative mkdir to a replacement path.
   */
  if (mkdirat(inherited_target_fd, probe_name, 0700) != 0) {
    if (errno == ENOENT) {
      puts("unlinked");
      return 0;
    }
    fprintf(stderr, "descriptor-relative namespace probe failed: %d\n", errno);
    return 2;
  }

  if (unlinkat(inherited_target_fd, probe_name, AT_REMOVEDIR) != 0) {
    fprintf(stderr, "failed to remove the namespace probe: %d\n", errno);
    return 2;
  }

  puts("linked");
  return 0;
}
