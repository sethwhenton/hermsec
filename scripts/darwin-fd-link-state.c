#define _DARWIN_C_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
  inherited_target_fd = 3,
};

int main(void) {
  char path[MAXPATHLEN];
  struct stat descriptor_stat;
  struct stat path_stat;

  if (fstat(inherited_target_fd, &descriptor_stat) != 0) {
    fprintf(stderr, "fstat failed: %d\n", errno);
    return 2;
  }

  errno = 0;
  if (fcntl(inherited_target_fd, F_GETPATH, path) != 0) {
    if (errno == ENOENT) {
      puts("unlinked");
      return 0;
    }
    fprintf(stderr, "F_GETPATH failed: %d\n", errno);
    return 2;
  }

  if (lstat(path, &path_stat) != 0) {
    fprintf(stderr, "F_GETPATH returned an unverifiable path: %d\n", errno);
    return 2;
  }
  if (
    descriptor_stat.st_dev != path_stat.st_dev ||
    descriptor_stat.st_ino != path_stat.st_ino
  ) {
    fputs("F_GETPATH resolved to a different object\n", stderr);
    return 2;
  }

  puts("linked");
  return 0;
}
