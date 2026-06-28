#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <action> <param>\n", argv[0]);
        return 1;
    }

    const char* action = argv[1];
    const char* param = argv[2];

    if (strcmp(action, "echo") == 0) {
        printf("Data: %s\n", param);
    } else if (strcmp(action, "file") == 0) {
        FILE* fp = fopen(param, "r");
        if (fp) {
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), fp)) {
                printf("%s", buffer);
            }
            fclose(fp);
        } else {
            printf("File not found\n");
        }
    }

    return 0;
}
