#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

// VULN 1: Hardcoded database credentials (CWE-798)
const char* DB_HOST = "localhost";
const char* DB_USER = "admin";
const char* DB_PASS = "vulntest_cpp_db_pass!@#";

// VULN 2: Hardcoded API key (CWE-798)
const char* API_KEY = "vulntest-cpp-api-key-ck-1234567890abcdef";

// VULN 3: Buffer overflow via gets (CWE-120)
void gets_vulnerable() {
    char buffer[64];
    printf("Enter name: ");
    gets(buffer);  // VULN: gets() is unsafe
    printf("Hello, %s\n", buffer);
}

// VULN 4: Buffer overflow via strcpy (CWE-120)
void strcpy_vulnerable(const char* input) {
    char buffer[64];
    strcpy(buffer, input);  // VULN: no bounds checking
    printf("Data: %s\n", buffer);
}

// VULN 5: Buffer overflow via strcat (CWE-120)
void strcat_vulnerable(const char* input) {
    char buffer[128] = "Prefix: ";
    strcat(buffer, input);  // VULN: no bounds checking
    printf("Data: %s\n", buffer);
}

// VULN 6: Format string vulnerability (CWE-134)
void format_string_vulnerable(const char* input) {
    printf(input);  // VULN: user input as format string
}

// VULN 7: Command Injection via popen (CWE-78)
void ping_host(const char* host) {
    char command[256];
    snprintf(command, sizeof(command), "ping -c 4 %s", host);
    FILE* fp = popen(command, "r");
    if (fp) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), fp)) {
            printf("%s", buffer);
        }
        pclose(fp);
    }
}

// VULN 8: Command Injection via system (CWE-78)
void run_command(const char* cmd) {
    system(cmd);  // VULN: direct system call
}

// VULN 9: Path Traversal (CWE-22)
void read_file(const char* filename) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "data/%s", filename);
    FILE* fp = fopen(filepath, "r");
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

// VULN 10: XSS via sprintf (CWE-79)
void search_page(const char* query) {
    char html[1024];
    snprintf(html, sizeof(html), "<html><body><h1>Search: %s</h1></body></html>", query);
    printf("%s", html);
}

// VULN 11: Weak random (CWE-330)
void generate_token() {
    srand(time(NULL));
    int token = rand();
    printf("Token: %d\n", token);
}

// VULN 12: Information exposure (CWE-209)
void handle_error() {
    FILE* fp = fopen("/nonexistent/file", "r");
    if (!fp) {
        perror("Error opening file");  // VULN: verbose error
        printf("errno: %d\n", errno);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <action> <param>\n", argv[0]);
        return 1;
    }

    const char* action = argv[1];
    const char* param = argv[2];

    if (strcmp(action, "gets") == 0) {
        gets_vulnerable();
    } else if (strcmp(action, "strcpy") == 0) {
        strcpy_vulnerable(param);
    } else if (strcmp(action, "strcat") == 0) {
        strcat_vulnerable(param);
    } else if (strcmp(action, "printf") == 0) {
        format_string_vulnerable(param);
    } else if (strcmp(action, "ping") == 0) {
        ping_host(param);
    } else if (strcmp(action, "run") == 0) {
        run_command(param);
    } else if (strcmp(action, "file") == 0) {
        read_file(param);
    } else if (strcmp(action, "search") == 0) {
        search_page(param);
    } else if (strcmp(action, "token") == 0) {
        generate_token();
    } else if (strcmp(action, "error") == 0) {
        handle_error();
    }

    return 0;
}
