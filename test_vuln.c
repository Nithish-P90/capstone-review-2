/*
 * test_vuln.c — Sample C file with intentional vulnerabilities for scanner testing
 * Covers: CWE-120, CWE-476, CWE-416, CWE-190, CWE-78, CWE-134, CWE-20
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── CWE-120: Buffer overflow via strcpy ───────────────────
 * strcpy does not check destination buffer size.
 * Attacker-controlled 'username' can overflow 'buf[16]'.
 */
void process_username(char *username) {
    char buf[16];
    strcpy(buf, username);   /* VULNERABLE: no bounds check */
    printf("Hello, %s\n", buf);
}

/* ── CWE-476: Null pointer dereference ────────────────────
 * malloc can return NULL on allocation failure.
 * Dereferencing without NULL check causes crash.
 */
void create_user(int size) {
    char *data = (char *)malloc(size);
    data[0] = 'A';           /* VULNERABLE: no NULL check */
    free(data);
}

/* ── CWE-416: Use-after-free ──────────────────────────────
 * Memory is freed then accessed again on the next line.
 */
void update_record(void) {
    char *buf = (char *)malloc(64);
    if (buf == NULL) return;
    strcpy(buf, "record data");
    free(buf);
    printf("%s\n", buf);     /* VULNERABLE: use after free */
}

/* ── CWE-190: Integer overflow ────────────────────────────
 * 'count' could be large enough that count*sizeof(int)
 * wraps to a small value, causing under-allocation.
 */
void allocate_array(int count) {
    int *arr = (int *)malloc(count * sizeof(int));  /* VULNERABLE: overflow in count*4 */
    if (arr == NULL) return;
    for (int i = 0; i < count; i++) arr[i] = i;
    free(arr);
}

/* ── CWE-78: OS command injection ─────────────────────────
 * User input passed directly to system() without sanitization.
 */
void run_report(char *filename) {
    char cmd[256];
    sprintf(cmd, "cat %s", filename);  /* VULNERABLE: filename could contain ; rm -rf */
    system(cmd);
}

/* ── CWE-134: Format string vulnerability ─────────────────
 * User-controlled string passed as format argument to printf.
 */
void log_message(char *user_input) {
    printf(user_input);      /* VULNERABLE: user controls format string */
}

/* ── CWE-20: Improper input validation ────────────────────
 * Array index from user input used without bounds check.
 */
int get_value(int *arr, int index) {
    return arr[index];       /* VULNERABLE: index not validated */
}

/* ── SAFE: correct buffer copy with bounds check ──────────
 * This function is intentionally safe — scanner should NOT flag it.
 */
void safe_copy(char *dest, const char *src, size_t dest_size) {
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

/* ── SAFE: correct null check after malloc ────────────────
 * Intentionally safe — scanner should NOT flag it.
 */
char *safe_alloc(size_t size) {
    char *ptr = (char *)malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "allocation failed\n");
        return NULL;
    }
    return ptr;
}
