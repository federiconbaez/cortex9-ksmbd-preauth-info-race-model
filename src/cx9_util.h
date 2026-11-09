/* Small helpers shared by the model, the CLI and the tests: TSV fields
 * with C-style escapes, and CSV quoting. No allocation, bounded buffers. */
#ifndef CX9_UTIL_H
#define CX9_UTIL_H
#include <stddef.h>
#include <stdio.h>

#define CX9_FIELD_MAX 4096
#define CX9_MAX_FIELDS 16

/* Split a TSV line in place (tabs; trailing \n/\r removed). Returns the
 * number of fields, or -1 if there are more than max. */
int cx9_split_tsv(char *line, char **fields, int max);

/* Decode \\ \t \n \r \xHH into out (NUL-terminated). Returns the decoded
 * length, or -1 on a malformed escape, an embedded NUL or overflow. */
long cx9_unescape(const char *in, char *out, size_t outsz);

/* Encode bytes so that the result has no tab, newline, backslash or
 * non-printable byte (inverse of cx9_unescape). Returns 0, -1 on overflow. */
int cx9_escape(const char *in, size_t n, char *out, size_t outsz);

/* Write s as one CSV field (RFC 4180 quoting when needed). */
void cx9_csv_field(FILE *f, const char *s);
#endif
