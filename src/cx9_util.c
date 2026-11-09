#include "cx9_util.h"
#include <string.h>

int cx9_split_tsv(char *line, char **fields, int max) {
  int n = 0;
  size_t len = strlen(line);
  char *p = line;
  while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
  for (;;) {
    char *t = strchr(p, '\t');
    if (n >= max) return -1;
    fields[n++] = p;
    if (!t) break;
    *t = '\0';
    p = t + 1;
  }
  return n;
}

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

long cx9_unescape(const char *in, char *out, size_t outsz) {
  size_t o = 0;
  if (outsz == 0) return -1;
  while (*in) {
    char c = *in++;
    if (c == '\\') {
      char e = *in++;
      if (e == '\\') c = '\\';
      else if (e == 't') c = '\t';
      else if (e == 'n') c = '\n';
      else if (e == 'r') c = '\r';
      else if (e == 'x') {
        int h, l;
        if (!in[0] || !in[1]) return -1;
        h = hexval(in[0]);
        l = hexval(in[1]);
        if (h < 0 || l < 0) return -1;
        c = (char)(h * 16 + l);
        in += 2;
        if (c == '\0') return -1;
      } else return -1;
    }
    if (o + 1 >= outsz) return -1;
    out[o++] = c;
  }
  out[o] = '\0';
  return (long)o;
}

int cx9_escape(const char *in, size_t n, char *out, size_t outsz) {
  static const char hx[] = "0123456789abcdef";
  size_t i, o = 0;
  for (i = 0; i < n; ++i) {
    unsigned char c = (unsigned char)in[i];
    char buf[4];
    size_t k = 0, j;
    if (c == '\\') { buf[k++] = '\\'; buf[k++] = '\\'; }
    else if (c == '\t') { buf[k++] = '\\'; buf[k++] = 't'; }
    else if (c == '\n') { buf[k++] = '\\'; buf[k++] = 'n'; }
    else if (c == '\r') { buf[k++] = '\\'; buf[k++] = 'r'; }
    else if (c < 0x20 || c >= 0x7f) {
      buf[k++] = '\\'; buf[k++] = 'x'; buf[k++] = hx[c >> 4]; buf[k++] = hx[c & 15];
    } else buf[k++] = (char)c;
    if (o + k + 1 > outsz) return -1;
    for (j = 0; j < k; ++j) out[o++] = buf[j];
  }
  if (o + 1 > outsz) return -1;
  out[o] = '\0';
  return 0;
}

void cx9_csv_field(FILE *f, const char *s) {
  if (strpbrk(s, ",\"\n\r") == NULL) {
    fputs(s, f);
    return;
  }
  fputc('"', f);
  for (; *s; ++s) {
    if (*s == '"') fputc('"', f);
    fputc(*s, f);
  }
  fputc('"', f);
}
