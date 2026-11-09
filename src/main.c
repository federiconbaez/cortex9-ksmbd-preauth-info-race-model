/* CLI (enumerates schedules of an abstract model; no kernel code):
 *   ksrace results fixtures/cases.tsv <dir>     regenerate cases.csv + sweep.csv
 *   ksrace case <version> <mode> <variant> <init> <rounds> <senders> <schedule> */
#include "cx9_util.h"
#include "ks_model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *versions[] = {"pre", "post"}, *modes[] = {"reload", "cached"},
                  *variants[] = {"fail_only", "alloc_fail", "alloc_ok"}, *inits[] = {"null", "live"};

static int results(const char *cases, const char *dir) {
  char path[1024], line[3 * CX9_FIELD_MAX];
  FILE *in = fopen(cases, "r"), *out, *sw;
  size_t a, b, v, i;
  int r, s;
  if (!in) return 1;
  snprintf(path, sizeof path, "%s/cases.csv", dir);
  out = fopen(path, "w");
  if (!out) { fclose(in); return 1; }
  fputs("id,kind,version,mode,variant,init,rounds,senders,schedule,outcome\n", out);
  while (fgets(line, sizeof line, in)) {
    char *f[CX9_MAX_FIELDS];
    ks_config c;
    if (line[0] == '#' || line[0] == '\n') continue;
    if (cx9_split_tsv(line, f, CX9_MAX_FIELDS) != 10 ||
        ks_parse_config(f[2], f[3], f[4], f[5], atoi(f[6]), atoi(f[7]), &c) != 0) {
      fclose(in); fclose(out);
      return 1;
    }
    for (i = 0; i < 9; ++i) fprintf(out, "%s,", f[i]);
    fprintf(out, "%s\n", ks_outcome_name(ks_schedule(&c, f[8])));
  }
  fclose(in);
  fclose(out);
  snprintf(path, sizeof path, "%s/sweep.csv", dir);
  sw = fopen(path, "w");
  if (!sw) return 1;
  fputs("version,mode,variant,init,rounds,senders,schedules,ok,skip,uaf,null_deref\n", sw);
  for (v = 0; v < 2; ++v)
    for (a = 0; a < 2; ++a)
      for (b = 0; b < 3; ++b)
        for (i = 0; i < 2; ++i)
          for (r = 1; r <= 3; ++r)
            for (s = 1; s <= 2; ++s) {
              ks_config c;
              ks_counts k;
              if (ks_parse_config(versions[v], modes[a], variants[b], inits[i], r, s, &c) ||
                  ks_enumerate(&c, &k)) {
                fclose(sw);
                return 1;
              }
              fprintf(sw, "%s,%s,%s,%s,%d,%d,%ld,%ld,%ld,%ld,%ld\n", versions[v], modes[a], variants[b],
                      inits[i], r, s, k.schedules, k.ok, k.skip, k.uaf, k.null_deref);
            }
  fclose(sw);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 4 && strcmp(argv[1], "results") == 0) return results(argv[2], argv[3]);
  if (argc == 9 && strcmp(argv[1], "case") == 0) {
    ks_config c;
    ks_counts k;
    if (ks_parse_config(argv[2], argv[3], argv[4], argv[5], atoi(argv[6]), atoi(argv[7]), &c)) return 2;
    printf("outcome=%s\n", ks_outcome_name(ks_schedule(&c, argv[8])));
    if (ks_enumerate(&c, &k) == 0)
      printf("all schedules of this configuration: %ld (ok %ld, skip %ld, uaf %ld, null_deref %ld)\n",
             k.schedules, k.ok, k.skip, k.uaf, k.null_deref);
    return 0;
  }
  fprintf(stderr, "usage: %s results <cases.tsv> <dir> | case <version> <mode> <variant> <init> <rounds> "
                  "<senders> <schedule>\n", argv[0]);
  return 2;
}
