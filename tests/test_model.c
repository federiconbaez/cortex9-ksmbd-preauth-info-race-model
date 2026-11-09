/* Tests for the ksmbd preauth_info interleaving model. Run under ASan + UBSan
 * with -fno-sanitize-recover (scripts/build.sh test). */
#include "cx9_util.h"
#include "ks_model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;
#define CHECK(c, what)                                                    \
  do {                                                                    \
    checks++;                                                             \
    if (!(c)) {                                                           \
      failures++;                                                         \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, what);               \
    }                                                                     \
  } while (0)

#define MAXCASES 64
typedef struct {
  char id[64], kind[16], schedule[256], hand[32];
  ks_config cfg;
} tcase;
static tcase cases[MAXCASES];
static int ncases;
static const char *versions[] = {"pre", "post"}, *modes[] = {"reload", "cached"},
                  *variants[] = {"fail_only", "alloc_fail", "alloc_ok"}, *inits[] = {"null", "live"};

static void load_cases(const char *dir) {
  char path[512], line[3 * CX9_FIELD_MAX];
  FILE *f;
  snprintf(path, sizeof path, "%s/cases.tsv", dir);
  f = fopen(path, "r");
  CHECK(f != NULL, "open cases.tsv");
  if (!f) return;
  while (fgets(line, sizeof line, f) && ncases < MAXCASES) {
    char *fl[CX9_MAX_FIELDS];
    tcase *c = &cases[ncases];
    if (line[0] == '#' || line[0] == '\n') continue;
    if (cx9_split_tsv(line, fl, CX9_MAX_FIELDS) != 10 || strlen(fl[0]) >= 64 || strlen(fl[1]) >= 16 ||
        strlen(fl[8]) >= 256 || strlen(fl[9]) >= 32 ||
        ks_parse_config(fl[2], fl[3], fl[4], fl[5], atoi(fl[6]), atoi(fl[7]), &c->cfg) != 0) {
      CHECK(0, "cases.tsv row");
      continue;
    }
    strcpy(c->id, fl[0]);
    strcpy(c->kind, fl[1]);
    strcpy(c->schedule, fl[8]);
    strcpy(c->hand, fl[9]);
    ncases++;
  }
  fclose(f);
  CHECK(ncases >= 20, "at least 20 fixture cases");
}

static void test_hand_labels(void) {
  int i, pos = 0, neg = 0;
  for (i = 0; i < ncases; ++i) {
    ks_outcome o = ks_schedule(&cases[i].cfg, cases[i].schedule);
    CHECK(strcmp(ks_outcome_name(o), cases[i].hand) == 0, cases[i].id);
    if (strcmp(cases[i].kind, "pos") == 0) {
      pos++;
      if (cases[i].cfg.version == KS_PRE) CHECK(o == KO_UAF || o == KO_NULL_DEREF, "positive pre: a fault");
      else CHECK(o == KO_INFEASIBLE, "positive post: the faulting order cannot happen");
    }
    if (strcmp(cases[i].kind, "neg") == 0) {
      neg++;
      CHECK(o == KO_OK || o == KO_SKIP, "negative: no fault");
    }
  }
  CHECK(pos >= 8 && neg >= 8, "enough positive and negative cases");
}

static void test_expected_file(const char *dir) {
  char path[512], line[1024];
  FILE *f;
  int ncase = 0, nsweep = 0;
  snprintf(path, sizeof path, "%s/expected.tsv", dir);
  f = fopen(path, "r");
  CHECK(f != NULL, "open expected.tsv");
  if (!f) return;
  while (fgets(line, sizeof line, f)) {
    char *fl[CX9_MAX_FIELDS];
    int n = cx9_split_tsv(line, fl, CX9_MAX_FIELDS), i, found = 0;
    if (n == 3 && strcmp(fl[0], "case") == 0) {
      for (i = 0; i < ncases; ++i)
        if (strcmp(cases[i].id, fl[1]) == 0) {
          found = 1;
          CHECK(strcmp(ks_outcome_name(ks_schedule(&cases[i].cfg, cases[i].schedule)), fl[2]) == 0, fl[1]);
          CHECK(strcmp(cases[i].hand, fl[2]) == 0, "hand label agrees with derive_expected");
        }
      CHECK(found, "expected id is in cases.tsv");
      ncase++;
    } else if (n == 12 && strcmp(fl[0], "sweep") == 0) {
      ks_config c;
      ks_counts k;
      CHECK(ks_parse_config(fl[1], fl[2], fl[3], fl[4], atoi(fl[5]), atoi(fl[6]), &c) == 0, "sweep config");
      CHECK(ks_enumerate(&c, &k) == 0, "enumerate");
      CHECK(k.schedules == atol(fl[7]) && k.ok == atol(fl[8]) && k.skip == atol(fl[9]) &&
                k.uaf == atol(fl[10]) && k.null_deref == atol(fl[11]),
            "counts agree with the memoised Python count");
      nsweep++;
    } else {
      CHECK(0, "expected.tsv row");
    }
  }
  fclose(f);
  CHECK(ncase == ncases && nsweep == 144, "every case and every configuration");
}

static void test_invariants(void) {
  size_t v, a, b, i;
  int r, s;
  for (v = 0; v < 2; ++v)
    for (a = 0; a < 2; ++a)
      for (b = 0; b < 3; ++b)
        for (i = 0; i < 2; ++i)
          for (r = 1; r <= 3; ++r)
            for (s = 1; s <= 2; ++s) {
              ks_config c;
              ks_counts k;
              ks_parse_config(versions[v], modes[a], variants[b], inits[i], r, s, &c);
              CHECK(ks_enumerate(&c, &k) == 0, "enumerate");
              CHECK(k.schedules == k.ok + k.skip + k.uaf + k.null_deref, "counts add up");
              if (v == 1) CHECK(k.uaf == 0 && k.null_deref == 0, "post: no UAF and no NULL dereference");
              if (b == 2) CHECK(k.uaf == 0 && k.null_deref == 0, "alloc_ok: nothing is freed, no fault");
              if (v == 0 && b != 2 && !(b == 0 && i == 0))
                CHECK(k.uaf > 0, "pre: every freeing configuration has a UAF schedule");
              if (b == 0 && i == 0) CHECK(k.skip == k.schedules, "fail_only from NULL: always SKIP");
              if (v == 0 && a == 1) CHECK(k.null_deref == 0, "pre cached: never a NULL dereference");
            }
}

/* Every string over {N,S} up to the full length, run through ks_schedule,
 * must add up to the enumeration for the same configuration. */
static void test_strings_vs_enumeration(void) {
  static const char *cfgs[][4] = {{"pre", "reload", "fail_only", "live"}, {"pre", "cached", "alloc_fail", "null"},
                                  {"post", "reload", "alloc_fail", "live"}, {"post", "cached", "fail_only", "live"}};
  size_t q;
  for (q = 0; q < sizeof cfgs / sizeof cfgs[0]; ++q) {
    ks_config c;
    ks_counts k, got;
    int len;
    memset(&got, 0, sizeof got);
    ks_parse_config(cfgs[q][0], cfgs[q][1], cfgs[q][2], cfgs[q][3], 1, 1, &c);
    ks_enumerate(&c, &k);
    for (len = 0; len <= 10; ++len) {
      long m, top = 1L << len;
      for (m = 0; m < top; ++m) {
        char sch[16];
        int i;
        ks_outcome o;
        for (i = 0; i < len; ++i) sch[i] = (m >> i) & 1 ? 'S' : 'N';
        sch[len] = '\0';
        o = ks_schedule(&c, sch);
        CHECK(o != KO_BAD_INPUT, "letters N and S are valid");
        if (o == KO_INFEASIBLE) continue;
        got.schedules++;
        if (o == KO_OK) got.ok++;
        if (o == KO_SKIP) got.skip++;
        if (o == KO_UAF) got.uaf++;
        if (o == KO_NULL_DEREF) got.null_deref++;
      }
    }
    CHECK(got.schedules == k.schedules && got.ok == k.ok && got.skip == k.skip && got.uaf == k.uaf &&
              got.null_deref == k.null_deref,
          "schedule strings and enumeration agree");
  }
}

static void test_adversarial(void) {
  ks_config c;
  static char big[KS_MAX_STEPS * KS_MAX_THREADS + 8];
  CHECK(ks_parse_config("mid", "reload", "fail_only", "live", 1, 1, &c) == -1, "bad version");
  CHECK(ks_parse_config("pre", "lazy", "fail_only", "live", 1, 1, &c) == -1, "bad mode");
  CHECK(ks_parse_config("pre", "reload", "x", "live", 1, 1, &c) == -1, "bad variant");
  CHECK(ks_parse_config("pre", "reload", "fail_only", "dead", 1, 1, &c) == -1, "bad init");
  CHECK(ks_parse_config("pre", "reload", "fail_only", "live", 0, 1, &c) == -1, "rounds 0");
  CHECK(ks_parse_config("pre", "reload", "fail_only", "live", 4, 1, &c) == -1, "rounds 4");
  CHECK(ks_parse_config("pre", "reload", "fail_only", "live", 1, 3, &c) == -1, "senders 3");
  ks_parse_config("pre", "reload", "fail_only", "live", 1, 1, &c);
  CHECK(ks_schedule(&c, "") == KO_INFEASIBLE, "empty schedule is incomplete");
  CHECK(ks_schedule(&c, "SSS") == KO_INFEASIBLE, "handler never ran");
  CHECK(ks_schedule(&c, "SSSNNNNN") == KO_INFEASIBLE, "extra handler step");
  CHECK(ks_schedule(&c, "s") == KO_BAD_INPUT, "lower case");
  CHECK(ks_schedule(&c, "T") == KO_BAD_INPUT, "second sender absent");
  memset(big, 'N', sizeof big - 1);
  CHECK(ks_schedule(&c, big) == KO_BAD_INPUT, "over-long schedule");
  ks_parse_config("post", "reload", "alloc_fail", "live", 3, 2, &c);
  CHECK(ks_schedule(&c, "NSNSNSNS") == KO_INFEASIBLE, "post: alternating inside a critical section");
}

/* PRACTICE.md levels, as checks. */
static void test_practice_levels(void) {
  ks_config c;
  ks_counts k;
  ks_parse_config("pre", "cached", "fail_only", "live", 1, 1, &c);
  CHECK(ks_schedule(&c, "SSSNNNN") == KO_OK, "level 1: no overlap");
  CHECK(ks_schedule(&c, "SNNNNSS") == KO_UAF, "level 2: check, free, use");
  ks_parse_config("pre", "reload", "fail_only", "live", 1, 1, &c);
  CHECK(ks_schedule(&c, "SNNNNSS") == KO_NULL_DEREF, "level 3: the reload sees NULL");
  CHECK(ks_schedule(&c, "SNNSNNS") == KO_UAF, "level 3: between kfree and the NULL store");
  ks_parse_config("post", "cached", "fail_only", "live", 1, 1, &c);
  CHECK(ks_schedule(&c, "SNNNNSSSS") == KO_INFEASIBLE, "level 4: the lock forbids the order");
  ks_enumerate(&c, &k);
  CHECK(k.schedules == 2 && k.uaf == 0, "level 4: two schedules, both safe");
  ks_parse_config("pre", "reload", "alloc_fail", "null", 1, 1, &c);
  CHECK(ks_schedule(&c, "NNSNSNSN") == KO_UAF, "level 5: the object from the failing negotiate");
  ks_parse_config("pre", "reload", "alloc_ok", "null", 3, 2, &c);
  ks_enumerate(&c, &k);
  CHECK(k.uaf == 0 && k.null_deref == 0, "level 6: success path only");
}

int main(int argc, char **argv) {
  const char *dir = argc > 1 ? argv[1] : "fixtures";
  load_cases(dir);
  test_hand_labels();
  test_expected_file(dir);
  test_invariants();
  test_strings_vs_enumeration();
  test_adversarial();
  test_practice_levels();
  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
