#include "ks_model.h"
#include <string.h>

typedef enum { OP_LOCK, OP_UNLOCK, OP_CHECK, OP_LOAD, OP_USE, OP_ALLOC, OP_FREE, OP_SETNULL } op;

typedef struct {
  op ops[KS_MAX_STEPS];
  int n;
} prog;

typedef struct {
  int ptr;                   /* -1 = NULL, else object id */
  int live[KS_MAX_OBJS];
  int nobjs;
  int owner;                 /* -1 = free, else thread index */
  int pc[KS_MAX_THREADS];
  int seen[KS_MAX_THREADS];  /* value read by CHECK */
  int addr[KS_MAX_THREADS];  /* value used by USE */
  ks_outcome res[KS_MAX_THREADS];
} state;

static const char *onames[] = {"OK", "SKIP", "UAF", "NULL_DEREF", "INFEASIBLE", "BAD_INPUT"};
const char *ks_outcome_name(ks_outcome o) { return onames[o]; }

int ks_parse_config(const char *version, const char *mode, const char *variant, const char *init,
                    int rounds, int senders, ks_config *c) {
  memset(c, 0, sizeof *c);
  if (strcmp(version, "pre") == 0) c->version = KS_PRE;
  else if (strcmp(version, "post") == 0) c->version = KS_POST;
  else return -1;
  if (strcmp(mode, "reload") == 0) c->mode = KS_RELOAD;
  else if (strcmp(mode, "cached") == 0) c->mode = KS_CACHED;
  else return -1;
  if (strcmp(variant, "fail_only") == 0) c->variant = KV_FAIL_ONLY;
  else if (strcmp(variant, "alloc_fail") == 0) c->variant = KV_ALLOC_FAIL;
  else if (strcmp(variant, "alloc_ok") == 0) c->variant = KV_ALLOC_OK;
  else return -1;
  if (strcmp(init, "null") == 0) c->init = KI_NULL;
  else if (strcmp(init, "live") == 0) c->init = KI_LIVE;
  else return -1;
  if (rounds < 1 || rounds > 3 || senders < 1 || senders > 2) return -1;
  c->rounds = rounds;
  c->senders = senders;
  return 0;
}

static void build(const ks_config *c, prog *p, int nthreads) {
  int t, r;
  memset(p, 0, sizeof(prog) * (size_t)nthreads);
  for (r = 0; r < c->rounds; ++r) { /* thread 0: the negotiate handler */
    prog *h = &p[0];
    h->ops[h->n++] = OP_LOCK;
    if (c->variant != KV_FAIL_ONLY) h->ops[h->n++] = OP_ALLOC;
    if (c->variant != KV_ALLOC_OK) {
      h->ops[h->n++] = OP_FREE;
      h->ops[h->n++] = OP_SETNULL;
    }
    h->ops[h->n++] = OP_UNLOCK;
  }
  for (t = 1; t < nthreads; ++t) {
    prog *s = &p[t];
    if (c->version == KS_POST) s->ops[s->n++] = OP_LOCK;
    s->ops[s->n++] = OP_CHECK;
    s->ops[s->n++] = OP_LOAD;
    s->ops[s->n++] = OP_USE;
    if (c->version == KS_POST) s->ops[s->n++] = OP_UNLOCK;
  }
}

static void init_state(const ks_config *c, state *st, int nthreads) {
  int t;
  memset(st, 0, sizeof *st);
  st->owner = -1;
  st->ptr = -1;
  if (c->init == KI_LIVE) {
    st->ptr = 0;
    st->live[0] = 1;
    st->nobjs = 1;
  }
  for (t = 0; t < nthreads; ++t) {
    st->seen[t] = -1;
    st->addr[t] = -1;
    st->res[t] = KO_OK;
  }
}

static int done(const prog *p, const state *st, int t) { return st->pc[t] >= p[t].n; }
static int blocked(const prog *p, const state *st, int t) {
  return !done(p, st, t) && p[t].ops[st->pc[t]] == OP_LOCK && st->owner != -1;
}

/* One step of thread t. Returns 0, or -1 if the model would overflow. */
static int step(const ks_config *c, const prog *p, state *st, int t) {
  op o = p[t].ops[st->pc[t]];
  st->pc[t]++;
  switch (o) {
    case OP_LOCK: st->owner = t; break;
    case OP_UNLOCK: st->owner = -1; break;
    case OP_ALLOC:
      if (st->nobjs >= KS_MAX_OBJS) return -1;
      st->live[st->nobjs] = 1;
      st->ptr = st->nobjs++;
      break;
    case OP_FREE:
      if (st->ptr >= 0) st->live[st->ptr] = 0;
      break;
    case OP_SETNULL: st->ptr = -1; break;
    case OP_CHECK:
      st->seen[t] = st->ptr;
      if (st->ptr < 0) { /* if (conn->preauth_info) is false: skip to the end (or the unlock) */
        st->res[t] = KO_SKIP;
        st->pc[t] = c->version == KS_POST ? p[t].n - 1 : p[t].n;
      }
      break;
    case OP_LOAD: st->addr[t] = c->mode == KS_RELOAD ? st->ptr : st->seen[t]; break;
    case OP_USE:
      if (st->addr[t] < 0) st->res[t] = KO_NULL_DEREF;
      else if (!st->live[st->addr[t]]) st->res[t] = KO_UAF;
      else st->res[t] = KO_OK;
      break;
  }
  return 0;
}

static ks_outcome combine(const state *st, int nthreads) {
  int t, any_uaf = 0, any_null = 0, all_skip = 1;
  for (t = 1; t < nthreads; ++t) {
    any_uaf |= st->res[t] == KO_UAF;
    any_null |= st->res[t] == KO_NULL_DEREF;
    all_skip &= st->res[t] == KO_SKIP;
  }
  return any_uaf ? KO_UAF : any_null ? KO_NULL_DEREF : all_skip ? KO_SKIP : KO_OK;
}

ks_outcome ks_schedule(const ks_config *c, const char *schedule) {
  prog p[KS_MAX_THREADS];
  state st;
  int nthreads = 1 + c->senders, t;
  size_t i;
  if (strlen(schedule) > KS_MAX_STEPS * KS_MAX_THREADS) return KO_BAD_INPUT;
  build(c, p, nthreads);
  init_state(c, &st, nthreads);
  for (i = 0; schedule[i]; ++i) {
    char ch = schedule[i];
    t = ch == 'N' ? 0 : ch == 'S' ? 1 : ch == 'T' ? 2 : -1;
    if (t < 0 || t >= nthreads) return KO_BAD_INPUT;
    if (done(p, &st, t) || blocked(p, &st, t)) return KO_INFEASIBLE;
    if (step(c, p, &st, t)) return KO_BAD_INPUT;
  }
  for (t = 0; t < nthreads; ++t)
    if (!done(p, &st, t)) return KO_INFEASIBLE; /* incomplete schedule */
  return combine(&st, nthreads);
}

static int dfs(const ks_config *c, const prog *p, const state *st, int nthreads, ks_counts *out) {
  int t, moved = 0;
  for (t = 0; t < nthreads; ++t) {
    state nx;
    if (done(p, st, t) || blocked(p, st, t)) continue;
    nx = *st;
    if (step(c, p, &nx, t) || dfs(c, p, &nx, nthreads, out)) return -1;
    moved = 1;
  }
  if (!moved) {
    for (t = 0; t < nthreads; ++t)
      if (!done(p, st, t)) return -1; /* deadlock: cannot happen with one mutex */
    out->schedules++;
    switch (combine(st, nthreads)) {
      case KO_OK: out->ok++; break;
      case KO_SKIP: out->skip++; break;
      case KO_UAF: out->uaf++; break;
      case KO_NULL_DEREF: out->null_deref++; break;
      default: return -1;
    }
  }
  return 0;
}

int ks_enumerate(const ks_config *c, ks_counts *out) {
  prog p[KS_MAX_THREADS];
  state st;
  int nthreads = 1 + c->senders;
  memset(out, 0, sizeof *out);
  build(c, p, nthreads);
  init_state(c, &st, nthreads);
  return dfs(c, p, &st, nthreads, out);
}
