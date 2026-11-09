/* Interleaving model of the conn->preauth_info race in ksmbd (CVE-2026-72422).
 * No kernel code: two (or more) abstract threads over one shared pointer,
 * a set of objects with a live/freed flag and one mutex (conn_lock).
 *   send path, smb3_preauth_hash_rsp() NEGOTIATE branch:
 *     pre  (0c054227 old 9371-9374): CHECK P, LOAD P, USE      (no lock)
 *     post (0c054227 new 9371-9377): LOCK, CHECK, LOAD, USE, UNLOCK
 *   negotiate handler, smb2_handle_negotiate() (commit message: alloc and
 *   kfree + NULL all under conn_lock, held across the handler body):
 *     LOCK, [ALLOC], FREE, SETNULL, UNLOCK   per round
 * LOAD either reloads conn->preauth_info (RELOAD) or reuses the value read
 * by CHECK (CACHED): the C source reads the field twice and the compiler may
 * do either. Every interleaving is enumerated; nothing is executed. */
#ifndef KS_MODEL_H
#define KS_MODEL_H

#define KS_MAX_STEPS 64
#define KS_MAX_THREADS 4
#define KS_MAX_OBJS 8

typedef enum { KS_PRE, KS_POST } ks_version;
typedef enum { KS_RELOAD, KS_CACHED } ks_mode;
typedef enum {
  KV_FAIL_ONLY,  /* LOCK, FREE, SETNULL, UNLOCK (a negotiate that frees an existing object) */
  KV_ALLOC_FAIL, /* LOCK, ALLOC, FREE, SETNULL, UNLOCK (allocates, then fails) */
  KV_ALLOC_OK    /* LOCK, ALLOC, UNLOCK (negative control: nothing is freed) */
} ks_variant;
typedef enum { KI_NULL, KI_LIVE } ks_init;

typedef enum { KO_OK, KO_SKIP, KO_UAF, KO_NULL_DEREF, KO_INFEASIBLE, KO_BAD_INPUT } ks_outcome;

typedef struct {
  ks_version version;
  ks_mode mode;
  ks_variant variant;
  ks_init init;
  int rounds;  /* negotiate rounds in the handler thread, 1-3 */
  int senders; /* send-path threads, 1-2 */
} ks_config;

typedef struct {
  long schedules, ok, skip, uaf, null_deref; /* complete schedules; a schedule with any UAF counts as UAF */
} ks_counts;

/* Runs one schedule: a string of thread letters, 'N' for the handler and
 * 'S' / 'T' for the first / second sender, one letter per step. */
ks_outcome ks_schedule(const ks_config *c, const char *schedule);
/* Enumerates every interleaving (blocked threads cannot be scheduled). */
int ks_enumerate(const ks_config *c, ks_counts *out);
const char *ks_outcome_name(ks_outcome o);
int ks_parse_config(const char *version, const char *mode, const char *variant, const char *init,
                    int rounds, int senders, ks_config *c);
#endif
