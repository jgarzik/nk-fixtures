/*
 * ABI probe: what a table of facts is made of. Shared by the files that
 * each declare one (probe.c, probe-unwind.c).
 */

#define NKABI_NAME_LEN 88

typedef struct _NKABI_ENTRY {
    char Name[NKABI_NAME_LEN];
    unsigned __int64 Value;
} NKABI_ENTRY;

#define SZ(type) { "sizeof " #type, sizeof(type) },
#define OFF(type, member) { "offsetof " #type " " #member, FIELD_OFFSET(type, member) },

/* Every table starts with this entry, the pointer size as a sanity check,
 * and ends with NKABI_END. */
#define NKABI_BEGIN { "NKABI-BEGIN v1", sizeof(void *) }
#define NKABI_END { "NKABI-END", 0 }
