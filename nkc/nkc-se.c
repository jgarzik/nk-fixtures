/*
 * Conformance: security descriptors, access checks and tokens.
 *
 * Two lists.
 *
 * List 0 (0x222000) begins in the sender's thread: building a descriptor
 * with an access list the way a driver does for its device, the
 * well-known SIDs the kernel exports, and the two layouts of a
 * descriptor, absolute and self-relative. It goes on, on a system
 * thread, with what a file system asks of the security subsystem for
 * its own objects: the access check, privilege checks, the access state
 * of an open, the descriptor of a new object, and reading and changing
 * the parts of a descriptor.
 *
 * List 1 (0x222004), on a system thread: the System process's token as
 * the Se and the Zw routines describe it, duplicates of it, and
 * impersonation, which a thread made for it takes on and puts off.
 *
 * The subject of every check is the System process's token, since a
 * system thread is the same on every system: its user is the
 * system (S-1-5-18), its groups administrators (the owner it gives new
 * objects), everyone and authenticated users. Access lists are written
 * for those, and for SIDs it does not have. Access rights are a file's:
 * the generic mapping is that of files. A check is made for user mode
 * unless it says otherwise: for kernel mode nothing is checked.
 *
 * A descriptor a routine returns is logged part by part (NkcDump); a
 * SID is logged as one number (NkcSidCode).
 *
 * Of nkc-undoc.h: SeCreateAccessState, SeDeleteAccessState,
 * ZwImpersonateAnonymousToken, and the exports PsDereferencePrimaryToken
 * and PsDereferenceImpersonationToken.
 *
 * Left out: a descriptor with no owner or a null descriptor in an
 * access check, object-specific and conditional entries, system access
 * lists and mandatory labels, restricted tokens.
 */

/* The security routines are declared for file systems: <ntifs.h>,
 * which must come before <ntddk.h>. */
#include <ntifs.h>

#define NKC_DEVICE L"\\Device\\NkcSe"
#define NKC_THREADS
#define NKC_LISTS 2
#include "nkc.h"
#include "nkc-undoc.h"

static NKC_LIST_ROUTINE NkcSystemFacts;

/* Exported by the kernel and used by Microsoft's device-security
 * library; declared here in case the kit's headers leave it out. */
NTKERNELAPI NTSTATUS SeCaptureSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor,
                                                 KPROCESSOR_MODE RequestorMode, POOL_TYPE PoolType,
                                                 BOOLEAN ForceCapture,
                                                 PSECURITY_DESCRIPTOR *CapturedSecurityDescriptor);

#define NKC_ACL_ROOM 64

/* An empty access list in `Room` bytes, as RtlCreateAcl would leave it. */
static VOID NkcEmptyAcl(PACL Acl, USHORT Room)
{
    RtlZeroMemory(Acl, Room);
    Acl->AclRevision = ACL_REVISION;
    Acl->AclSize = Room;
}

static VOID NkcRun(NKC_LOG *Log)
{
    SECURITY_DESCRIPTOR Sd;
    UCHAR AclRoom[NKC_ACL_ROOM];
    UCHAR Relative[256];
    PACL Acl = (PACL)AclRoom;
    PACL Got;
    PSID Sid;
    BOOLEAN Present, Defaulted;
    ULONG Length;
    PSECURITY_DESCRIPTOR Captured;
    PISECURITY_DESCRIPTOR_RELATIVE Rel = (PISECURITY_DESCRIPTOR_RELATIVE)Relative;

    /* 12, 16, 12: the lengths of the SIDs for the system, for
     * administrators and for everyone. */
    NkcPut(Log, RtlLengthSid(SeExports->SeLocalSystemSid));
    NkcPut(Log, RtlLengthSid(SeExports->SeAliasAdminsSid));
    NkcPut(Log, RtlLengthSid(SeExports->SeWorldSid));

    /* 0xC0000058, 0: a descriptor is created at revision 1 only. */
    NkcPut(Log, (ULONG)RtlCreateSecurityDescriptor(&Sd, 2));
    NkcPut(Log, (ULONG)RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION));

    /* The length of an empty absolute descriptor, and its control bits. */
    NkcPut(Log, RtlLengthSecurityDescriptor(&Sd));
    NkcPut(Log, Sd.Control);

    /* 0, 0, 1, 0: it has no owner, and no access list. */
    Sid = (PSID)(ULONG_PTR)1;
    Defaulted = 1;
    NkcPut(Log, (ULONG)RtlGetOwnerSecurityDescriptor(&Sd, &Sid, &Defaulted));
    NkcPut(Log, Sid == NULL ? 0 : 1);
    Present = 1;
    NkcPut(Log, (ULONG)RtlGetDaclSecurityDescriptor(&Sd, &Present, &Got, &Defaulted));
    NkcPut(Log, Present);

    /* 0xC0000059: an entry at a revision the list does not have.
     * 0, 0, 2: full access for the system, then for administrators.
     * The space the two entries leave used. */
    NkcEmptyAcl(Acl, NKC_ACL_ROOM);
    NkcPut(Log, (ULONG)RtlAddAccessAllowedAce(Acl, ACL_REVISION + 5, GENERIC_ALL,
                                              SeExports->SeLocalSystemSid));
    NkcPut(Log, (ULONG)RtlAddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL,
                                              SeExports->SeLocalSystemSid));
    NkcPut(Log, (ULONG)RtlAddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL,
                                              SeExports->SeAliasAdminsSid));
    NkcPut(Log, Acl->AceCount);
    {
        /* Where the entries end: the header, then each entry in turn. */
        PACE_HEADER Ace = (PACE_HEADER)(Acl + 1);
        ULONG Used = sizeof(ACL);
        USHORT i;
        for (i = 0; i < Acl->AceCount; i++) {
            Used += Ace->AceSize;
            Ace = (PACE_HEADER)((PUCHAR)Ace + Ace->AceSize);
        }
        NkcPut(Log, Used);
    }

    /* The status when there is no room left for another entry. */
    NkcEmptyAcl((PACL)Relative, sizeof(ACL) + 8);
    NkcPut(Log, (ULONG)RtlAddAccessAllowedAce((PACL)Relative, ACL_REVISION, GENERIC_ALL,
                                              SeExports->SeAliasAdminsSid));

    /* 0; then 0, 1, 1, 0: the list is put in the descriptor, and comes
     * back: present, the same list, not defaulted. Control bits after. */
    NkcPut(Log, (ULONG)RtlSetDaclSecurityDescriptor(&Sd, TRUE, Acl, FALSE));
    Got = NULL;
    NkcPut(Log, (ULONG)RtlGetDaclSecurityDescriptor(&Sd, &Present, &Got, &Defaulted));
    NkcPut(Log, Present);
    NkcPut(Log, Got == Acl ? 1 : 0);
    NkcPut(Log, Defaulted);
    NkcPut(Log, Sd.Control);

    /* The descriptor's length now. */
    NkcPut(Log, RtlLengthSecurityDescriptor(&Sd));

    /* 0xC0000023 and the room needed; then 0: the self-relative form,
     * its control bits, its length, and where in it the list is. */
    Length = 0;
    NkcPut(Log, (ULONG)RtlAbsoluteToSelfRelativeSD(&Sd, Relative, &Length));
    NkcPut(Log, Length);
    Length = sizeof(Relative);
    NkcPut(Log, (ULONG)RtlAbsoluteToSelfRelativeSD(&Sd, Relative, &Length));
    NkcPut(Log, Rel->Control);
    NkcPut(Log, RtlLengthSecurityDescriptor(Relative));
    Got = NULL;
    NkcPut(Log, (ULONG)RtlGetDaclSecurityDescriptor(Relative, &Present, &Got, &Defaulted));
    NkcPut(Log, (ULONG)((PUCHAR)Got - Relative));
    NkcPut(Log, Rel->Owner);
    NkcPut(Log, Rel->Dacl);

    /* The status when a list is put in a self-relative descriptor. */
    NkcPut(Log, (ULONG)RtlSetDaclSecurityDescriptor(Relative, TRUE, Acl, FALSE));

    /* 0, 1: captured for a kernel-mode caller without being forced,
     * a descriptor is the caller's own. */
    Captured = NULL;
    NkcPut(Log, (ULONG)SeCaptureSecurityDescriptor(&Sd, KernelMode, NonPagedPool, FALSE,
                                                   &Captured));
    NkcPut(Log, Captured == &Sd ? 1 : 0);

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());

    /* The rest of the list, on a system thread. */
    NkcOnSystemThread(NkcSystemFacts, Log);
}

/*
 * The rest of both lists: SIDs, access lists and descriptors made by
 * hand, so that the only routines called are the ones in question.
 */

/* A SID of one or two sub-authorities, laid out as the kernel's. */
typedef struct _NKC_SID {
    UCHAR Revision;
    UCHAR Count;
    UCHAR Authority[6];
    ULONG Sub[2];
} NKC_SID;

#define NKC_SID_1(Authority, A)                                                                   \
    {                                                                                             \
        1, 1, { 0, 0, 0, 0, 0, Authority }, { A, 0 }                                              \
    }
#define NKC_SID_2(Authority, A, B)                                                                \
    {                                                                                             \
        1, 2, { 0, 0, 0, 0, 0, Authority }, { A, B }                                              \
    }

static NKC_SID NkcSystem = NKC_SID_1(5, 18);         /* the token's user */
static NKC_SID NkcAdmins = NKC_SID_2(5, 32, 544);    /* a group of it, and its owner */
static NKC_SID NkcWorld = NKC_SID_1(1, 0);           /* a group of it */
static NKC_SID NkcAuthenticated = NKC_SID_1(5, 11);  /* a group of it */
static NKC_SID NkcAnonymous = NKC_SID_1(5, 7);       /* not in it */
static NKC_SID NkcUsers = NKC_SID_2(5, 32, 545);     /* not in it */
static NKC_SID NkcOwnerRights = NKC_SID_1(3, 4);     /* stands for the owner */
static NKC_SID NkcCreatorOwner = NKC_SID_1(3, 0);    /* stands for a new object's owner */

/* One number for a SID: the authority, the number of sub-authorities,
 * and the low word of the last one. 0x05010012 is the system,
 * 0x05020220 administrators, 0x01010000 everyone, 0x0501000B
 * authenticated users, 0x05010007 anonymous, 0x05020221 users,
 * 0x10014000 the system integrity level. 0xFFFFFFFF: no SID. */
static ULONG NkcSidCode(PSID Sid)
{
    const NKC_SID *Known = (const NKC_SID *)Sid;
    const UCHAR *Last;
    ULONG Sub = 0;

    if (Sid == NULL) {
        return 0xFFFFFFFF;
    }
    if (Known->Count != 0) {
        Last = (const UCHAR *)Sid + 8 + 4 * (Known->Count - 1);
        Sub = Last[0] | ((ULONG)Last[1] << 8);
    }
    return ((ULONG)Known->Authority[5] << 24) | ((ULONG)Known->Count << 16) | Sub;
}

/* One entry of an access list. */
typedef struct _NKC_ACE {
    UCHAR Type;  /* ACCESS_ALLOWED_ACE_TYPE or ACCESS_DENIED_ACE_TYPE */
    UCHAR Flags; /* inheritance */
    ACCESS_MASK Mask;
    NKC_SID *Sid;
} NKC_ACE;

#define NKC_ALLOW ACCESS_ALLOWED_ACE_TYPE
#define NKC_DENY ACCESS_DENIED_ACE_TYPE

/* An access list of these entries in `Room`, exactly as long as they are. */
static PACL NkcAcl(PVOID Room, const NKC_ACE *Aces, ULONG Count)
{
    PACL Acl = (PACL)Room;
    PUCHAR At = (PUCHAR)(Acl + 1);
    ULONG i;

    for (i = 0; i < Count; i++) {
        PACE_HEADER Header = (PACE_HEADER)At;
        USHORT SidLength = (USHORT)(8 + 4 * Aces[i].Sid->Count);

        Header->AceType = Aces[i].Type;
        Header->AceFlags = Aces[i].Flags;
        Header->AceSize = (USHORT)(sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + SidLength);
        *(ACCESS_MASK *)(At + sizeof(ACE_HEADER)) = Aces[i].Mask;
        RtlCopyMemory(At + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK), Aces[i].Sid, SidLength);
        At += Header->AceSize;
    }
    Acl->AclRevision = ACL_REVISION;
    Acl->Sbz1 = 0;
    Acl->AclSize = (USHORT)(At - (PUCHAR)Room);
    Acl->AceCount = (USHORT)Count;
    Acl->Sbz2 = 0;
    return Acl;
}

/* How a descriptor's access list is given. */
#define NKC_NO_DACL (-1)   /* none: the "present" bit is clear */
#define NKC_NULL_DACL (-2) /* present, and a null pointer */

/* An absolute descriptor. `Count` entries, or one of the two above. */
static VOID NkcAbsolute(SECURITY_DESCRIPTOR *Sd, PVOID AclRoom, NKC_SID *Owner, NKC_SID *Group,
                        const NKC_ACE *Aces, LONG Count, USHORT Control)
{
    RtlZeroMemory(Sd, sizeof(*Sd));
    Sd->Revision = SECURITY_DESCRIPTOR_REVISION;
    Sd->Owner = Owner;
    Sd->Group = Group;
    Sd->Control = Control;
    if (Count != NKC_NO_DACL) {
        Sd->Control |= SE_DACL_PRESENT;
        Sd->Dacl = Count == NKC_NULL_DACL ? NULL : NkcAcl(AclRoom, Aces, (ULONG)Count);
    }
}

/* The entries of an access list: how many (and, above it, the list's
 * size), then each one's type, flags and size as one number, its mask
 * and its SID. 0xFFFFFFFF: no list. */
static VOID NkcDumpAcl(NKC_LOG *Log, PACL Acl)
{
    PUCHAR At;
    USHORT i;

    if (Acl == NULL) {
        NkcPut(Log, 0xFFFFFFFF);
        return;
    }
    NkcPut(Log, Acl->AceCount | ((ULONG)Acl->AclSize << 16));
    At = (PUCHAR)(Acl + 1);
    for (i = 0; i < Acl->AceCount && i < 16; i++) {
        PACE_HEADER Header = (PACE_HEADER)At;

        NkcPut(Log, Header->AceType | ((ULONG)Header->AceFlags << 8) |
                        ((ULONG)Header->AceSize << 16));
        NkcPut(Log, *(ACCESS_MASK *)(At + sizeof(ACE_HEADER)));
        NkcPut(Log, NkcSidCode(At + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK)));
        At += Header->AceSize;
    }
}

/* A self-relative descriptor, part by part: control bits; length; where
 * the owner, the group, the system list and the access list are; the
 * owner; the group; the access list (NkcDumpAcl). */
static VOID NkcDump(NKC_LOG *Log, PSECURITY_DESCRIPTOR Sd)
{
    PISECURITY_DESCRIPTOR_RELATIVE Relative = (PISECURITY_DESCRIPTOR_RELATIVE)Sd;
    PUCHAR Base = (PUCHAR)Sd;

    NkcPut(Log, Relative->Control);
    NkcPut(Log, RtlLengthSecurityDescriptor(Sd));
    NkcPut(Log, Relative->Owner);
    NkcPut(Log, Relative->Group);
    NkcPut(Log, Relative->Sacl);
    NkcPut(Log, Relative->Dacl);
    NkcPut(Log, NkcSidCode(Relative->Owner != 0 ? Base + Relative->Owner : NULL));
    NkcPut(Log, NkcSidCode(Relative->Group != 0 ? Base + Relative->Group : NULL));
    NkcDumpAcl(Log, Relative->Dacl != 0 ? (PACL)(Base + Relative->Dacl) : NULL);
}

/* What the generic rights mean for a file. */
static GENERIC_MAPPING NkcMapping = { 0x120089, 0x120116, 0x1200A0, 0x1F01FF };

/* Memory a list works in, from the pool: too much for a stack. */
typedef struct _NKC_ROOM {
    ULONG Acl[64];
    ULONG ParentAcl[64];
    ULONG Out[128];
    ULONG Aux[128]; /* SeCreateAccessState's AuxData */
    SECURITY_DESCRIPTOR Sd;
    SECURITY_DESCRIPTOR Parent;
    ACCESS_STATE State;
} NKC_ROOM;

/*
 * The access check.
 */

static const NKC_ACE NkcAllowRw[] = { { NKC_ALLOW, 0, 0x3, &NkcSystem } };
static const NKC_ACE NkcAllowR[] = { { NKC_ALLOW, 0, 0x1, &NkcSystem } };
static const NKC_ACE NkcAllowAll[] = { { NKC_ALLOW, 0, 0x1F01FF, &NkcSystem } };
static const NKC_ACE NkcDenyAll[] = { { NKC_DENY, 0, 0x1F01FF, &NkcSystem } };
static const NKC_ACE NkcDenyFirst[] = { { NKC_DENY, 0, 0x1, &NkcSystem },
                                        { NKC_ALLOW, 0, 0x3, &NkcSystem } };
static const NKC_ACE NkcDenyLast[] = { { NKC_ALLOW, 0, 0x3, &NkcSystem },
                                       { NKC_DENY, 0, 0x1, &NkcSystem } };
static const NKC_ACE NkcByGroups[] = { { NKC_ALLOW, 0, 0x1, &NkcWorld },
                                       { NKC_ALLOW, 0, 0x2, &NkcAdmins },
                                       { NKC_ALLOW, 0, 0x4, &NkcAuthenticated } };
static const NKC_ACE NkcDenyGroup[] = { { NKC_DENY, 0, 0x2, &NkcWorld },
                                        { NKC_ALLOW, 0, 0x3, &NkcSystem } };
static const NKC_ACE NkcStranger[] = { { NKC_ALLOW, 0, 0x1F01FF, &NkcAnonymous } };
static const NKC_ACE NkcDenyStranger[] = { { NKC_DENY, 0, 0x1, &NkcAnonymous },
                                           { NKC_ALLOW, 0, 0x1, &NkcSystem } };
static const NKC_ACE NkcOwnerReads[] = { { NKC_ALLOW, 0, READ_CONTROL, &NkcOwnerRights } };
static const NKC_ACE NkcOwnerOne[] = { { NKC_ALLOW, 0, 0x1, &NkcOwnerRights } };
static const NKC_ACE NkcGenericRead[] = { { NKC_ALLOW, 0, GENERIC_READ, &NkcSystem } };
static const NKC_ACE NkcGenericAll[] = { { NKC_ALLOW, 0, GENERIC_ALL, &NkcSystem } };
static const NKC_ACE NkcFileRead[] = { { NKC_ALLOW, 0, 0x120089, &NkcSystem } };
static const NKC_ACE NkcInheritOnly[] = { { NKC_ALLOW, INHERIT_ONLY_ACE, 0x1, &NkcSystem } };

typedef struct _NKC_CASE {
    NKC_SID *Owner;
    const NKC_ACE *Aces;
    LONG Count; /* or NKC_NO_DACL, NKC_NULL_DACL */
    ACCESS_MASK Desired;
    ACCESS_MASK Previously;
    KPROCESSOR_MODE Mode;
} NKC_CASE;

#define NKC_MAX MAXIMUM_ALLOWED
#define NKC_ASS ACCESS_SYSTEM_SECURITY
#define NKC_DENIED 0xC0000022 /* in the comments below: "denied" */

/* Each case logs three values: the status, the access granted, and 1
 * if SeAccessCheck returned TRUE, to which 0x100 times (1 + the number
 * of privileges) is added if it handed out a set of privileges used.
 * The comment of a case says them; "denied" is 0xC0000022, 0, 0. */
static const NKC_CASE NkcCases[] = {
    /* Kernel mode: nothing is looked at.
     * 0, 0x1F01FF, 1: all asked for, on a list that gives the subject
     * nothing.
     * 0, 0x1F01FF, 1: MAXIMUM_ALLOWED is what "generic all" maps to (a
     * guess: without the MAXIMUM_ALLOWED bit itself).
     * 0, 0x01000001, 1: ACCESS_SYSTEM_SECURITY with no privilege asked. */
    { &NkcAnonymous, NkcStranger, 1, 0x1F01FF, 0, KernelMode },
    { &NkcAnonymous, NkcStranger, 1, NKC_MAX, 0, KernelMode },
    { &NkcAnonymous, NkcStranger, 1, NKC_ASS | 0x1, 0, KernelMode },

    /* An entry for the user. 0, 1, 1: part of what it allows.
     * denied: more than it allows. */
    { &NkcAnonymous, NkcAllowRw, 1, 0x1, 0, UserMode },
    { &NkcAnonymous, NkcAllowRw, 1, 0x7, 0, UserMode },

    /* Deny 1, then allow 3. 0, 2, 1: the right not denied.
     * denied: both. 0, 2, 1: the most there is. */
    { &NkcAnonymous, NkcDenyFirst, 2, 0x2, 0, UserMode },
    { &NkcAnonymous, NkcDenyFirst, 2, 0x3, 0, UserMode },
    { &NkcAnonymous, NkcDenyFirst, 2, NKC_MAX, 0, UserMode },

    /* Allow 3, then deny 1: the order stored decides. 0, 3, 1: both
     * rights. 0, 3, 1: the most there is (a guess: the later denial
     * takes nothing from it). */
    { &NkcAnonymous, NkcDenyLast, 2, 0x3, 0, UserMode },
    { &NkcAnonymous, NkcDenyLast, 2, NKC_MAX, 0, UserMode },

    /* 0, 7, 1: one right from each of three groups. */
    { &NkcAnonymous, NkcByGroups, 3, 0x7, 0, UserMode },

    /* A denial for a group, then allowed to the user. denied: the right
     * denied. 0, 1, 1: the most there is. */
    { &NkcAnonymous, NkcDenyGroup, 2, 0x2, 0, UserMode },
    { &NkcAnonymous, NkcDenyGroup, 2, NKC_MAX, 0, UserMode },

    /* Entries for a SID the token does not have. denied, denied: one
     * that allows all gives nothing, and the most of nothing is a
     * refusal. 0, 1, 1: one that denies takes nothing. */
    { &NkcAnonymous, NkcStranger, 1, 0x1, 0, UserMode },
    { &NkcAnonymous, NkcStranger, 1, NKC_MAX, 0, UserMode },
    { &NkcAnonymous, NkcDenyStranger, 2, 0x1, 0, UserMode },

    /* No access list. 0, 1, 1: what is asked. 0, 0x1F01FF, 1: the most
     * is "generic all". 0, 0x1F11FF, 1: and what is asked beside it. */
    { &NkcAnonymous, NULL, NKC_NO_DACL, 0x1, 0, UserMode },
    { &NkcAnonymous, NULL, NKC_NO_DACL, NKC_MAX, 0, UserMode },
    { &NkcAnonymous, NULL, NKC_NO_DACL, NKC_MAX | 0x1000, 0, UserMode },

    /* An access list that is present and null is none. 0, 1, 1;
     * 0, 0x1F01FF, 1. */
    { &NkcAnonymous, NULL, NKC_NULL_DACL, 0x1, 0, UserMode },
    { &NkcAnonymous, NULL, NKC_NULL_DACL, NKC_MAX, 0, UserMode },

    /* An empty list, the owner someone else. denied three times: a
     * right, READ_CONTROL, the most there is. */
    { &NkcAnonymous, NkcAllowR, 0, 0x1, 0, UserMode },
    { &NkcAnonymous, NkcAllowR, 0, READ_CONTROL, 0, UserMode },
    { &NkcAnonymous, NkcAllowR, 0, NKC_MAX, 0, UserMode },

    /* An empty list, the owner the token's user: the owner may read
     * the descriptor and change the list, whatever the list says.
     * 0, 0x60000, 1. denied: but not delete. 0, 0x60000, 1: the most.
     * 0, 0x20000, 1: the owner a group of the token's. */
    { &NkcSystem, NkcAllowR, 0, READ_CONTROL | WRITE_DAC, 0, UserMode },
    { &NkcSystem, NkcAllowR, 0, DELETE, 0, UserMode },
    { &NkcSystem, NkcAllowR, 0, NKC_MAX, 0, UserMode },
    { &NkcAdmins, NkcAllowR, 0, READ_CONTROL, 0, UserMode },

    /* An entry for OWNER RIGHTS takes the place of what the owner has
     * unasked. Allowing READ_CONTROL: denied: WRITE_DAC. 0, 0x20000, 1:
     * READ_CONTROL. 0, 0x20000, 1: the most. */
    { &NkcSystem, NkcOwnerReads, 1, WRITE_DAC, 0, UserMode },
    { &NkcSystem, NkcOwnerReads, 1, READ_CONTROL, 0, UserMode },
    { &NkcSystem, NkcOwnerReads, 1, NKC_MAX, 0, UserMode },

    /* Allowing right 1: denied: to one who is not the owner. 0, 1, 1:
     * to the owner. denied: READ_CONTROL, which the entry replaced. */
    { &NkcAnonymous, NkcOwnerOne, 1, 0x1, 0, UserMode },
    { &NkcSystem, NkcOwnerOne, 1, 0x1, 0, UserMode },
    { &NkcSystem, NkcOwnerOne, 1, READ_CONTROL, 0, UserMode },

    /* 0, 0x20000, 1, a guess: an entry that denies the owner everything
     * comes after what the owner has unasked. */
    { &NkcSystem, NkcDenyAll, 1, READ_CONTROL, 0, UserMode },

    /* Generic rights. 0, 0x120089, 1: an entry's GENERIC_READ is what
     * it maps to. denied: and no more. 0, 0x1F01FF, 1: GENERIC_ALL.
     * 0, 0x120089, 1, a guess: GENERIC_READ asked for is mapped too
     * (the documentation wants it mapped by the caller). */
    { &NkcAnonymous, NkcGenericRead, 1, 0x120089, 0, UserMode },
    { &NkcAnonymous, NkcGenericRead, 1, 0x120089 | 0x2, 0, UserMode },
    { &NkcAnonymous, NkcGenericAll, 1, NKC_MAX, 0, UserMode },
    { &NkcAnonymous, NkcFileRead, 1, GENERIC_READ, 0, UserMode },

    /* denied: an entry that is only for inheriting gives nothing. */
    { &NkcAnonymous, NkcInheritOnly, 1, 0x1, 0, UserMode },

    /* Access granted before. 0, 0x101, 1: it comes back with what is
     * granted now. denied (and 0 granted): it does not survive a
     * refusal. Guesses: denied: nothing asked and nothing had;
     * 0, 0x100, 1: nothing asked, something had; 0, 0x100, 1: the most
     * of nothing, something had. */
    { &NkcAnonymous, NkcAllowR, 1, 0x1, 0x100, UserMode },
    { &NkcAnonymous, NkcAllowR, 1, 0x2, 0x100, UserMode },
    { &NkcAnonymous, NkcAllowR, 1, 0, 0, UserMode },
    { &NkcAnonymous, NkcAllowR, 1, 0, 0x100, UserMode },
    { &NkcAnonymous, NkcStranger, 1, NKC_MAX, 0x100, UserMode },

    /* Rights a privilege gives. The token has SeSecurityPrivilege and
     * SeTakeOwnershipPrivilege, both disabled. 0xC0000061
     * (STATUS_PRIVILEGE_NOT_HELD), 0, 0, twice: ACCESS_SYSTEM_SECURITY
     * is not the list's to give, alone or with the most there is.
     * denied: WRITE_OWNER with nothing in the list. 0, 0x80000, 1: the
     * list can give WRITE_OWNER. */
    { &NkcAnonymous, NkcAllowAll, 1, NKC_ASS, 0, UserMode },
    { &NkcAnonymous, NkcAllowAll, 1, NKC_MAX | NKC_ASS, 0, UserMode },
    { &NkcAnonymous, NkcAllowR, 0, WRITE_OWNER, 0, UserMode },
    { &NkcAnonymous, NkcAllowAll, 1, WRITE_OWNER, 0, UserMode },
};

/* One access check against the subject, which the caller has locked. */
static VOID NkcCheck(NKC_LOG *Log, NKC_ROOM *Room, PSECURITY_SUBJECT_CONTEXT Subject,
                     const NKC_CASE *Case)
{
    PPRIVILEGE_SET Privileges = NULL;
    ACCESS_MASK Granted = 0xAAAAAAAA;
    NTSTATUS Status = (NTSTATUS)0xAAAAAAAA;
    BOOLEAN Allowed;
    ULONG Flags;

    NkcAbsolute(&Room->Sd, Room->Acl, Case->Owner, &NkcSystem, Case->Aces, Case->Count, 0);
    Allowed = SeAccessCheck(&Room->Sd, Subject, TRUE, Case->Desired, Case->Previously,
                            &Privileges, &NkcMapping, Case->Mode, &Granted, &Status);
    Flags = Allowed ? 1 : 0;
    if (Privileges != NULL) {
        Flags |= 0x100 * (1 + Privileges->PrivilegeCount);
        SeFreePrivileges(Privileges);
    }
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, Granted);
    NkcPut(Log, Flags);
}

static VOID NkcAccess(NKC_LOG *Log, NKC_ROOM *Room)
{
    SECURITY_SUBJECT_CONTEXT Subject;
    PACCESS_TOKEN Primary;
    ULONG i;

    /* 1, 1, 0x4E4B: the subject of a system thread is its process's
     * token, with no client token; the level of impersonation, which
     * means something only with a client token, is left as the caller
     * had it.
     * 1, a guess: the process is named by its id. */
    Subject.ImpersonationLevel = (SECURITY_IMPERSONATION_LEVEL)0x4E4B;
    SeCaptureSubjectContext(&Subject);
    Primary = PsReferencePrimaryToken(PsInitialSystemProcess);
    NkcPut(Log, Subject.PrimaryToken == Primary ? 1 : 0);
    NkcPut(Log, Subject.ClientToken == NULL ? 1 : 0);
    NkcPut(Log, (ULONG)Subject.ImpersonationLevel);
    NkcPut(Log, Subject.ProcessAuditId == (PVOID)PsGetCurrentProcessId() ? 1 : 0);
    PsDereferencePrimaryToken(Primary);

    /* 0, 1: locking the subject disables normal kernel APCs. */
    NkcPut(Log, KeAreApcsDisabled() ? 1 : 0);
    SeLockSubjectContext(&Subject);
    NkcPut(Log, KeAreApcsDisabled() ? 1 : 0);

    for (i = 0; i < sizeof(NkcCases) / sizeof(NkcCases[0]); i++) {
        NkcCheck(Log, Room, &Subject, &NkcCases[i]);
    }

    /* 0, 0: unlocked, APCs are enabled again; still at PASSIVE_LEVEL. */
    SeUnlockSubjectContext(&Subject);
    NkcPut(Log, KeAreApcsDisabled() ? 1 : 0);
    NkcPut(Log, KeGetCurrentIrql());
    SeReleaseSubjectContext(&Subject);
}

/*
 * Privileges.
 */

/* A set of two privileges. */
typedef struct _NKC_TWO {
    PRIVILEGE_SET Set;
    LUID_AND_ATTRIBUTES Second;
} NKC_TWO;

/* The second follows the first as the next element of the set's array. */
C_ASSERT(FIELD_OFFSET(NKC_TWO, Second) ==
         FIELD_OFFSET(PRIVILEGE_SET, Privilege) + sizeof(LUID_AND_ATTRIBUTES));

static VOID NkcSetOf(NKC_TWO *Two, ULONG Count, ULONG Control, ULONG First, ULONG Second)
{
    RtlZeroMemory(Two, sizeof(*Two));
    Two->Set.PrivilegeCount = Count;
    Two->Set.Control = Control;
    Two->Set.Privilege[0].Luid.LowPart = First;
    Two->Second.Luid.LowPart = Second;
}

static VOID NkcPrivileges(NKC_LOG *Log)
{
    SECURITY_SUBJECT_CONTEXT Subject;
    NKC_TWO Two;
    LUID Luid;
    ULONG Low = 0, High = 0, i;

    /* Which privileges, by number, the token holds enabled, as two
     * masks: 0x60B1E890 (4, 7, 11, 13 to 16, 20, 21, 23, 29, 30) and
     * 0x1E (33 to 36). */
    Luid.HighPart = 0;
    for (i = 0; i < 64; i++) {
        Luid.LowPart = i;
        if (SeSinglePrivilegeCheck(Luid, UserMode)) {
            if (i < 32) {
                Low |= 1u << i;
            } else {
                High |= 1u << (i - 32);
            }
        }
    }
    NkcPut(Log, Low);
    NkcPut(Log, High);

    /* 1, 1: for kernel mode every privilege is held: one the token has
     * disabled (8, SeSecurityPrivilege) and one there is not (63). */
    Luid.LowPart = SE_SECURITY_PRIVILEGE;
    NkcPut(Log, SeSinglePrivilegeCheck(Luid, KernelMode));
    Luid.LowPart = 63;
    NkcPut(Log, SeSinglePrivilegeCheck(Luid, KernelMode));

    SeCaptureSubjectContext(&Subject);

    /* 1, 0x80000000: a set of one enabled privilege (7, SeTcbPrivilege)
     * is held, and the privilege is marked as used for access. */
    NkcSetOf(&Two, 1, PRIVILEGE_SET_ALL_NECESSARY, SE_TCB_PRIVILEGE, 0);
    NkcPut(Log, SePrivilegeCheck(&Two.Set, &Subject, UserMode));
    NkcPut(Log, Two.Set.Privilege[0].Attributes);

    /* 0: all of an enabled one and a disabled one (2,
     * SeCreateTokenPrivilege) are not held. Guesses: 0x80000000, 0: the
     * one found is marked all the same.
     * 1, 0x80000000, 0: any one of the two is. */
    NkcSetOf(&Two, 2, PRIVILEGE_SET_ALL_NECESSARY, SE_TCB_PRIVILEGE, SE_CREATE_TOKEN_PRIVILEGE);
    NkcPut(Log, SePrivilegeCheck(&Two.Set, &Subject, UserMode));
    NkcPut(Log, Two.Set.Privilege[0].Attributes);
    NkcPut(Log, Two.Second.Attributes);
    NkcSetOf(&Two, 2, 0, SE_TCB_PRIVILEGE, SE_CREATE_TOKEN_PRIVILEGE);
    NkcPut(Log, SePrivilegeCheck(&Two.Set, &Subject, UserMode));
    NkcPut(Log, Two.Set.Privilege[0].Attributes);
    NkcPut(Log, Two.Second.Attributes);

    /* 0, 0: a privilege there is not, for user mode. 1, 0: for kernel
     * mode it is held, and nothing is marked. */
    NkcSetOf(&Two, 1, PRIVILEGE_SET_ALL_NECESSARY, 63, 0);
    NkcPut(Log, SePrivilegeCheck(&Two.Set, &Subject, UserMode));
    NkcPut(Log, Two.Set.Privilege[0].Attributes);
    NkcPut(Log, SePrivilegeCheck(&Two.Set, &Subject, KernelMode));
    NkcPut(Log, Two.Set.Privilege[0].Attributes);

    /* Guesses: 1: all of no privileges are held; 0: any one of none is
     * not. */
    NkcSetOf(&Two, 0, PRIVILEGE_SET_ALL_NECESSARY, 0, 0);
    NkcPut(Log, SePrivilegeCheck(&Two.Set, &Subject, UserMode));
    NkcSetOf(&Two, 0, 0, 0, 0);
    NkcPut(Log, SePrivilegeCheck(&Two.Set, &Subject, UserMode));

    SeReleaseSubjectContext(&Subject);
}

/*
 * The access state of an open.
 */

static VOID NkcAccessState(NKC_LOG *Log, NKC_ROOM *Room)
{
    static UNICODE_STRING TypeName = RTL_CONSTANT_STRING(L"NkcSe");
    static UNICODE_STRING ObjectName = RTL_CONSTANT_STRING(L"\\Device\\NkcSe\\Object");
    PACCESS_STATE State = &Room->State;
    PACCESS_TOKEN Primary;
    NKC_TWO Two;
    BOOLEAN Generate;
    NTSTATUS Status;

    /* 0: an access state for an open that asks to read and to delete. */
    RtlZeroMemory(State, sizeof(*State));
    RtlZeroMemory(Room->Aux, sizeof(Room->Aux));
    Status = SeCreateAccessState(State, Room->Aux, GENERIC_READ | DELETE, &NkcMapping);
    NkcPut(Log, (ULONG)Status);
    if (!NT_SUCCESS(Status)) {
        return;
    }

    /* 0x130089: what is still to be granted is what was asked, mapped.
     * 0x130089, a guess: so is what was asked "originally".
     * 0, 0: nothing granted yet; no flags.
     * 0: not evaluated, no audit, none on close, no privileges
     * allocated (one byte each). */
    NkcPut(Log, State->RemainingDesiredAccess);
    NkcPut(Log, State->OriginalDesiredAccess);
    NkcPut(Log, State->PreviouslyGrantedAccess);
    NkcPut(Log, State->Flags);
    NkcPut(Log, State->SecurityEvaluated | ((ULONG)State->GenerateAudit << 8) |
                    ((ULONG)State->GenerateOnClose << 16) |
                    ((ULONG)State->PrivilegesAllocated << 24));

    /* 1, 1: the subject is captured in it: the process's token, no
     * client's. 1, 1: no descriptor; the auxiliary data is the room
     * the caller gave. 0, 0: no privileges, no names. 1, a guess: the
     * operation has an id. */
    Primary = PsReferencePrimaryToken(PsInitialSystemProcess);
    NkcPut(Log, State->SubjectSecurityContext.PrimaryToken == Primary ? 1 : 0);
    PsDereferencePrimaryToken(Primary);
    NkcPut(Log, State->SubjectSecurityContext.ClientToken == NULL ? 1 : 0);
    NkcPut(Log, State->SecurityDescriptor == NULL ? 1 : 0);
    NkcPut(Log, State->AuxData == (PVOID)Room->Aux ? 1 : 0);
    NkcPut(Log, State->Privileges.InitialPrivilegeSet.PrivilegeCount);
    NkcPut(Log, (ULONG)State->ObjectName.Length | State->ObjectTypeName.Length);
    NkcPut(Log, (State->OperationID.LowPart | (ULONG)State->OperationID.HighPart) != 0 ? 1 : 0);

    /* 0, 1, 7, 0: a privilege used is appended: the state's own set
     * holds it. 0, 3, 0: two more fit. 0, then guesses, 3 and 1: a
     * fourth does not; the set moves to the pool and the state's own
     * is left as it was. */
    NkcSetOf(&Two, 1, PRIVILEGE_SET_ALL_NECESSARY, SE_TCB_PRIVILEGE, 0);
    NkcPut(Log, (ULONG)SeAppendPrivileges(State, &Two.Set));
    NkcPut(Log, State->Privileges.InitialPrivilegeSet.PrivilegeCount);
    NkcPut(Log, State->Privileges.InitialPrivilegeSet.Privilege[0].Luid.LowPart);
    NkcPut(Log, State->PrivilegesAllocated);
    NkcSetOf(&Two, 2, PRIVILEGE_SET_ALL_NECESSARY, SE_CHANGE_NOTIFY_PRIVILEGE, SE_DEBUG_PRIVILEGE);
    NkcPut(Log, (ULONG)SeAppendPrivileges(State, &Two.Set));
    NkcPut(Log, State->Privileges.InitialPrivilegeSet.PrivilegeCount);
    NkcPut(Log, State->PrivilegesAllocated);
    NkcSetOf(&Two, 1, PRIVILEGE_SET_ALL_NECESSARY, SE_AUDIT_PRIVILEGE, 0);
    NkcPut(Log, (ULONG)SeAppendPrivileges(State, &Two.Set));
    NkcPut(Log, State->Privileges.InitialPrivilegeSet.PrivilegeCount);
    NkcPut(Log, State->PrivilegesAllocated);

    /* An open to audit, with auditing of object access off. 0xAA: for
     * kernel mode nothing is done, the caller's flag stays as it was.
     * 0, a guess: for user mode the flag is cleared. 0: and the state
     * does not ask for an audit on close. */
    NkcAbsolute(&Room->Sd, Room->Acl, &NkcSystem, &NkcSystem, NkcAllowAll, 1, 0);
    Generate = 0xAA;
    SeOpenObjectAuditAlarm(&TypeName, NULL, &ObjectName, &Room->Sd, State, FALSE, TRUE,
                           KernelMode, &Generate);
    NkcPut(Log, Generate);
    Generate = 0xAA;
    SeOpenObjectAuditAlarm(&TypeName, NULL, &ObjectName, &Room->Sd, State, FALSE, TRUE, UserMode,
                           &Generate);
    NkcPut(Log, Generate);
    NkcPut(Log, State->GenerateOnClose);
    SeDeleteAccessState(State);

    /* 0, 0x02000000: asked for the most there is, that is what remains
     * to be granted. */
    RtlZeroMemory(State, sizeof(*State));
    RtlZeroMemory(Room->Aux, sizeof(Room->Aux));
    Status = SeCreateAccessState(State, Room->Aux, MAXIMUM_ALLOWED, &NkcMapping);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, State->RemainingDesiredAccess);
        SeDeleteAccessState(State);
    }
}

/*
 * The descriptor of a new object.
 */

/* A parent's list: an entry for each way of being inherited. */
static const NKC_ACE NkcParentAces[] = {
    { NKC_ALLOW, OBJECT_INHERIT_ACE, 0x1, &NkcWorld },
    { NKC_ALLOW, CONTAINER_INHERIT_ACE, 0x2, &NkcAdmins },
    { NKC_ALLOW, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE, GENERIC_EXECUTE,
      &NkcSystem },
    { NKC_ALLOW, CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE, 0x8, &NkcAuthenticated },
    { NKC_ALLOW, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, GENERIC_ALL, &NkcCreatorOwner },
    { NKC_ALLOW, 0, 0x10, &NkcUsers },
    { NKC_DENY, OBJECT_INHERIT_ACE, 0x20, &NkcAnonymous },
};
/* A parent's list with nothing to inherit. */
static const NKC_ACE NkcPlainParent[] = { { NKC_ALLOW, 0, 0x10, &NkcUsers } };
/* A list the creator supplies. */
static const NKC_ACE NkcSupplied[] = { { NKC_ALLOW, 0, GENERIC_READ, &NkcWorld },
                                       { NKC_ALLOW, 0, GENERIC_ALL, &NkcCreatorOwner } };

/* Assign: the status, then, if there is a descriptor, its dump; it is
 * deassigned again. */
static VOID NkcAssign(NKC_LOG *Log, PSECURITY_DESCRIPTOR Parent, PSECURITY_DESCRIPTOR Supplied,
                      BOOLEAN IsDirectory)
{
    SECURITY_SUBJECT_CONTEXT Subject;
    PSECURITY_DESCRIPTOR New = NULL;
    NTSTATUS Status;

    SeCaptureSubjectContext(&Subject);
    Status = SeAssignSecurity(Parent, Supplied, &New, IsDirectory, &Subject, &NkcMapping,
                              PagedPool);
    SeReleaseSubjectContext(&Subject);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status) && New != NULL) {
        NkcDump(Log, New);
        SeDeassignSecurity(&New);
    }
}

static VOID NkcAssigns(NKC_LOG *Log, NKC_ROOM *Room)
{
    PSECURITY_DESCRIPTOR Parent = &Room->Parent;
    PSECURITY_DESCRIPTOR Supplied = &Room->Sd;
#define NKC_PARENT(Aces)                                                                          \
    NkcAbsolute(&Room->Parent, Room->ParentAcl, &NkcUsers, &NkcUsers, Aces,                       \
                (LONG)(sizeof(Aces) / sizeof(Aces[0])), 0)

    /* Neither a parent nor a descriptor supplied: all from the token.
     * 0; control 0x8004 (self-relative, an access list); the owner
     * 0x05020220 (administrators, the token's owner for new objects),
     * the group 0x05010012 (the system, its primary group); the token's
     * default list, two entries: the system 0x1F01FF and administrators
     * 0x1200A9, their generic rights mapped. */
    NkcAssign(Log, NULL, NULL, FALSE);

    /* A descriptor supplied, no parent: its owner (the system), its
     * group (administrators), its list: everyone 0x120089, and the
     * creator-owner entry now for the owner, the system, 0x1F01FF. */
    NkcAbsolute(&Room->Sd, Room->Acl, &NkcSystem, &NkcAdmins, NkcSupplied, 2, 0);
    NkcAssign(Log, NULL, Supplied, FALSE);

    /* A parent, for an object that is not a directory: the entries
     * marked for objects, with no flags left: everyone 1; the system
     * 0x1200A0 (the entry that was only for inheriting takes effect);
     * the creator-owner entry for the new owner, administrators,
     * 0x1F01FF; the denial for anonymous 0x20. Owner and group from the
     * token. */
    NKC_PARENT(NkcParentAces);
    NkcAssign(Log, Parent, NULL, FALSE);

    /* The same parent, for a directory: entries marked for containers
     * take effect and those marked to go further stay inheritable;
     * those for objects only are kept, for inheriting only. Which
     * entries, in which order, with which flags, is what the dump is
     * for. */
    NkcAssign(Log, Parent, NULL, TRUE);

    /* A parent and a supplied list: the supplied list. */
    NkcAbsolute(&Room->Sd, Room->Acl, NULL, NULL, NkcSupplied, 2, 0);
    NkcAssign(Log, Parent, Supplied, FALSE);

    /* A parent and a supplied list marked defaulted: what is inherited
     * comes before a default. */
    NkcAbsolute(&Room->Sd, Room->Acl, NULL, NULL, NkcSupplied, 2, SE_DACL_DEFAULTED);
    NkcAssign(Log, Parent, Supplied, FALSE);

    /* A parent with nothing to inherit: the token's default list. */
    NKC_PARENT(NkcPlainParent);
    NkcAssign(Log, Parent, NULL, FALSE);

    /* Supplied: an owner the token could not be (anonymous). 0, a
     * guess: assigned all the same, for a thread whose previous mode is
     * kernel mode. */
    NkcAbsolute(&Room->Sd, Room->Acl, &NkcAnonymous, &NkcAnonymous, NULL, NKC_NO_DACL, 0);
    NkcAssign(Log, NULL, Supplied, FALSE);

    /* Supplied: a list that is present and null. The object has a null
     * list: control 0x8004 and no list anywhere. */
    NkcAbsolute(&Room->Sd, Room->Acl, NULL, NULL, NULL, NKC_NULL_DACL, 0);
    NkcAssign(Log, NULL, Supplied, FALSE);
#undef NKC_PARENT
}

/*
 * Reading and changing a descriptor's parts.
 */

/* Change the object's descriptor: the status; 1 if the object has
 * another descriptor now; and, if it has, that one's dump. The one it
 * had is freed. */
static VOID NkcSet(NKC_LOG *Log, PSECURITY_DESCRIPTOR *Object, SECURITY_INFORMATION Information,
                   PSECURITY_DESCRIPTOR Modification)
{
    PSECURITY_DESCRIPTOR Old = *Object;
    NTSTATUS Status;

    Status = SeSetSecurityDescriptorInfo(NULL, &Information, Modification, Object, PagedPool,
                                         &NkcMapping);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, *Object != Old ? 1 : 0);
    if (NT_SUCCESS(Status) && *Object != Old && *Object != NULL) {
        NkcDump(Log, *Object);
        SeDeassignSecurity(&Old);
    } else {
        *Object = Old;
    }
}

static VOID NkcDescriptors(NKC_LOG *Log, NKC_ROOM *Room)
{
    static const SECURITY_INFORMATION Parts[] = {
        OWNER_SECURITY_INFORMATION,
        GROUP_SECURITY_INFORMATION,
        DACL_SECURITY_INFORMATION,
        SACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        0,
    };
    static const NKC_ACE Write[] = { { NKC_ALLOW, 0, GENERIC_WRITE, &NkcWorld } };
    PISECURITY_DESCRIPTOR_RELATIVE Out = (PISECURITY_DESCRIPTOR_RELATIVE)Room->Out;
    SECURITY_SUBJECT_CONTEXT Subject;
    PSECURITY_DESCRIPTOR Object = NULL, None = NULL;
    SECURITY_INFORMATION Information;
    ULONG Length, i;
    NTSTATUS Status;

    /* 0: the object: owner the system, group administrators, a list of
     * two entries. */
    NkcAbsolute(&Room->Sd, Room->Acl, &NkcSystem, &NkcAdmins, NkcSupplied, 2, 0);
    SeCaptureSubjectContext(&Subject);
    Status = SeAssignSecurity(NULL, &Room->Sd, &Object, FALSE, &Subject, &NkcMapping, PagedPool);
    SeReleaseSubjectContext(&Subject);
    NkcPut(Log, (ULONG)Status);
    if (!NT_SUCCESS(Status) || Object == NULL) {
        return;
    }

    /* For the owner, the group, the access list, the system list, the
     * first three together, and nothing: 0xC0000023 and the length
     * needed, when there is no room; then 0, the length again, and the
     * descriptor made: control bits and where owner, group, system list
     * and access list are. A part not asked for, or not there, is left
     * out: its offset is 0. */
    for (i = 0; i < sizeof(Parts) / sizeof(Parts[0]); i++) {
        Information = Parts[i];
        Length = 0;
        NkcPut(Log, (ULONG)SeQuerySecurityDescriptorInfo(&Information, Out, &Length, &Object));
        NkcPut(Log, Length);
        RtlZeroMemory(Room->Out, sizeof(Room->Out));
        Length = sizeof(Room->Out);
        Status = SeQuerySecurityDescriptorInfo(&Information, Out, &Length, &Object);
        NkcPut(Log, (ULONG)Status);
        NkcPut(Log, Length);
        NkcPut(Log, Out->Control);
        NkcPut(Log, Out->Owner);
        NkcPut(Log, Out->Group);
        NkcPut(Log, Out->Sacl);
        NkcPut(Log, Out->Dacl);
    }

    /* 0, 20, 0x8000: an object with no descriptor gives an empty one. */
    Information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    RtlZeroMemory(Room->Out, sizeof(Room->Out));
    Length = sizeof(Room->Out);
    NkcPut(Log, (ULONG)SeQuerySecurityDescriptorInfo(&Information, Out, &Length, &None));
    NkcPut(Log, Length);
    NkcPut(Log, Out->Control);

    /* A new access list. 0, 1: the object has a new descriptor: owner
     * and group as before, the list one entry, everyone 0x120116: its
     * generic right mapped (a guess). */
    NkcAbsolute(&Room->Sd, Room->Acl, NULL, NULL, Write, 1, 0);
    NkcSet(Log, &Object, DACL_SECURITY_INFORMATION, &Room->Sd);

    /* The owner asked to be set, and none given. 0xC000005A
     * (STATUS_INVALID_OWNER), 0, a guess. */
    NkcSet(Log, &Object, OWNER_SECURITY_INFORMATION, &Room->Sd);

    /* A new owner the token may be: administrators. 0, 1 and the dump.
     * Then one it may not be, anonymous: 0xC000005A, 0, a guess. */
    NkcAbsolute(&Room->Sd, Room->Acl, &NkcAdmins, NULL, NULL, NKC_NO_DACL, 0);
    NkcSet(Log, &Object, OWNER_SECURITY_INFORMATION, &Room->Sd);
    NkcAbsolute(&Room->Sd, Room->Acl, &NkcAnonymous, NULL, NULL, NKC_NO_DACL, 0);
    NkcSet(Log, &Object, OWNER_SECURITY_INFORMATION, &Room->Sd);

    /* The group and the access list asked to be set, and neither given.
     * Guesses: 0, 1 each time, and the object is left without the
     * part. */
    NkcSet(Log, &Object, GROUP_SECURITY_INFORMATION, &Room->Sd);
    NkcSet(Log, &Object, DACL_SECURITY_INFORMATION, &Room->Sd);

    /* 0: the object's descriptor is given back. */
    NkcPut(Log, (ULONG)SeDeassignSecurity(&Object));
}

static VOID NkcSystemFacts(NKC_LOG *Log)
{
    NKC_ROOM *Room;

    Room = (NKC_ROOM *)ExAllocatePoolWithTag(PagedPool, sizeof(*Room), NKC_TAG);
    if (Room == NULL) {
        return;
    }
    NkcAccess(Log, Room);
    NkcPrivileges(Log);
    NkcAccessState(Log, Room);
    NkcAssigns(Log, Room);
    NkcDescriptors(Log, Room);
    ExFreePoolWithTag(Room, NKC_TAG);

    /* 0: at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}

/*
 * List 1: tokens and impersonation.
 */

/* What SeQueryInformationToken handed out is freed with ExFreePool. */
static VOID NkcFree(PVOID Block)
{
    if (Block != NULL) {
        ExFreePoolWithTag(Block, 0);
    }
}

/* A token in three values: its type, its user, and its impersonation
 * level (or the status that refuses to tell it). */
static VOID NkcTokenBrief(NKC_LOG *Log, PACCESS_TOKEN Token)
{
    PVOID Block = NULL;
    NTSTATUS Status;

    NkcPut(Log, (ULONG)SeTokenType(Token));
    Status = SeQueryInformationToken(Token, TokenUser, &Block);
    NkcPut(Log, NT_SUCCESS(Status) ? NkcSidCode(((PTOKEN_USER)Block)->User.Sid) : (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcFree(Block);
    }
    Block = NULL;
    Status = SeQueryInformationToken(Token, TokenImpersonationLevel, &Block);
    NkcPut(Log, NT_SUCCESS(Status) ? (ULONG) * (SECURITY_IMPERSONATION_LEVEL *)Block
                                   : (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcFree(Block);
    }
}

/* The System process's token, class by class, as the kernel routine
 * tells it. */
static VOID NkcSystemToken(NKC_LOG *Log, PACCESS_TOKEN Token)
{
    PVOID Block;
    NTSTATUS Status;
    ULONG i, Count;

    /* 1, 0x05010012, 0xC0000003: a primary token; its user is the
     * system; a primary token has no impersonation level to tell. */
    NkcTokenBrief(Log, Token);

    /* 0, 0: the user's attributes. */
    Block = NULL;
    Status = SeQueryInformationToken(Token, TokenUser, &Block);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, ((PTOKEN_USER)Block)->User.Attributes);
        NkcFree(Block);
    }

    /* 0, 4, then each group and its attributes: administrators 0xE
     * (enabled, by default, an owner), everyone 7 and authenticated
     * users 7 (mandatory as well), the system integrity level 0x60. */
    Block = NULL;
    Status = SeQueryInformationToken(Token, TokenGroups, &Block);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Block;

        Count = Groups->GroupCount;
        NkcPut(Log, Count);
        for (i = 0; i < Count && i < 16; i++) {
            NkcPut(Log, NkcSidCode(Groups->Groups[i].Sid));
            NkcPut(Log, Groups->Groups[i].Attributes);
        }
        NkcFree(Block);
    }

    /* 0, the number of privileges, then each one's number and
     * attributes (3: enabled, and by default; 0: disabled), in the
     * order the token gives them. */
    Block = NULL;
    Status = SeQueryInformationToken(Token, TokenPrivileges, &Block);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Block;

        Count = Privileges->PrivilegeCount;
        NkcPut(Log, Count);
        for (i = 0; i < Count && i < 64; i++) {
            NkcPut(Log, Privileges->Privileges[i].Luid.LowPart);
            NkcPut(Log, Privileges->Privileges[i].Attributes);
        }
        NkcFree(Block);
    }

    /* 0, 0x05020220: new objects are owned by administrators.
     * 0, 0x05010012: their group is the system. */
    Block = NULL;
    Status = SeQueryInformationToken(Token, TokenOwner, &Block);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, NkcSidCode(((PTOKEN_OWNER)Block)->Owner));
        NkcFree(Block);
    }
    Block = NULL;
    Status = SeQueryInformationToken(Token, TokenPrimaryGroup, &Block);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, NkcSidCode(((PTOKEN_PRIMARY_GROUP)Block)->PrimaryGroup));
        NkcFree(Block);
    }

    /* 0, and the list new objects get by default: two entries, the
     * system GENERIC_ALL, administrators 0xA0020000. */
    Block = NULL;
    Status = SeQueryInformationToken(Token, TokenDefaultDacl, &Block);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcDumpAcl(Log, ((PTOKEN_DEFAULT_DACL)Block)->DefaultDacl);
        NkcFree(Block);
    }

    /* 0, 1: the type, in a block of its own. */
    Block = NULL;
    Status = SeQueryInformationToken(Token, TokenType, &Block);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, (ULONG) * (TOKEN_TYPE *)Block);
        NkcFree(Block);
    }

    /* 0; the logon session 0x3E7, 0 (the system's); type 1, level 0;
     * the numbers of groups and of privileges; the two halves of the
     * time it expires; dynamic memory charged and available. */
    Block = NULL;
    Status = SeQueryInformationToken(Token, TokenStatistics, &Block);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        PTOKEN_STATISTICS Statistics = (PTOKEN_STATISTICS)Block;

        NkcPut(Log, Statistics->AuthenticationId.LowPart);
        NkcPut(Log, (ULONG)Statistics->AuthenticationId.HighPart);
        NkcPut(Log, (ULONG)Statistics->TokenType);
        NkcPut(Log, (ULONG)Statistics->ImpersonationLevel);
        NkcPut(Log, Statistics->GroupCount);
        NkcPut(Log, Statistics->PrivilegeCount);
        NkcPut(Log, Statistics->ExpirationTime.LowPart);
        NkcPut(Log, (ULONG)Statistics->ExpirationTime.HighPart);
        NkcPut(Log, Statistics->DynamicCharged);
        NkcPut(Log, Statistics->DynamicAvailable);
        NkcFree(Block);
    }

    /* Three classes answered with a number where the block's address
     * would go, four bytes of it. 0, 0: session 0. 0, 0x4000: the
     * system integrity level. 0, 0: not an app container. */
    Block = NULL;
    NkcPut(Log, (ULONG)SeQueryInformationToken(Token, TokenSessionId, &Block));
    NkcPut(Log, (ULONG)(ULONG_PTR)Block);
    Block = NULL;
    NkcPut(Log, (ULONG)SeQueryInformationToken(Token, TokenIntegrityLevel, &Block));
    NkcPut(Log, (ULONG)(ULONG_PTR)Block);
    Block = NULL;
    NkcPut(Log, (ULONG)SeQueryInformationToken(Token, TokenIsAppContainer, &Block));
    NkcPut(Log, (ULONG)(ULONG_PTR)Block);

    /* 0xC0000003: a class there is not. */
    Block = NULL;
    NkcPut(Log, (ULONG)SeQueryInformationToken(Token, (TOKEN_INFORMATION_CLASS)0x7F, &Block));
}

/* Ask a token handle for a class: the status and the length returned. */
static NTSTATUS NkcAsk(NKC_LOG *Log, HANDLE Token, TOKEN_INFORMATION_CLASS Class, PVOID Out,
                       ULONG Room)
{
    ULONG Length = 0xAAAAAAAA;
    NTSTATUS Status;

    Status = ZwQueryInformationToken(Token, Class, Out, Room, &Length);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, Length);
    return Status;
}

/* A token handle in two values: its type and its impersonation level
 * (or the status that refuses to tell it). */
static VOID NkcHandleBrief(NKC_LOG *Log, HANDLE Token)
{
    ULONG Value = 0xAAAAAAAA, Length;
    NTSTATUS Status;

    Status = ZwQueryInformationToken(Token, TokenType, &Value, sizeof(Value), &Length);
    NkcPut(Log, NT_SUCCESS(Status) ? Value : (ULONG)Status);
    Value = 0xAAAAAAAA;
    Status = ZwQueryInformationToken(Token, TokenImpersonationLevel, &Value, sizeof(Value),
                                     &Length);
    NkcPut(Log, NT_SUCCESS(Status) ? Value : (ULONG)Status);
}

static VOID NkcTokenHandles(NKC_LOG *Log, NKC_ROOM *Room)
{
    SECURITY_QUALITY_OF_SERVICE Qos;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Primary = NULL, Copy, None;
    PULONG Out = Room->Out;
    ULONG Level;
    NTSTATUS Status;

    /* 0xC000007C (STATUS_NO_TOKEN), 1: a thread that impersonates
     * nobody has no token of its own to open; the caller's handle is
     * left as it was (a guess). */
    None = (HANDLE)(ULONG_PTR)1;
    NkcPut(Log, (ULONG)ZwOpenThreadTokenEx(NtCurrentThread(), TOKEN_QUERY, TRUE,
                                           OBJ_KERNEL_HANDLE, &None));
    NkcPut(Log, None == (HANDLE)(ULONG_PTR)1 ? 1 : 0);

    /* 0: the process's token, opened. */
    Status = ZwOpenProcessTokenEx(NtCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE,
                                  OBJ_KERNEL_HANDLE, &Primary);
    NkcPut(Log, (ULONG)Status);
    if (!NT_SUCCESS(Status)) {
        return;
    }

    /* The user. 0xC0000023, 28: no room, and the length needed. 0, 28,
     * 0x05010012, 0: the system, no attributes. */
    NkcAsk(Log, Primary, TokenUser, NULL, 0);
    RtlZeroMemory(Room->Out, sizeof(Room->Out));
    if (NT_SUCCESS(NkcAsk(Log, Primary, TokenUser, Out, sizeof(Room->Out)))) {
        NkcPut(Log, NkcSidCode(((PTOKEN_USER)Out)->User.Sid));
        NkcPut(Log, ((PTOKEN_USER)Out)->User.Attributes);
    }

    /* The type. 0xC0000023, 4, a guess: two bytes are too few, and the
     * status is the one for a short buffer. 0, 4, 1: primary. */
    NkcAsk(Log, Primary, TokenType, Out, 2);
    Out[0] = 0xAAAAAAAA;
    NkcAsk(Log, Primary, TokenType, Out, sizeof(ULONG));
    NkcPut(Log, Out[0]);

    /* 0xC0000003: a primary token has no impersonation level; the
     * length is left as it was (a guess). */
    NkcAsk(Log, Primary, TokenImpersonationLevel, Out, sizeof(ULONG));

    /* 0, 4, 0: session 0. 0, 4, 0: not an app container. */
    Out[0] = 0xAAAAAAAA;
    NkcAsk(Log, Primary, TokenSessionId, Out, sizeof(ULONG));
    NkcPut(Log, Out[0]);
    Out[0] = 0xAAAAAAAA;
    NkcAsk(Log, Primary, TokenIsAppContainer, Out, sizeof(ULONG));
    NkcPut(Log, Out[0]);

    /* 0, 28, 0x10014000, 0x60: the integrity level, as a label: the
     * SID of the system level and its attributes. */
    RtlZeroMemory(Room->Out, sizeof(Room->Out));
    if (NT_SUCCESS(NkcAsk(Log, Primary, TokenIntegrityLevel, Out, sizeof(Room->Out)))) {
        NkcPut(Log, NkcSidCode(((PTOKEN_MANDATORY_LABEL)Out)->Label.Sid));
        NkcPut(Log, ((PTOKEN_MANDATORY_LABEL)Out)->Label.Attributes);
    }

    /* 0, 56, 0x3E7, 1, 0: the statistics: the logon session, the type,
     * the level. */
    RtlZeroMemory(Room->Out, sizeof(Room->Out));
    if (NT_SUCCESS(NkcAsk(Log, Primary, TokenStatistics, Out, sizeof(Room->Out)))) {
        PTOKEN_STATISTICS Statistics = (PTOKEN_STATISTICS)Out;

        NkcPut(Log, Statistics->AuthenticationId.LowPart);
        NkcPut(Log, (ULONG)Statistics->TokenType);
        NkcPut(Log, (ULONG)Statistics->ImpersonationLevel);
    }

    /* 0xC0000003: a class there is not. */
    NkcAsk(Log, Primary, (TOKEN_INFORMATION_CLASS)0x7F, Out, sizeof(Room->Out));

    /* A copy made an impersonation token, at each level from anonymous
     * to delegation: 0, 2, and the level asked: 0, 1, 2, 3. */
    for (Level = SecurityAnonymous; Level <= SecurityDelegation; Level++) {
        Qos.Length = sizeof(Qos);
        Qos.ImpersonationLevel = (SECURITY_IMPERSONATION_LEVEL)Level;
        Qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
        Qos.EffectiveOnly = FALSE;
        InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        Attributes.SecurityQualityOfService = &Qos;
        Copy = NULL;
        Status = ZwDuplicateToken(Primary, TOKEN_QUERY, &Attributes, FALSE, TokenImpersonation,
                                  &Copy);
        NkcPut(Log, (ULONG)Status);
        if (NT_SUCCESS(Status)) {
            NkcHandleBrief(Log, Copy);
            ZwClose(Copy);
        }
    }

    /* The same with no level said. 0, 2, and a guess, 0: anonymous. */
    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Copy = NULL;
    Status = ZwDuplicateToken(Primary, TOKEN_QUERY, &Attributes, FALSE, TokenImpersonation,
                              &Copy);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcHandleBrief(Log, Copy);
        ZwClose(Copy);
    }

    /* A copy that is a primary token again: 0, 1, 0xC0000003. */
    Copy = NULL;
    Status = ZwDuplicateToken(Primary, TOKEN_QUERY, &Attributes, FALSE, TokenPrimary, &Copy);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcHandleBrief(Log, Copy);
        ZwClose(Copy);
    }

    /* 0: closed. */
    NkcPut(Log, (ULONG)ZwClose(Primary));
}

/*
 * Impersonation, on a thread that exists for it: whatever it has taken
 * on ends with it.
 */

typedef struct _NKC_ACTOR {
    NKC_LOG *Log;
    NKC_ROOM *Room;
    PACCESS_TOKEN Primary;
} NKC_ACTOR;

/* What the current thread impersonates: 1 if it has a token, then, if
 * so, 1 if it is `Expected` (when that is not NULL), the level, the
 * two flags as one number (copy-on-open, and effective-only times
 * 0x100), and the token in brief. */
static VOID NkcWearing(NKC_LOG *Log, PACCESS_TOKEN Expected)
{
    SECURITY_IMPERSONATION_LEVEL Level = (SECURITY_IMPERSONATION_LEVEL)0xAA;
    BOOLEAN CopyOnOpen = 0xAA, EffectiveOnly = 0xAA;
    PACCESS_TOKEN Token;

    Token = PsReferenceImpersonationToken(PsGetCurrentThread(), &CopyOnOpen, &EffectiveOnly,
                                          &Level);
    NkcPut(Log, Token != NULL ? 1 : 0);
    if (Token == NULL) {
        return;
    }
    if (Expected != NULL) {
        NkcPut(Log, Token == Expected ? 1 : 0);
    }
    NkcPut(Log, (ULONG)Level);
    NkcPut(Log, CopyOnOpen | ((ULONG)EffectiveOnly << 8));
    NkcTokenBrief(Log, Token);
    PsDereferenceImpersonationToken(Token);
}

/* Stop impersonating, the way a driver without PsRevertToSelf does:
 * the thread's impersonation token set to no token. */
static NTSTATUS NkcRevert(VOID)
{
    HANDLE None = NULL;

    return ZwSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &None,
                                  sizeof(None));
}

/* One access check as the current thread's subject, client token and
 * all: the three values of NkcCheck. */
static VOID NkcCheckNow(NKC_LOG *Log, NKC_ROOM *Room, const NKC_CASE *Case)
{
    SECURITY_SUBJECT_CONTEXT Subject;

    SeCaptureSubjectContext(&Subject);
    SeLockSubjectContext(&Subject);
    NkcCheck(Log, Room, &Subject, Case);
    SeUnlockSubjectContext(&Subject);
    SeReleaseSubjectContext(&Subject);
}

static const NKC_ACE NkcForAnonymous[] = { { NKC_ALLOW, 0, 0x1, &NkcAnonymous } };
/* Right 1 asked of a list that allows it to the system; to anonymous. */
static const NKC_CASE NkcAsSystem = { &NkcUsers, NkcAllowR, 1, 0x1, 0, UserMode };
static const NKC_CASE NkcAsAnonymous = { &NkcUsers, NkcForAnonymous, 1, 0x1, 0, UserMode };

static KSTART_ROUTINE NkcActor;

static VOID NkcActor(PVOID Context)
{
    NKC_ACTOR *Actor = (NKC_ACTOR *)Context;
    NKC_LOG *Log = Actor->Log;
    PETHREAD Thread = PsGetCurrentThread();
    SECURITY_QUALITY_OF_SERVICE Qos;
    SECURITY_CLIENT_CONTEXT Client;
    SECURITY_SUBJECT_CONTEXT Subject;
    HANDLE Handle;
    NTSTATUS Status;

    /* 0: a new thread impersonates nobody. */
    NkcWearing(Log, NULL);

    /* A client context of this thread itself, tracked dynamically: 0;
     * then guesses: 1: it uses the thread's own token directly; 1, 1:
     * a primary token, the process's; 2, 0, 0: the level asked, not
     * remote, not effective-only. */
    Qos.Length = sizeof(Qos);
    Qos.ImpersonationLevel = SecurityImpersonation;
    Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    Qos.EffectiveOnly = FALSE;
    RtlZeroMemory(&Client, sizeof(Client));
    Status = SeCreateClientSecurity(Thread, &Qos, FALSE, &Client);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, Client.DirectlyAccessClientToken);
        NkcPut(Log, (ULONG)SeTokenType(Client.ClientToken));
        NkcPut(Log, Client.ClientToken == Actor->Primary ? 1 : 0);
        NkcPut(Log, (ULONG)Client.SecurityQos.ImpersonationLevel);
        NkcPut(Log, Client.ServerIsRemote);
        NkcPut(Log, Client.DirectAccessEffectiveOnly);
        SeDeleteClientSecurity(&Client);
    }

    /* The same tracked statically: 0; 0: the context has a token of its
     * own; 2, 0: an impersonation token, a copy; 2, 0, 0. */
    Qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    RtlZeroMemory(&Client, sizeof(Client));
    Status = SeCreateClientSecurity(Thread, &Qos, FALSE, &Client);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, Client.DirectlyAccessClientToken);
        NkcPut(Log, (ULONG)SeTokenType(Client.ClientToken));
        NkcPut(Log, Client.ClientToken == Actor->Primary ? 1 : 0);
        NkcPut(Log, (ULONG)Client.SecurityQos.ImpersonationLevel);
        NkcPut(Log, Client.ServerIsRemote);
        NkcPut(Log, Client.DirectAccessEffectiveOnly);

        /* 0: the thread impersonates that client. 1, 1, 2: it has a
         * token, the context's, at the impersonation level; the two
         * flags, a guess, 1 (copy-on-open, not effective-only); in
         * brief 2, 0x05010012, 2: an impersonation token of the
         * system's, level 2. */
        Status = SeImpersonateClientEx(&Client, NULL);
        NkcPut(Log, (ULONG)Status);
        if (NT_SUCCESS(Status)) {
            NkcWearing(Log, Client.ClientToken);

            /* 1, 1, 2: the thread's subject now has a client token,
             * the same one, beside the process's. */
            SeCaptureSubjectContext(&Subject);
            NkcPut(Log, Subject.ClientToken == Client.ClientToken ? 1 : 0);
            NkcPut(Log, Subject.PrimaryToken == Actor->Primary ? 1 : 0);
            NkcPut(Log, (ULONG)Subject.ImpersonationLevel);
            SeReleaseSubjectContext(&Subject);

            /* 0; 2, 2: the thread's token can be opened now: an
             * impersonation token of level 2. */
            Handle = NULL;
            Status = ZwOpenThreadTokenEx(NtCurrentThread(), TOKEN_QUERY, TRUE, OBJ_KERNEL_HANDLE,
                                         &Handle);
            NkcPut(Log, (ULONG)Status);
            if (NT_SUCCESS(Status)) {
                NkcHandleBrief(Log, Handle);
                ZwClose(Handle);
            }

            /* 0, 1, 1: as the system still, the list for the system
             * allows. */
            NkcCheckNow(Log, Actor->Room, &NkcAsSystem);

            /* 0, 0: put off; the thread impersonates nobody. */
            NkcPut(Log, (ULONG)NkcRevert());
            NkcWearing(Log, NULL);
        }
        SeDeleteClientSecurity(&Client);
    }

    /* A client at the identification level: 0, 0: made and taken on.
     * 1, 1, 1: the thread has a token, the context's, at level 1; the
     * flags as above; in brief 2, 0x05010012, 1.
     * 0xC00000A5 (STATUS_BAD_IMPERSONATION_LEVEL), 0, 0, a guess: a
     * token that only identifies cannot be checked for access. 0. */
    Qos.ImpersonationLevel = SecurityIdentification;
    RtlZeroMemory(&Client, sizeof(Client));
    Status = SeCreateClientSecurity(Thread, &Qos, FALSE, &Client);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        Status = SeImpersonateClientEx(&Client, NULL);
        NkcPut(Log, (ULONG)Status);
        if (NT_SUCCESS(Status)) {
            NkcWearing(Log, Client.ClientToken);
            NkcCheckNow(Log, Actor->Room, &NkcAsSystem);
            NkcPut(Log, (ULONG)NkcRevert());
        }
        SeDeleteClientSecurity(&Client);
    }

    /* 0: the thread takes on the anonymous token. 1; guesses: level 2,
     * flags 0; in brief 2, 0x05010007, 2: an impersonation token whose
     * user is anonymous (S-1-5-7). */
    Status = ZwImpersonateAnonymousToken(NtCurrentThread());
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcWearing(Log, NULL);

        /* denied: as anonymous, a list for the system gives nothing.
         * 0, 1, 1: a list for anonymous does. The subject of a check
         * is the client while a thread impersonates. */
        NkcCheckNow(Log, Actor->Room, &NkcAsSystem);
        NkcCheckNow(Log, Actor->Room, &NkcAsAnonymous);

        /* 0; 0, 28, 0x05010007: the thread's token, opened and asked
         * for its user. */
        Handle = NULL;
        Status = ZwOpenThreadTokenEx(NtCurrentThread(), TOKEN_QUERY, TRUE, OBJ_KERNEL_HANDLE,
                                     &Handle);
        NkcPut(Log, (ULONG)Status);
        if (NT_SUCCESS(Status)) {
            RtlZeroMemory(Actor->Room->Out, sizeof(Actor->Room->Out));
            if (NT_SUCCESS(NkcAsk(Log, Handle, TokenUser, Actor->Room->Out,
                                  sizeof(Actor->Room->Out)))) {
                NkcPut(Log, NkcSidCode(((PTOKEN_USER)Actor->Room->Out)->User.Sid));
            }
            ZwClose(Handle);
        }

        /* 0, 0: put off; nobody again. */
        NkcPut(Log, (ULONG)NkcRevert());
        NkcWearing(Log, NULL);
    }

    /* 0, 1, 1: and the list for the system allows again. */
    NkcCheckNow(Log, Actor->Room, &NkcAsSystem);

    /* 0: putting off what is not on is fine. */
    NkcPut(Log, (ULONG)NkcRevert());
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID NkcTokenFacts(NKC_LOG *Log)
{
    NKC_ACTOR Actor;
    NKC_ROOM *Room;
    PACCESS_TOKEN Primary, Again;

    Room = (NKC_ROOM *)ExAllocatePoolWithTag(PagedPool, sizeof(*Room), NKC_TAG);
    if (Room == NULL) {
        return;
    }

    /* 1: the System process has one primary token, whoever asks. */
    Primary = PsReferencePrimaryToken(PsInitialSystemProcess);
    Again = PsReferencePrimaryToken(PsInitialSystemProcess);
    NkcPut(Log, Primary == Again ? 1 : 0);
    PsDereferencePrimaryToken(Again);

    NkcSystemToken(Log, Primary);
    NkcTokenHandles(Log, Room);

    Actor.Log = Log;
    Actor.Room = Room;
    Actor.Primary = Primary;
    NkcJoin(NkcStart(NkcActor, &Actor));

    PsDereferencePrimaryToken(Primary);
    ExFreePoolWithTag(Room, NKC_TAG);

    /* 0: at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}

static VOID NkcRunList(ULONG List, NKC_LOG *Log)
{
    UNREFERENCED_PARAMETER(List);
    NkcOnSystemThread(NkcTokenFacts, Log);
}
