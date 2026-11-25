/*
 * Conformance: security descriptors.
 *
 * Building a descriptor with an access list the way a driver does for
 * its device, the well-known SIDs the kernel exports, and the two
 * layouts of a descriptor, absolute and self-relative.
 */

/* The security routines are declared for file systems: <ntifs.h>,
 * which must come before <ntddk.h>. */
#include <ntifs.h>

#define NKC_DEVICE L"\\Device\\NkcSe"
#include "nkc.h"

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
}
