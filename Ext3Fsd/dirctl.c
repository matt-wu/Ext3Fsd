/*
 * COPYRIGHT:        See COPYRIGHT.TXT
 * PROJECT:          Ext2 File System Driver for WinNT/2K/XP
 * FILE:             dirctl.c
 * PROGRAMMER:       Matt Wu <mattwu@163.com>
 * HOMEPAGE:         http://www.ext2fsd.com
 * UPDATE HISTORY:
 */

/* INCLUDES *****************************************************************/

#include "ext2fs.h"

/* GLOBALS ***************************************************************/

extern PEXT2_GLOBAL Ext2Global;

/* DEFINITIONS *************************************************************/

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, Ext2GetInfoLength)
#pragma alloc_text(PAGE, Ext2ProcessEntry)
#pragma alloc_text(PAGE, Ext2QueryDirectory)
#pragma alloc_text(PAGE, Ext2NotifyChangeDirectory)
#pragma alloc_text(PAGE, Ext2DirectoryControl)
#pragma alloc_text(PAGE, Ext2IsDirectoryEmpty)
#endif

ULONG
Ext2GetInfoLength(IN FILE_INFORMATION_CLASS  FileInformationClass)
{
    switch (FileInformationClass) {

    case FileDirectoryInformation:
        return FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName[0]);

    case FileFullDirectoryInformation:
        return FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName[0]);

    case FileBothDirectoryInformation:
        return FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName[0]);

    case FileNamesInformation:
        return FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName[0]);

    case FileIdFullDirectoryInformation:
        return FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName[0]);

    case FileIdBothDirectoryInformation:
        return FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName[0]);

    default:
        break;
    }

    return 0;
}

NTSTATUS
Ext2ProcessEntry(
    IN PEXT2_IRP_CONTEXT    IrpContext,
    IN PEXT2_VCB            Vcb,
    IN PEXT2_FCB            Dcb,
    IN FILE_INFORMATION_CLASS  FileInformationClass,
    IN ULONG                in,
    IN PVOID                Buffer,
    IN ULONG                UsedLength,
    IN ULONG                Length,
    IN ULONG                FileIndex,
    IN PUNICODE_STRING      pName,
    OUT PULONG              EntrySize,
    IN BOOLEAN              Single
)
{
    PEXT2_MCB   Mcb = NULL;
    PEXT2_MCB   Target = NULL;

    NTSTATUS    Status = STATUS_SUCCESS;
    struct inode Inode = { 0 };

    ULONG InfoLength = 0;
    ULONG NameLength = 0;
    ULONG dwBytes = 0;
    LONGLONG FileSize = 0;
    LONGLONG AllocationSize;
    ULONG   FileAttributes = 0;

    *EntrySize = 0;
    NameLength = pName->Length;

    InfoLength = Ext2GetInfoLength(FileInformationClass);
    if (InfoLength == 0) {
        DEBUG(DL_ERR, ("Ext2ProcessDirEntry: Invalid Info Class %xh for %wZ in %wZ\n",
                       FileInformationClass, pName, &Dcb->Mcb->FullName ));
        return STATUS_INVALID_INFO_CLASS;
    }

    if (InfoLength + NameLength > Length)  {
        DEBUG(DL_INF, ( "Ext2PricessDirEntry: Buffer is not enough.\n"));
        Status = STATUS_BUFFER_OVERFLOW;
        if (UsedLength || InfoLength > Length) {
            DEBUG(DL_CP, ("Ext2ProcessDirEntry: Buffer overflows for %wZ in %wZ\n",
                          pName, &Dcb->Mcb->FullName ));
            return Status;
        }
        RtlZeroMemory((PCHAR)Buffer + UsedLength, Length);
    } else {
        RtlZeroMemory((PCHAR)Buffer + UsedLength, InfoLength + NameLength);
    }

    DEBUG(DL_CP, ("Ext2ProcessDirEntry: %wZ in %wZ\n", pName, &Dcb->Mcb->FullName ));

    Mcb = Ext2SearchMcb(Vcb, Dcb->Mcb, pName);
    if (NULL == Mcb) {

        Inode.i_ino = in;
        if (!Ext2LoadInode(Vcb, &Inode)) {
            DEBUG(DL_ERR, ("Ext2PricessDirEntry: Loading inode %xh (%wZ) error.\n",
                           in, pName ));
            DbgBreak();
            Status = STATUS_SUCCESS;
            goto errorout;
        }

        if (S_ISLNK(Inode.i_mode)) {
            DEBUG(DL_RES, ("Ext2ProcessDirEntry: SymLink: %wZ\\%wZ\n",
                           &Dcb->Mcb->FullName, pName));
            Ext2LookupFile(IrpContext, Vcb, pName, Dcb->Mcb, &Mcb, 0);
        }
    }

    if (Mcb != NULL)  {

        if (IsMcbSymLink(Mcb)) {
            Target = Mcb->Target;
            ASSERT(Target);
            if (IsMcbDirectory(Target)) {
                FileSize = 0;
            } else {
                FileSize = Target->FileSize.QuadPart;
            }
        } else {
            if (IsMcbDirectory(Mcb)) {
                FileSize = 0;
            } else {
                FileSize = Mcb->FileSize.QuadPart;
            }
        }

        FileAttributes = Mcb->FileAttr;

    } else {

        if (S_ISDIR(Inode.i_mode)) {
            FileSize = 0;
        } else {
            FileSize  = Inode.i_size;
        }

        if (S_ISDIR(Inode.i_mode)) {
            FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        } else {
            FileAttributes = FILE_ATTRIBUTE_NORMAL;
        }

        if (Ext2IsReadOnly(Inode.i_mode)) {
            SetFlag(FileAttributes, FILE_ATTRIBUTE_READONLY);
        }
    }

    AllocationSize = CEILING_ALIGNED(ULONGLONG, FileSize, BLOCK_SIZE);

    /* process special files under root directory */
    if (IsRoot(Dcb)) {
        /* set hidden and system attributes for Recycled /
           RECYCLER / pagefile.sys */
        BOOLEAN IsDirectory = IsFlagOn(FileAttributes, FILE_ATTRIBUTE_DIRECTORY);
        if (Ext2IsSpecialSystemFile(pName, IsDirectory)) {
            SetFlag(FileAttributes, FILE_ATTRIBUTE_HIDDEN);
            SetFlag(FileAttributes, FILE_ATTRIBUTE_SYSTEM);
        }
    }

    /* set hidden attribute for all entries starting with '.' */
    if (( pName->Length >= 4 && pName->Buffer[0] == L'.') &&
            ((pName->Length == 4 && pName->Buffer[1] != L'.') ||
             pName->Length >= 6 )) {
        SetFlag(FileAttributes, FILE_ATTRIBUTE_HIDDEN);
    }

    switch (FileInformationClass) {

    case FileDirectoryInformation:

    {
        PFILE_DIRECTORY_INFORMATION     FDI;

        FDI = (PFILE_DIRECTORY_INFORMATION) ((PUCHAR)Buffer + UsedLength);
        if (!Single) {
            FDI->NextEntryOffset = InfoLength + NameLength;
            FDI->NextEntryOffset = CEILING_ALIGNED(ULONG, FDI->NextEntryOffset, 8);
        }

        FDI->FileIndex = FileIndex;

        if (Mcb) {

            FDI->CreationTime = Mcb->CreationTime;
            FDI->LastAccessTime = Mcb->LastAccessTime;
            FDI->LastWriteTime = Mcb->LastWriteTime;
            FDI->ChangeTime = Mcb->ChangeTime;

        } else {

            FDI->CreationTime = Ext2NtTime(Inode.i_ctime);
            FDI->LastAccessTime = Ext2NtTime(Inode.i_atime);
            FDI->LastWriteTime = Ext2NtTime(Inode.i_mtime);
            FDI->ChangeTime = Ext2NtTime(Inode.i_mtime);
        }

        FDI->FileAttributes = FileAttributes;
        FDI->EndOfFile.QuadPart = FileSize;
        FDI->AllocationSize.QuadPart = AllocationSize;

        FDI->FileNameLength = NameLength;
        if (InfoLength + NameLength > Length) {
            NameLength = Length - InfoLength;
        }
        RtlCopyMemory(FDI->FileName, pName->Buffer, NameLength);

        *EntrySize = InfoLength + NameLength;
        break;
    }

    case FileFullDirectoryInformation:

    {
        PFILE_FULL_DIR_INFORMATION      FFI;

        FFI = (PFILE_FULL_DIR_INFORMATION) ((PUCHAR)Buffer + UsedLength);
        if (!Single) {
            FFI->NextEntryOffset = InfoLength + NameLength;
            FFI->NextEntryOffset = CEILING_ALIGNED(ULONG, FFI->NextEntryOffset, 8);
        }

        FFI->FileIndex = FileIndex;

        if (Mcb) {

            FFI->CreationTime = Mcb->CreationTime;
            FFI->LastAccessTime = Mcb->LastAccessTime;
            FFI->LastWriteTime = Mcb->LastWriteTime;
            FFI->ChangeTime = Mcb->ChangeTime;

        } else {

            FFI->CreationTime = Ext2NtTime(Inode.i_ctime);
            FFI->LastAccessTime = Ext2NtTime(Inode.i_atime);
            FFI->LastWriteTime = Ext2NtTime(Inode.i_mtime);
            FFI->ChangeTime = Ext2NtTime(Inode.i_mtime);
        }

        FFI->FileAttributes = FileAttributes;
        FFI->FileNameLength = NameLength;
        if (InfoLength + NameLength > Length) {
            NameLength = Length - InfoLength;
        }
        RtlCopyMemory(FFI->FileName, pName->Buffer, NameLength);

        *EntrySize = InfoLength + NameLength;
        break;
    }

    case FileBothDirectoryInformation:

    {
        PFILE_BOTH_DIR_INFORMATION      FBI;

        FBI = (PFILE_BOTH_DIR_INFORMATION) ((PUCHAR)Buffer + UsedLength);
        if (!Single) {
            FBI->NextEntryOffset = InfoLength + NameLength;
            FBI->NextEntryOffset = CEILING_ALIGNED(ULONG, FBI->NextEntryOffset, 8);
        }

        FBI->FileIndex = FileIndex;
        FBI->EndOfFile.QuadPart = FileSize;
        FBI->AllocationSize.QuadPart = AllocationSize;

        if (Mcb) {

            FBI->CreationTime = Mcb->CreationTime;
            FBI->LastAccessTime = Mcb->LastAccessTime;
            FBI->LastWriteTime = Mcb->LastWriteTime;
            FBI->ChangeTime = Mcb->ChangeTime;

        } else {

            FBI->CreationTime = Ext2NtTime(Inode.i_ctime);
            FBI->LastAccessTime = Ext2NtTime(Inode.i_atime);
            FBI->LastWriteTime = Ext2NtTime(Inode.i_mtime);
            FBI->ChangeTime = Ext2NtTime(Inode.i_mtime);
        }

        FBI->FileAttributes = FileAttributes;

#ifdef DIR_ENTRY_SHORT_NAME
        if (NameLength <= 24) {
            RtlCopyMemory(FBI->ShortName, pName->Buffer, NameLength);
            FBI->ShortNameLength = (UCHAR)NameLength;
        }
#endif

        FBI->FileNameLength = NameLength;
        if (InfoLength + NameLength > Length) {
            NameLength = Length - InfoLength;
        }
        RtlCopyMemory(FBI->FileName, pName->Buffer, NameLength);

        *EntrySize = InfoLength + NameLength;
        break;
    }

    case FileNamesInformation:

    {
        PFILE_NAMES_INFORMATION         FNI;

        FNI = (PFILE_NAMES_INFORMATION) ((PUCHAR)Buffer + UsedLength);
        if (!Single) {
            FNI->NextEntryOffset = InfoLength + NameLength;
            FNI->NextEntryOffset = CEILING_ALIGNED(ULONG, FNI->NextEntryOffset, 8);
        }

        FNI->FileNameLength = NameLength;
        if (InfoLength + NameLength > Length) {
            NameLength = Length - InfoLength;
        }
        RtlCopyMemory(FNI->FileName, pName->Buffer, NameLength);

        *EntrySize = InfoLength + NameLength;
        break;
    }

    case FileIdFullDirectoryInformation:

    {
        PFILE_ID_FULL_DIR_INFORMATION   FIF;

        FIF = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)Buffer + UsedLength);
        if (!Single) {
            FIF->NextEntryOffset = InfoLength + NameLength;
            FIF->NextEntryOffset = CEILING_ALIGNED(ULONG, FIF->NextEntryOffset, 8);
        }

        FIF->FileIndex = FileIndex;

        if (Mcb) {

            FIF->CreationTime = Mcb->CreationTime;
            FIF->LastAccessTime = Mcb->LastAccessTime;
            FIF->LastWriteTime = Mcb->LastWriteTime;
            FIF->ChangeTime = Mcb->ChangeTime;

        } else {

            FIF->CreationTime = Ext2NtTime(Inode.i_ctime);
            FIF->LastAccessTime = Ext2NtTime(Inode.i_atime);
            FIF->LastWriteTime = Ext2NtTime(Inode.i_mtime);
            FIF->ChangeTime = Ext2NtTime(Inode.i_mtime);
        }

        FIF->FileAttributes = FileAttributes;
        FIF->FileId.QuadPart = (LONGLONG)in;
        FIF->FileNameLength = NameLength;
        if (InfoLength + NameLength > Length) {
            NameLength = Length - InfoLength;
        }
        RtlCopyMemory(FIF->FileName, pName->Buffer, NameLength);

        *EntrySize = InfoLength + NameLength;
        break;
    }

    case FileIdBothDirectoryInformation:

    {
        PFILE_ID_BOTH_DIR_INFORMATION   FIB;

        FIB = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)Buffer + UsedLength);
        if (!Single) {
            FIB->NextEntryOffset = InfoLength + NameLength;
            FIB->NextEntryOffset = CEILING_ALIGNED(ULONG, FIB->NextEntryOffset, 8);
        }

        FIB->FileIndex = FileIndex;
        FIB->EndOfFile.QuadPart = FileSize;
        FIB->AllocationSize.QuadPart = AllocationSize;

        if (Mcb) {

            FIB->CreationTime = Mcb->CreationTime;
            FIB->LastAccessTime = Mcb->LastAccessTime;
            FIB->LastWriteTime = Mcb->LastWriteTime;
            FIB->ChangeTime = Mcb->ChangeTime;

        } else {

            FIB->CreationTime = Ext2NtTime(Inode.i_ctime);
            FIB->LastAccessTime = Ext2NtTime(Inode.i_atime);
            FIB->LastWriteTime = Ext2NtTime(Inode.i_mtime);
            FIB->ChangeTime = Ext2NtTime(Inode.i_mtime);
        }

        FIB->FileAttributes = FileAttributes;
        FIB->FileId.QuadPart = (LONGLONG)in;

#ifdef DIR_ENTRY_SHORT_NAME
        if (NameLength <= 24) {
            RtlCopyMemory(FIB->ShortName, pName->Buffer, NameLength);
            FIB->ShortNameLength = (UCHAR)NameLength;
        }
#endif

        FIB->FileNameLength = NameLength;
        if (InfoLength + NameLength > Length) {
            NameLength = Length - InfoLength;
        }
        RtlCopyMemory(FIB->FileName, pName->Buffer, NameLength);

        *EntrySize = InfoLength + NameLength;
        break;
    }

    default:
        Status = STATUS_INVALID_INFO_CLASS;
        break;
    }

    if (Mcb) {
        Ext2DerefMcb(Mcb);
    }

errorout:

    DEBUG(DL_CP, ("Ext2ProcessDirEntry: Status = %xh for %wZ in %wZ\n",
                  Status, pName, &Dcb->Mcb->FullName ));

    return Status;
}


BOOLEAN
Ext2IsWearingCloak(
    IN  PEXT2_VCB       Vcb,
    IN  POEM_STRING     OemName
)
{
    size_t  PatLen = 0;

    /* we could not filter the files: "." and ".." */
    if (OemName->Length >= 1 && OemName->Buffer[0] == '.') {

        if ( OemName->Length == 2 && OemName->Buffer[1] == '.') {
            return FALSE;
        } else if (OemName->Length == 1) {
            return FALSE;
        }
    }

    /* checking name prefix */
    if (Vcb->bHidingPrefix) {
        PatLen = strlen(&Vcb->sHidingPrefix[0]);
        if (PatLen <= OemName->Length) {
            if ( _strnicmp( OemName->Buffer,
                            Vcb->sHidingPrefix,
                            PatLen ) == 0) {
                return TRUE;
            }
        }
    }

    /* checking name suffix */
    if (Vcb->bHidingSuffix) {
        PatLen = strlen(&Vcb->sHidingSuffix[0]);
        if (PatLen <= OemName->Length) {
            if ( _strnicmp(&OemName->Buffer[OemName->Length - PatLen],
                           Vcb->sHidingSuffix, PatLen ) == 0) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static int Ext2FillEntry(void *context, const char *name, int namlen,
                         ULONG offset, __u32 ino, unsigned int d_type)
{
    PEXT2_FILLDIR_CONTEXT fc = context;
    PEXT2_IRP_CONTEXT IrpContext = fc->efc_irp;

    PEXT2_FCB       Fcb = IrpContext->Fcb;
    PEXT2_CCB       Ccb = IrpContext->Ccb;
    PEXT2_VCB       Vcb = Fcb->Vcb;

    OEM_STRING      Oem;
    UNICODE_STRING  Unicode = { 0 };
    NTSTATUS        Status = STATUS_SUCCESS;
    ULONG           EntrySize;
    USHORT          NameLen;
    int             rc = 0;

    if (fc->efc_start > 0 && (fc->efc_single || (fc->efc_size <
                              fc->efc_start +  namlen * 2 + Ext2GetInfoLength(fc->efc_fi)) )) {
        rc = 1;
        goto errorout;
    }


    Oem.Buffer = (void *)name;
    Oem.Length = namlen & 0xFF;
    Oem.MaximumLength = Oem.Length;

    /* skip . and .. */
    if ((Oem.Length == 1 && name[0] == '.') || (Oem.Length == 2 &&
            name[0] == '.' && name[1] == '.' )) {
        goto errorout;
    }

    if (Ext2IsWearingCloak(Vcb, &Oem)) {
        goto errorout;
    }

    NameLen = (USHORT)Ext2OEMToUnicodeSize(Vcb, &Oem);
    if (NameLen <= 0) {
        fc->efc_status = STATUS_INSUFFICIENT_RESOURCES;
        rc = -ENOMEM;
        goto errorout;
    }

    Unicode.MaximumLength = NameLen + 2;
    Unicode.Buffer = Ext2AllocatePool(
                         PagedPool,
                         Unicode.MaximumLength,
                         EXT2_INAME_MAGIC
                     );
    if (!Unicode.Buffer) {
        DEBUG(DL_ERR, ( "Ex2QueryDirectory: failed to "
                        "allocate InodeFileName.\n"));
        fc->efc_status = STATUS_INSUFFICIENT_RESOURCES;
        rc = -ENOMEM;
        goto errorout;
    }
    RtlZeroMemory(Unicode.Buffer, Unicode.MaximumLength);
    INC_MEM_COUNT(PS_INODE_NAME, Unicode.Buffer, Unicode.MaximumLength);

    Status = Ext2OEMToUnicode(Vcb, &Unicode, &Oem);
    if (!NT_SUCCESS(Status)) {
        DEBUG(DL_ERR, ( "Ex2QueryDirectory: Ext2OEMtoUnicode failed with %xh.\n", Status));
        fc->efc_status = STATUS_INSUFFICIENT_RESOURCES;
        rc = -ENOMEM;
        goto errorout;
    }

    if (FsRtlDoesNameContainWildCards( &Ccb->DirectorySearchPattern) ?
            FsRtlIsNameInExpression(&Ccb->DirectorySearchPattern,
                                    &Unicode, TRUE, NULL) :
            !RtlCompareUnicodeString(&Ccb->DirectorySearchPattern,
                                     &Unicode, TRUE)) {
        Status = Ext2ProcessEntry(fc->efc_irp, Vcb, Fcb, fc->efc_fi, ino, fc->efc_buf,
                                  CEILING_ALIGNED(ULONG, fc->efc_start, 8),
                                  fc->efc_size - CEILING_ALIGNED(ULONG, fc->efc_start, 8),
                                  offset, &Unicode, &EntrySize, fc->efc_single);
        if (NT_SUCCESS(Status)) {
            if (EntrySize > 0) {
                fc->efc_prev = CEILING_ALIGNED(ULONG, fc->efc_start, 8);
                fc->efc_start = fc->efc_prev + EntrySize;
            } else {
                DbgBreak();
            }
        } else {
            if (Status == STATUS_BUFFER_OVERFLOW) {
                if (fc->efc_start == 0) {
                    fc->efc_start = EntrySize;
                } else {
                    Status = STATUS_SUCCESS;
                }
            }
            rc = 1;
        }
    }

errorout:

    fc->efc_status = Status;
    if (Unicode.Buffer)
        Ext2FreePool(Unicode.Buffer, EXT2_INAME_MAGIC);

    return rc;
}


NTSTATUS
Ext2QueryDirectory (IN PEXT2_IRP_CONTEXT IrpContext)
{
    PDEVICE_OBJECT          DeviceObject;
    NTSTATUS                Status = STATUS_UNSUCCESSFUL;
    PEXT2_VCB               Vcb;
    PFILE_OBJECT            FileObject;
    PEXT2_FCB               Fcb;
    PEXT2_MCB               Mcb;
    PEXT2_CCB               Ccb;
    PIRP                    Irp;
    PIO_STACK_LOCATION      IoStackLocation;

    ULONG                   Length;
    ULONG                   FileIndex;
    PUNICODE_STRING         FileName;
    PUCHAR                  Buffer;

    BOOLEAN                 RestartScan;
    BOOLEAN                 ReturnSingleEntry;
    BOOLEAN                 IndexSpecified;
    BOOLEAN                 FirstQuery;
    BOOLEAN                 FcbResourceAcquired = FALSE;

    USHORT                  NameLen;
    FILE_INFORMATION_CLASS  fi;

    OEM_STRING              Oem = { 0 };
    UNICODE_STRING          Unicode = { 0 };
    PEXT2_DIR_ENTRY2        pDir = NULL;

    ULONG                   ByteOffset;
    ULONG                   RecLen = 0;
    ULONG                   EntrySize = 0;

    EXT2_FILLDIR_CONTEXT    fc = { 0 };

    __try {

        ASSERT(IrpContext);
        ASSERT((IrpContext->Identifier.Type == EXT2ICX) &&
               (IrpContext->Identifier.Size == sizeof(EXT2_IRP_CONTEXT)));

        DeviceObject = IrpContext->DeviceObject;

        //
        // This request is not allowed on the main device object
        //
        if (IsExt2FsDevice(DeviceObject)) {
            Status = STATUS_INVALID_DEVICE_REQUEST;
            __leave;
        }

        Vcb = (PEXT2_VCB) DeviceObject->DeviceExtension;
        ASSERT(Vcb != NULL);
        ASSERT((Vcb->Identifier.Type == EXT2VCB) &&
               (Vcb->Identifier.Size == sizeof(EXT2_VCB)));

        if (!IsMounted(Vcb)) {
            Status = STATUS_VOLUME_DISMOUNTED;
            __leave;
        }

        FileObject = IrpContext->FileObject;
        Fcb = (PEXT2_FCB) FileObject->FsContext;
        if (Fcb == NULL) {
            Status = STATUS_INVALID_PARAMETER;
            __leave;
        }
        Mcb = Fcb->Mcb;
        if (IsSymLink(Fcb))
            Mcb = Mcb->Target;
        if (NULL == Mcb) {
            Status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        //
        // This request is not allowed on volumes
        //
        if (Fcb->Identifier.Type == EXT2VCB) {
            Status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        ASSERT((Fcb->Identifier.Type == EXT2FCB) &&
               (Fcb->Identifier.Size == sizeof(EXT2_FCB)));

        if (!IsDirectory(Fcb)) {
            Status = STATUS_NOT_A_DIRECTORY;
            __leave;
        }

        Ccb = (PEXT2_CCB) FileObject->FsContext2;

        ASSERT(Ccb);
        ASSERT((Ccb->Identifier.Type == EXT2CCB) &&
               (Ccb->Identifier.Size == sizeof(EXT2_CCB)));

        Irp = IrpContext->Irp;
        IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

#ifndef _GNU_NTIFS_

        fi = IoStackLocation->Parameters.QueryDirectory.FileInformationClass;

        Length = IoStackLocation->Parameters.QueryDirectory.Length;

        FileName = (PUNICODE_STRING)IoStackLocation->Parameters.QueryDirectory.FileName;

        FileIndex = IoStackLocation->Parameters.QueryDirectory.FileIndex;

#else // _GNU_NTIFS_

        fi = ((PEXTENDED_IO_STACK_LOCATION)
              IoStackLocation)->Parameters.QueryDirectory.FileInformationClass;

        Length = ((PEXTENDED_IO_STACK_LOCATION)
                  IoStackLocation)->Parameters.QueryDirectory.Length;

        FileName = ((PEXTENDED_IO_STACK_LOCATION)
                    IoStackLocation)->Parameters.QueryDirectory.FileName;

        FileIndex = ((PEXTENDED_IO_STACK_LOCATION)
                     IoStackLocation)->Parameters.QueryDirectory.FileIndex;

#endif // _GNU_NTIFS_

        RestartScan = FlagOn(((PEXTENDED_IO_STACK_LOCATION)
                              IoStackLocation)->Flags, SL_RESTART_SCAN);
        ReturnSingleEntry = FlagOn(((PEXTENDED_IO_STACK_LOCATION)
                                    IoStackLocation)->Flags, SL_RETURN_SINGLE_ENTRY);
        IndexSpecified = FlagOn(((PEXTENDED_IO_STACK_LOCATION)
                                 IoStackLocation)->Flags, SL_INDEX_SPECIFIED);

        Buffer = Ext2GetUserBuffer(Irp);
        if (Buffer == NULL) {
            DbgBreak();
            Status = STATUS_INVALID_USER_BUFFER;
            __leave;
        }

        if (!IsFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT)) {
            Status = STATUS_PENDING;
            __leave;
        }

        if (!ExAcquireResourceSharedLite(
                    &Fcb->MainResource,
                    IsFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT) )) {
            Status = STATUS_PENDING;
            __leave;
        }
        FcbResourceAcquired = TRUE;

        if (FileName != NULL) {

            if (Ccb->DirectorySearchPattern.Buffer != NULL) {

                FirstQuery = FALSE;

            } else {

                FirstQuery = TRUE;

                Ccb->DirectorySearchPattern.Length =
                    Ccb->DirectorySearchPattern.MaximumLength =
                        FileName->Length;

                Ccb->DirectorySearchPattern.Buffer =
                    Ext2AllocatePool(PagedPool, FileName->Length,
                                     EXT2_DIRSP_MAGIC);

                if (Ccb->DirectorySearchPattern.Buffer == NULL) {
                    DEBUG(DL_ERR, ( "Ex2QueryDirectory: failed to allocate SerarchPattern.\n"));
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    __leave;
                }

                INC_MEM_COUNT( PS_DIR_PATTERN,
                               Ccb->DirectorySearchPattern.Buffer,
                               Ccb->DirectorySearchPattern.MaximumLength);

                Status = RtlUpcaseUnicodeString(
                             &(Ccb->DirectorySearchPattern),
                             FileName,
                             FALSE);

                if (!NT_SUCCESS(Status)) {
                    __leave;
                }
            }

        } else if (Ccb->DirectorySearchPattern.Buffer != NULL) {

            FirstQuery = FALSE;
            FileName = &Ccb->DirectorySearchPattern;

        } else {

            FirstQuery = TRUE;

            Ccb->DirectorySearchPattern.Length =
                Ccb->DirectorySearchPattern.MaximumLength = 2;

            Ccb->DirectorySearchPattern.Buffer =
                Ext2AllocatePool(PagedPool, 4, EXT2_DIRSP_MAGIC);

            if (Ccb->DirectorySearchPattern.Buffer == NULL) {
                DEBUG(DL_ERR, ( "Ex2QueryDirectory: failed to allocate SerarchPattern (1st).\n"));
                Status = STATUS_INSUFFICIENT_RESOURCES;
                __leave;
            }

            INC_MEM_COUNT( PS_DIR_PATTERN,
                           Ccb->DirectorySearchPattern.Buffer,
                           Ccb->DirectorySearchPattern.MaximumLength);

            RtlZeroMemory(Ccb->DirectorySearchPattern.Buffer, 4);
            RtlCopyMemory(
                Ccb->DirectorySearchPattern.Buffer,
                L"*\0", 2);
        }

        if (IndexSpecified) {
            Ccb->filp.f_pos = FileIndex;
        } else {
            if (RestartScan || FirstQuery) {
                Ccb->filp.f_pos = FileIndex = 0;
            } else {
                FileIndex = (ULONG)Ccb->filp.f_pos;
            }
        }

        RtlZeroMemory(Buffer, Length);

        fc.efc_irp = IrpContext;
        fc.efc_buf = Buffer;
        fc.efc_size = Length;
        fc.efc_start = 0;
        fc.efc_single = ReturnSingleEntry;
        fc.efc_fi = fi;
        fc.efc_status = STATUS_SUCCESS;

#ifdef EXT2_HTREE_INDEX

        if (EXT3_HAS_COMPAT_FEATURE(Mcb->Inode.i_sb,
                                    EXT3_FEATURE_COMPAT_DIR_INDEX) &&
                ((EXT3_I(&Mcb->Inode)->i_flags & EXT3_INDEX_FL) ||
                 ((Mcb->Inode.i_size >> BLOCK_BITS) == 1)) ) {
            int rc = ext3_dx_readdir(&Ccb->filp, Ext2FillEntry, &fc);
            Status = fc.efc_status;
            if (rc != ERR_BAD_DX_DIR) {
                goto errorout;
            }
            /*
             * We don't set the inode dirty flag since it's not
             * critical that it get flushed back to the disk.
             */
            EXT3_I(&Mcb->Inode)->i_flags &= ~EXT3_INDEX_FL;
        }
#endif

        if (Mcb->Inode.i_size <= Ccb->filp.f_pos) {
            Status = STATUS_NO_MORE_FILES;
            __leave;
        }

        pDir = Ext2AllocatePool(
                   PagedPool,
                   sizeof(EXT2_DIR_ENTRY2),
                   EXT2_DENTRY_MAGIC
               );

        if (!pDir) {
            DEBUG(DL_ERR, ( "Ex2QueryDirectory: failed to allocate pDir.\n"));
            Status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        INC_MEM_COUNT(PS_DIR_ENTRY, pDir, sizeof(EXT2_DIR_ENTRY2));
        ByteOffset = FileIndex;

        DEBUG(DL_CP, ("Ex2QueryDirectory: Dir: %wZ Index=%xh Pattern : %wZ.\n",
                      &Fcb->Mcb->FullName, FileIndex, &Ccb->DirectorySearchPattern));

        while ((ByteOffset < Mcb->Inode.i_size) &&
                (CEILING_ALIGNED(ULONG, fc.efc_start, 8) < Length)) {

            RtlZeroMemory(pDir, sizeof(EXT2_DIR_ENTRY2));

            Status = Ext2ReadInode(
                         IrpContext,
                         Vcb,
                         Mcb,
                         (ULONGLONG)ByteOffset,
                         (PVOID)pDir,
                         sizeof(EXT2_DIR_ENTRY2),
                         FALSE,
                         &EntrySize);

            if (!NT_SUCCESS(Status)) {
                __leave;
            }

            if (pDir->rec_len == 0) {
                RecLen = BLOCK_SIZE - (ByteOffset & (BLOCK_SIZE - 1));
            } else {
                RecLen = ext3_rec_len_from_disk(pDir->rec_len);
            }

            if (!pDir->inode || pDir->inode >= INODES_COUNT) {
                goto ProcessNextEntry;
            }

            /* skip . and .. */
            if ((pDir->name_len == 1 && pDir->name[0] == '.') ||
                    (pDir->name_len == 2 && pDir->name[0] == '.' && pDir->name[1] == '.' )) {
                goto ProcessNextEntry;
            }

            Oem.Buffer = pDir->name;
            Oem.Length = (pDir->name_len & 0xff);
            Oem.MaximumLength = Oem.Length;

            if (Ext2IsWearingCloak(Vcb, &Oem)) {
                goto ProcessNextEntry;
            }

            NameLen = (USHORT) Ext2OEMToUnicodeSize(Vcb, &Oem);

            if (NameLen <= 0) {
                DEBUG(DL_CP, ("Ext2QueryDirectory: failed to count unicode length for inode: %xh\n",
                              pDir->inode));
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            if ( Unicode.Buffer != NULL && Unicode.MaximumLength > NameLen) {
                /* reuse buffer */
            } else {
                /* free and re-allocate it */
                if (Unicode.Buffer) {
                    DEC_MEM_COUNT(PS_INODE_NAME,
                                  Unicode.Buffer,
                                  Unicode.MaximumLength);
                    Ext2FreePool(Unicode.Buffer, EXT2_INAME_MAGIC);
                }
                Unicode.MaximumLength = NameLen + 2;
                Unicode.Buffer = Ext2AllocatePool(
                                     PagedPool, Unicode.MaximumLength,
                                     EXT2_INAME_MAGIC
                                 );
                if (!Unicode.Buffer) {
                    DEBUG(DL_ERR, ( "Ex2QueryDirectory: failed to "
                                    "allocate InodeFileName.\n"));
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    __leave;
                }
                INC_MEM_COUNT(PS_INODE_NAME, Unicode.Buffer, Unicode.MaximumLength);
            }

            Unicode.Length = 0;
            RtlZeroMemory(Unicode.Buffer, Unicode.MaximumLength);

            Status = Ext2OEMToUnicode(Vcb, &Unicode, &Oem);
            if (!NT_SUCCESS(Status)) {
                DEBUG(DL_ERR, ( "Ex2QueryDirectory: Ext2OEMtoUnicode failed with %xh.\n", Status));
                Status = STATUS_INSUFFICIENT_RESOURCES;
                __leave;
            }

            DEBUG(DL_CP, ( "Ex2QueryDirectory: process inode: %xh / %wZ (%d).\n",
                           pDir->inode, &Unicode, Unicode.Length));

            if (FsRtlDoesNameContainWildCards(
                        &(Ccb->DirectorySearchPattern)) ?
                    FsRtlIsNameInExpression(
                        &(Ccb->DirectorySearchPattern),
                        &Unicode,
                        TRUE,
                        NULL) :
                    !RtlCompareUnicodeString(
                        &(Ccb->DirectorySearchPattern),
                        &Unicode,
                        TRUE)           ) {

                Status = Ext2ProcessEntry(
                             IrpContext,
                             Vcb,
                             Fcb,
                             fi,
                             pDir->inode,
                             Buffer,
                             CEILING_ALIGNED(ULONG, fc.efc_start, 8),
                             Length - CEILING_ALIGNED(ULONG, fc.efc_start, 8),
                             ByteOffset,
                             &Unicode,
                             &EntrySize,
                             ReturnSingleEntry
                         );

                if (NT_SUCCESS(Status)) {
                    if (EntrySize > 0) {
                        fc.efc_prev  = CEILING_ALIGNED(ULONG, fc.efc_start, 8);
                        fc.efc_start = fc.efc_prev + EntrySize;
                    } else {
                        DbgBreak();
                    }
                } else {
                    if (Status == STATUS_BUFFER_OVERFLOW) {
                        if (fc.efc_start == 0) {
                            fc.efc_start = EntrySize;
                        } else {
                            Status = STATUS_SUCCESS;
                        }
                    } else {
                        __leave;
                    }
                    break;
                }
            }

ProcessNextEntry:

            ByteOffset += RecLen;
            Ccb->filp.f_pos = ByteOffset;

            if (fc.efc_start && ReturnSingleEntry) {
                Status = STATUS_SUCCESS;
                goto errorout;
            }
        }

errorout:

        ((PULONG)((PUCHAR)Buffer + fc.efc_prev))[0] = 0;
        FileIndex = ByteOffset;

        if (Status == STATUS_BUFFER_OVERFLOW) {
            /* just return fc.efc_start/EntrySize bytes that we filled */
        } else if (!fc.efc_start) {
            if (NT_SUCCESS(Status)) {
                if (FirstQuery) {
                    Status = STATUS_NO_SUCH_FILE;
                } else {
                    Status = STATUS_NO_MORE_FILES;
                }
            }
        } else {
            Status = STATUS_SUCCESS;
        }

    } __finally {

        if (FcbResourceAcquired) {
            ExReleaseResourceLite(&Fcb->MainResource);
        }

        if (pDir != NULL) {
            Ext2FreePool(pDir, EXT2_DENTRY_MAGIC);
            DEC_MEM_COUNT(PS_DIR_ENTRY, pDir, sizeof(EXT2_DIR_ENTRY2));
        }

        if (Unicode.Buffer != NULL) {
            DEC_MEM_COUNT(PS_INODE_NAME, Unicode.Buffer, Unicode.MaximumLength );
            Ext2FreePool(Unicode.Buffer, EXT2_INAME_MAGIC);
        }

        if (!IrpContext->ExceptionInProgress) {

            if ( Status == STATUS_PENDING ||
                    Status == STATUS_CANT_WAIT) {

                Status = Ext2LockUserBuffer(
                             IrpContext->Irp,
                             Length,
                             IoWriteAccess );

                if (NT_SUCCESS(Status)) {
                    Status = Ext2QueueRequest(IrpContext);
                } else {
                    Ext2CompleteIrpContext(IrpContext, Status);
                }
            } else {
                IrpContext->Irp->IoStatus.Information = fc.efc_start;
                Ext2CompleteIrpContext(IrpContext, Status);
            }
        }
    }

    return Status;
}

NTSTATUS
Ext2NotifyChangeDirectory (
    IN PEXT2_IRP_CONTEXT IrpContext
)
{
    PDEVICE_OBJECT      DeviceObject;
    BOOLEAN             CompleteRequest = TRUE;
    NTSTATUS            Status = STATUS_UNSUCCESSFUL;
    PEXT2_VCB           Vcb;
    PFILE_OBJECT        FileObject;
    PEXT2_FCB           Fcb;
    PIRP                Irp;
    PIO_STACK_LOCATION  IrpSp;
    ULONG               CompletionFilter;
    BOOLEAN             WatchTree;

    BOOLEAN             bFcbAcquired = FALSE;

    __try {

        ASSERT(IrpContext);
        ASSERT((IrpContext->Identifier.Type == EXT2ICX) &&
               (IrpContext->Identifier.Size == sizeof(EXT2_IRP_CONTEXT)));

        //
        //  Always set the wait flag in the Irp context for the original request.
        //

        SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );

        DeviceObject = IrpContext->DeviceObject;

        if (IsExt2FsDevice(DeviceObject)) {
            Status = STATUS_INVALID_DEVICE_REQUEST;
            __leave;
        }

        Vcb = (PEXT2_VCB) DeviceObject->DeviceExtension;

        ASSERT(Vcb != NULL);
        ASSERT((Vcb->Identifier.Type == EXT2VCB) &&
               (Vcb->Identifier.Size == sizeof(EXT2_VCB)));

        FileObject = IrpContext->FileObject;
        Fcb = (PEXT2_FCB) FileObject->FsContext;
        ASSERT(Fcb);

        if (Fcb->Identifier.Type == EXT2VCB) {
            DbgBreak();
            Status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        ASSERT((Fcb->Identifier.Type == EXT2FCB) &&
               (Fcb->Identifier.Size == sizeof(EXT2_FCB)));

        if (!IsDirectory(Fcb)) {
            DbgBreak();
            Status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        if (ExAcquireResourceExclusiveLite(
                    &Fcb->MainResource,
                    TRUE ))  {
            bFcbAcquired = TRUE;
        } else {
            Status = STATUS_PENDING;
            __leave;
        }

        Irp = IrpContext->Irp;

        IrpSp = IoGetCurrentIrpStackLocation(Irp);

#ifndef _GNU_NTIFS_

        CompletionFilter =
            IrpSp->Parameters.NotifyDirectory.CompletionFilter;

#else // _GNU_NTIFS_

        CompletionFilter = ((PEXTENDED_IO_STACK_LOCATION)
                            IrpSp)->Parameters.NotifyDirectory.CompletionFilter;

#endif // _GNU_NTIFS_

        WatchTree = IsFlagOn(IrpSp->Flags, SL_WATCH_TREE);

        if (FlagOn(Fcb->Flags, FCB_DELETE_PENDING)) {
            Status = STATUS_DELETE_PENDING;
            __leave;
        }

        FsRtlNotifyFullChangeDirectory( Vcb->NotifySync,
                                        &Vcb->NotifyList,
                                        FileObject->FsContext2,
                                        (PSTRING)(&Fcb->Mcb->FullName),
                                        WatchTree,
                                        FALSE,
                                        CompletionFilter,
                                        Irp,
                                        NULL,
                                        NULL );

        CompleteRequest = FALSE;

        Status = STATUS_PENDING;

        /*
            Currently the driver is read-only but here is an example on how to use the
            FsRtl-functions to report a change:

            ANSI_STRING TestString;
            USHORT      FileNamePartLength;

            RtlInitAnsiString(&TestString, "\\ntifs.h");

            FileNamePartLength = 7;

            FsRtlNotifyReportChange(
                Vcb->NotifySync,            // PNOTIFY_SYNC NotifySync
                &Vcb->NotifyList,           // PLIST_ENTRY  NotifyList
                &TestString,                // PSTRING      FullTargetName
                &FileNamePartLength,        // PUSHORT      FileNamePartLength
                FILE_NOTIFY_CHANGE_NAME     // ULONG        FilterMatch
                );

            or

            ANSI_STRING TestString;

            RtlInitAnsiString(&TestString, "\\ntifs.h");

            FsRtlNotifyFullReportChange(
                Vcb->NotifySync,            // PNOTIFY_SYNC NotifySync
                &Vcb->NotifyList,           // PLIST_ENTRY  NotifyList
                &TestString,                // PSTRING      FullTargetName
                1,                          // USHORT       TargetNameOffset
                NULL,                       // PSTRING      StreamName OPTIONAL
                NULL,                       // PSTRING      NormalizedParentName OPTIONAL
                FILE_NOTIFY_CHANGE_NAME,    // ULONG        FilterMatch
                0,                          // ULONG        Action
                NULL                        // PVOID        TargetContext
                );
        */

    } __finally {

        if (bFcbAcquired) {
            ExReleaseResourceLite(&Fcb->MainResource);
        }

        if (!IrpContext->ExceptionInProgress) {
            if (CompleteRequest) {
                if (Status == STATUS_PENDING) {
                    Ext2QueueRequest(IrpContext);
                } else {
                    Ext2CompleteIrpContext(IrpContext, Status);
                }
            } else {
                IrpContext->Irp = NULL;
                Ext2CompleteIrpContext(IrpContext, Status);
            }
        }
    }

    return Status;
}

VOID
Ext2NotifyReportChange (
    IN PEXT2_IRP_CONTEXT IrpContext,
    IN PEXT2_VCB         Vcb,
    IN PEXT2_MCB         Mcb,
    IN ULONG             Filter,
    IN ULONG             Action   )
{
    USHORT          Offset;

    Offset = (USHORT) ( Mcb->FullName.Length -
                        Mcb->ShortName.Length);

    FsRtlNotifyFullReportChange( Vcb->NotifySync,
                                 &(Vcb->NotifyList),
                                 (PSTRING) (&Mcb->FullName),
                                 (USHORT) Offset,
                                 (PSTRING)NULL,
                                 (PSTRING) NULL,
                                 (ULONG) Filter,
                                 (ULONG) Action,
                                 (PVOID) NULL );

    // ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
}


NTSTATUS
Ext2DirectoryControl (IN PEXT2_IRP_CONTEXT IrpContext)
{
    NTSTATUS Status;

    ASSERT(IrpContext);

    ASSERT((IrpContext->Identifier.Type == EXT2ICX) &&
           (IrpContext->Identifier.Size == sizeof(EXT2_IRP_CONTEXT)));

    switch (IrpContext->MinorFunction) {

    case IRP_MN_QUERY_DIRECTORY:
        Status = Ext2QueryDirectory(IrpContext);
        break;

    case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
        Status = Ext2NotifyChangeDirectory(IrpContext);
        break;

    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        Ext2CompleteIrpContext(IrpContext, Status);
    }

    return Status;
}


BOOLEAN
Ext2IsDirectoryEmpty (
    PEXT2_IRP_CONTEXT   IrpContext,
    PEXT2_VCB           Vcb,
    PEXT2_MCB           Mcb
)
{
    if (!IsMcbDirectory(Mcb) || IsMcbSymLink(Mcb)) {
        return TRUE;
    }

    return !!ext3_is_dir_empty(IrpContext, &Mcb->Inode);
}