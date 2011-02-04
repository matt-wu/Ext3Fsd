#ifndef _ENUM_DISK_INCLUDE_
#define _ENUM_DISK_INCLUDE_

#include "ntdll.h"
#include <objbase.h>
#include <initguid.h>
#include <devioctl.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <regstr.h>
#include <winsvc.h>
#include "mountmgr.h"
#include "dbt.h"
#include "ext2fs.h"
#include <winioctl.h>

/*
 *  system definitions
 */

#define USING_IOCTL_EX TRUE

#if (USING_IOCTL_EX)

#if !defined(_M_AMD64)

//
// Support for GUID Partition Table (GPT) disks.
//

//
// There are currently two ways a disk can be partitioned. With a traditional
// AT-style master boot record (PARTITION_STYLE_MBR) and with a new, GPT
// partition table (PARTITION_STYLE_GPT). RAW is for an unrecognizable
// partition style. There are a very limited number of things you can
// do with a RAW partititon.
//

typedef enum _PARTITION_STYLE {
    PARTITION_STYLE_MBR,
    PARTITION_STYLE_GPT,
    PARTITION_STYLE_RAW
} PARTITION_STYLE;


//
// The following structure defines information in a GPT partition that is
// not common to both GPT and MBR partitions.
//

typedef struct _PARTITION_INFORMATION_GPT {
    GUID PartitionType;                 // Partition type. See table 16-3.
    GUID PartitionId;                   // Unique GUID for this partition.
    DWORD64 Attributes;                 // See table 16-4.
    WCHAR Name [36];                    // Partition Name in Unicode.
} PARTITION_INFORMATION_GPT, *PPARTITION_INFORMATION_GPT;

//
//  The following are GPT partition attributes applicable for any
//  partition type. These attributes are not OS-specific
//

#define GPT_ATTRIBUTE_PLATFORM_REQUIRED             (0x0000000000000001)

//
// The following are GPT partition attributes applicable when the
// PartitionType is PARTITION_BASIC_DATA_GUID.
//

#define GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER    (0x8000000000000000)
#define GPT_BASIC_DATA_ATTRIBUTE_HIDDEN             (0x4000000000000000)
#define GPT_BASIC_DATA_ATTRIBUTE_READ_ONLY          (0x1000000000000000)

//
// The following structure defines information in an MBR partition that is not
// common to both GPT and MBR partitions.
//

typedef struct _PARTITION_INFORMATION_MBR {
    BYTE  PartitionType;
    BOOLEAN BootIndicator;
    BOOLEAN RecognizedPartition;
    DWORD HiddenSectors;
} PARTITION_INFORMATION_MBR, *PPARTITION_INFORMATION_MBR;


//
// The structure SET_PARTITION_INFO_EX is used with the ioctl
// IOCTL_SET_PARTITION_INFO_EX to set information about a specific
// partition. Note that for MBR partitions, you can only set the partition
// signature, whereas GPT partitions allow setting of all fields that
// you can get.
//

typedef SET_PARTITION_INFORMATION SET_PARTITION_INFORMATION_MBR;
typedef PARTITION_INFORMATION_GPT SET_PARTITION_INFORMATION_GPT;


typedef struct _SET_PARTITION_INFORMATION_EX {
    PARTITION_STYLE PartitionStyle;
    union {
        SET_PARTITION_INFORMATION_MBR Mbr;
        SET_PARTITION_INFORMATION_GPT Gpt;
    };
} SET_PARTITION_INFORMATION_EX, *PSET_PARTITION_INFORMATION_EX;


//
// The structure CREATE_DISK_GPT with the ioctl IOCTL_DISK_CREATE_DISK
// to initialize an virgin disk with an empty GPT partition table.
//

typedef struct _CREATE_DISK_GPT {
    GUID DiskId;                    // Unique disk id for the disk.
    DWORD MaxPartitionCount;        // Maximim number of partitions allowable.
} CREATE_DISK_GPT, *PCREATE_DISK_GPT;

//
// The structure CREATE_DISK_MBR with the ioctl IOCTL_DISK_CREATE_DISK
// to initialize an virgin disk with an empty MBR partition table.
//

typedef struct _CREATE_DISK_MBR {
    DWORD Signature;
} CREATE_DISK_MBR, *PCREATE_DISK_MBR;


typedef struct _CREATE_DISK {
    PARTITION_STYLE PartitionStyle;
    union {
        CREATE_DISK_MBR Mbr;
        CREATE_DISK_GPT Gpt;
    };
} CREATE_DISK, *PCREATE_DISK;


//
// The structure GET_LENGTH_INFORMATION is used with the ioctl
// IOCTL_DISK_GET_LENGTH_INFO to obtain the length, in bytes, of the
// disk, partition, or volume.
//

typedef struct _GET_LENGTH_INFORMATION {
    LARGE_INTEGER   Length;
} GET_LENGTH_INFORMATION, *PGET_LENGTH_INFORMATION;

//
// The PARTITION_INFORMATION_EX structure is used with the
// IOCTL_DISK_GET_DRIVE_LAYOUT_EX, IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
// IOCTL_DISK_GET_PARTITION_INFO_EX and IOCTL_DISK_GET_PARTITION_INFO_EX calls.
//

typedef struct _PARTITION_INFORMATION_EX {
    PARTITION_STYLE PartitionStyle;
    LARGE_INTEGER StartingOffset;
    LARGE_INTEGER PartitionLength;
    DWORD PartitionNumber;
    BOOLEAN RewritePartition;
    union {
        PARTITION_INFORMATION_MBR Mbr;
        PARTITION_INFORMATION_GPT Gpt;
    };
} PARTITION_INFORMATION_EX, *PPARTITION_INFORMATION_EX;


//
// GPT specific drive layout information.
//

typedef struct _DRIVE_LAYOUT_INFORMATION_GPT {
    GUID DiskId;
    LARGE_INTEGER StartingUsableOffset;
    LARGE_INTEGER UsableLength;
    DWORD MaxPartitionCount;
} DRIVE_LAYOUT_INFORMATION_GPT, *PDRIVE_LAYOUT_INFORMATION_GPT;


//
// MBR specific drive layout information.
//

typedef struct _DRIVE_LAYOUT_INFORMATION_MBR {
    DWORD Signature;
} DRIVE_LAYOUT_INFORMATION_MBR, *PDRIVE_LAYOUT_INFORMATION_MBR;

//
// The structure DRIVE_LAYOUT_INFORMATION_EX is used with the
// IOCTL_SET_DRIVE_LAYOUT_EX and IOCTL_GET_DRIVE_LAYOUT_EX calls.
//

typedef struct _DRIVE_LAYOUT_INFORMATION_EX {
    DWORD PartitionStyle;
    DWORD PartitionCount;
    union {
        DRIVE_LAYOUT_INFORMATION_MBR Mbr;
        DRIVE_LAYOUT_INFORMATION_GPT Gpt;
    };
    PARTITION_INFORMATION_EX PartitionEntry[1];
} DRIVE_LAYOUT_INFORMATION_EX, *PDRIVE_LAYOUT_INFORMATION_EX;

#endif /* !defined(_M_AMD64) */

//
// New IOCTLs for GUID Partition tabled disks.
//

#define IOCTL_DISK_GET_PARTITION_INFO_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0012, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_SET_PARTITION_INFO_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0013, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_GET_DRIVE_LAYOUT_EX      CTL_CODE(IOCTL_DISK_BASE, 0x0014, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_SET_DRIVE_LAYOUT_EX      CTL_CODE(IOCTL_DISK_BASE, 0x0015, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_CREATE_DISK              CTL_CODE(IOCTL_DISK_BASE, 0x0016, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_GET_LENGTH_INFO          CTL_CODE(IOCTL_DISK_BASE, 0x0017, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_DISK_GET_DRIVE_GEOMETRY_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0028, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DISK_GET_DRIVE_LAYOUT_EXT    IOCTL_DISK_GET_DRIVE_LAYOUT_EX
#define IOCTL_DISK_SET_DRIVE_LAYOUT_EXT    IOCTL_DISK_SET_DRIVE_LAYOUT_EX
#define PARTITION_INFORMATION_EXT PARTITION_INFORMATION_EX
#define PPARTITION_INFORMATION_EXT PARTITION_INFORMATION_EX *
#define DRIVE_LAYOUT_INFORMATION_EXT DRIVE_LAYOUT_INFORMATION_EX
#define PDRIVE_LAYOUT_INFORMATION_EXT DRIVE_LAYOUT_INFORMATION_EX *

#else

#define IOCTL_DISK_GET_DRIVE_LAYOUT_EXT    IOCTL_DISK_GET_DRIVE_LAYOUT
#define IOCTL_DISK_SET_DRIVE_LAYOUT_EXT    IOCTL_DISK_SET_DRIVE_LAYOUT
typedef PARTITION_INFORMATION PARTITION_INFORMATION_EXT, *PPARTITION_INFORMATION_EXT;
typedef DRIVE_LAYOUT_INFORMATION DRIVE_LAYOUT_INFORMATION_EXT, *PDRIVE_LAYOUT_INFORMATION_EXT;

#endif // USING_IOCTL_EX


#define FILE_REMOVABLE_MEDIA            0x00000001
#define FILE_READ_ONLY_DEVICE           0x00000002
#define FILE_FLOPPY_DISKETTE            0x00000004
#define FILE_WRITE_ONCE_MEDIA           0x00000008
#define FILE_REMOTE_DEVICE              0x00000010
#define FILE_DEVICE_IS_MOUNTED          0x00000020
#define FILE_VIRTUAL_VOLUME             0x00000040
#define FILE_AUTOGENERATED_DEVICE_NAME  0x00000080
#define FILE_DEVICE_SECURE_OPEN         0x00000100

#define IOCTL_STORAGE_QUERY_PROPERTY   CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* storeage query type */
typedef enum _STORAGE_QUERY_TYPE {
    PropertyStandardQuery = 0,
    PropertyExistsQuery,
    PropertyMaskQuery,
    PropertyQueryMaxDefined
} STORAGE_QUERY_TYPE, *PSTORAGE_QUERY_TYPE;

/* storage property id */
typedef enum _STORAGE_PROPERTY_ID {
    StorageDeviceProperty = 0,
    StorageAdapterProperty
} STORAGE_PROPERTY_ID, *PSTORAGE_PROPERTY_ID;

/* storage property query */
typedef struct _STORAGE_PROPERTY_QUERY {
    STORAGE_PROPERTY_ID PropertyId;
    STORAGE_QUERY_TYPE QueryType;
    UCHAR AdditionalParameters[1];
} STORAGE_PROPERTY_QUERY, *PSTORAGE_PROPERTY_QUERY;


/* storage device descriptor */
typedef struct _STORAGE_DEVICE_DESCRIPTOR {
    ULONG Version;
    ULONG Size;
    UCHAR DeviceType;
    UCHAR DeviceTypeModifier;
    BOOLEAN RemovableMedia;
    BOOLEAN CommandQueueing;
    ULONG VendorIdOffset;
    ULONG ProductIdOffset;
    ULONG ProductRevisionOffset;
    ULONG SerialNumberOffset;
    STORAGE_BUS_TYPE BusType;
    ULONG RawPropertiesLength;
    UCHAR RawDeviceProperties[512];
} STORAGE_DEVICE_DESCRIPTOR, *PSTORAGE_DEVICE_DESCRIPTOR;

//
// Adapter properties
//
// This descriptor can be retrieved from a target device object of from the
// device object for the bus.  Retrieving from the target device object will
// forward the request to the underlying bus
//

typedef struct _STORAGE_ADAPTER_DESCRIPTOR {

    ULONG Version;

    ULONG Size;

    ULONG MaximumTransferLength;

    ULONG MaximumPhysicalPages;

    ULONG AlignmentMask;

    BOOLEAN AdapterUsesPio;

    BOOLEAN AdapterScansDown;

    BOOLEAN CommandQueueing;

    BOOLEAN AcceleratedTransfer;

    BOOLEAN BusType;

    USHORT BusMajorVersion;

    USHORT BusMinorVersion;

} STORAGE_ADAPTER_DESCRIPTOR, *PSTORAGE_ADAPTER_DESCRIPTOR;


//
// Bus Type
//

static char* BusType[] = {
    "UNKNOWN",  // 0x00
    "SCSI",
    "ATAPI",
    "ATA",
    "IEEE 1394",
    "SSA",
    "FIBRE",
    "USB",
    "RAID"
};

//
// SCSI Device Type
//

static char* DeviceType[] = {
    "Direct Access Device", // 0x00
    "Tape Device",          // 0x01
    "Printer Device",       // 0x02
    "Processor Device",     // 0x03
    "WORM Device",          // 0x04
    "CDROM Device",         // 0x05
    "Scanner Device",       // 0x06
    "Optical Disk",         // 0x07
    "Media Changer",        // 0x08
    "Comm. Device",         // 0x09
    "ASCIT8",               // 0x0A
    "ASCIT8",               // 0x0B
    "Array Device",         // 0x0C
    "Enclosure Device",     // 0x0D
    "RBC Device",           // 0x0E
    "Unknown Device"        // 0x0F
};


/*
 * IFS format callbacks
 */

//
// Output command
//
typedef struct {
    DWORD Lines;
    PCHAR Output;
} TEXTOUTPUT, *PTEXTOUTPUT;

//
// Callback command types
//
typedef enum {
    PROGRESS,
    DONEWITHSTRUCTURE,
    UNKNOWN2,
    UNKNOWN3,
    UNKNOWN4,
    UNKNOWN5,
    INSUFFICIENTRIGHTS,
    UNKNOWN7,
    UNKNOWN8,
    UNKNOWN9,
    UNKNOWNA,
    DONE,
    UNKNOWNC,
    UNKNOWND,
    OUTPUT,
    STRUCTUREPROGRESS
} CALLBACKCOMMAND;

/*
 *  ext2 codepages
 */

extern CHAR * gCodepages[];

//
// FMIFS callback definition
//
typedef BOOLEAN (__stdcall *PFMIFSCALLBACK)( CALLBACKCOMMAND Command, DWORD SubAction, PVOID ActionInfo );

//
// Chkdsk command in FMIFS
//
typedef VOID (__stdcall *PCHKDSK)( PWCHAR DriveRoot,
                                   PWCHAR Format,
                                   BOOL CorrectErrors,
                                   BOOL Verbose,
                                   BOOL CheckOnlyIfDirty,
                                   BOOL ScanDrive,
                                   PVOID Unused2,
                                   PVOID Unused3,
                                   PFMIFSCALLBACK Callback );

//
// Format command in FMIFS
//

// media flags
#define FMIFS_HARDDISK 0xC
#define FMIFS_FLOPPY   0x8

typedef VOID (__stdcall *PFORMATEX)( PWCHAR DriveRoot,
                                     DWORD MediaFlag,
                                     PWCHAR Format,
                                     PWCHAR Label,
                                     BOOL QuickFormat,
                                     DWORD ClusterSize,
                                     PFMIFSCALLBACK Callback );

#include "..\ext3fsd\include\common.h"

/*
 * structure definitions
 */

typedef struct _EXT2_PARTITION *PEXT2_PARTITION;

typedef struct _EXT2_DISK {

    ULONG               Magic;
    ULONG               Null;
    CHAR                Name[256];
    ULONGLONG           Size;

    BOOLEAN             bEjected;
    BOOLEAN             bLoaded;
    BOOLEAN             IsFile;
    UCHAR               OrderNo;
    UCHAR               NumParts;
    UCHAR               ExtStart;
    DISK_GEOMETRY       DiskGeometry;
    STORAGE_DEVICE_DESCRIPTOR   SDD;
    STORAGE_ADAPTER_DESCRIPTOR  SAD;
    PDRIVE_LAYOUT_INFORMATION_EXT Layout;

    PEXT2_PARTITION     DataParts;
} EXT2_DISK, *PEXT2_DISK;

#define EXT2_DISK_MAGIC      'EDSK'
#define EXT2_DISK_NULL_MAGIC 'ENUL'

typedef struct _EXT2_CDROM {
    ULONG               Magic[2];
    CHAR                Name[256];
    ULONGLONG           Size;

    UCHAR               OrderNo;
    BOOLEAN             bLoaded;
    BOOLEAN             bEjected;
    BOOLEAN             bIsDVD;
    ULONGLONG           DrvLetters;

    DISK_GEOMETRY       DiskGeometry;
    STORAGE_DEVICE_DESCRIPTOR   SDD;
    STORAGE_ADAPTER_DESCRIPTOR  SAD;
    EXT2_VOLUME_PROPERTY2       EVP;
} EXT2_CDROM, *PEXT2_CDROM;

#define EXT2_CDROM_DEVICE_MAGIC 'ECDR'
#define EXT2_CDROM_VOLUME_MAGIC 'ECDV'


typedef struct _EXT2_VOLUME {
    ULONG                   Magic;
    struct _EXT2_VOLUME *   Next;
    CHAR                    Name[REGSTR_VAL_MAX_HCID_LEN];
    ULONGLONG               DrvLetters;
    BOOLEAN                 bRecognized;
    BOOLEAN                 bDynamic;
    PVOLUME_DISK_EXTENTS    Extent;
    NT::FILE_FS_DEVICE_INFORMATION FsdInfo;
    NT::FILE_FS_SIZE_INFORMATION   FssInfo;
    union {
        NT::FILE_FS_ATTRIBUTE_INFORMATION FsaInfo;
        CHAR _tmp_alinged_buf[MAX_PATH];
    };
    CHAR                    FileSystem[64];
    EXT2_VOLUME_PROPERTY2   EVP;
    PEXT2_PARTITION         Part;
} EXT2_VOLUME, *PEXT2_VOLUME;

#define EXT2_VOLUME_MAGIC 'EVOL'

typedef struct _EXT2_PARTITION {
    ULONG                   Magic;
    UCHAR                   Number;
    PEXT2_DISK              Disk;
    PPARTITION_INFORMATION_EXT  Entry;
    ULONGLONG               DrvLetters;
    PEXT2_VOLUME            Volume;
    CHAR                    Name[REGSTR_VAL_MAX_HCID_LEN];
} EXT2_PARTITION;
#define EXT2_PART_MAGIC 'EPRT'

typedef struct _EXT2_LETTER {

    UCHAR               Letter;
    BOOLEAN             bUsed;
    BOOLEAN             bTemporary;
    UINT                DrvType;

    PVOLUME_DISK_EXTENTS    Extent;
    PSTORAGE_DEVICE_NUMBER  SDN;

    CHAR                SymLink[MAX_PATH];
} EXT2_LETTER, *PEXT2_LETTER;


/*
 * global definitions
 */

extern BOOLEAN g_bAutoMount;
extern ULONG g_nFlps;
extern ULONG g_nDisks;
extern ULONG g_nCdroms;
extern ULONG g_nVols;

extern EXT2_LETTER drvLetters[26];
extern EXT2_LETTER drvDigits[10];

extern PEXT2_DISK      gDisks;
extern PEXT2_CDROM     gCdroms;
extern PEXT2_VOLUME    gVols;


/*
 * routines definitions
 */

char *PartitionString(int type);
char *DriveTypeString(UINT type);
char *DeviceTypeString(DEVICE_TYPE type);
char *BusTypeString(STORAGE_BUS_TYPE BusType);


BOOLEAN IsVista();

BOOLEAN
IsWindows2000();

#define EXT2_DESIRED_ACCESS (GENERIC_READ)

NT::NTSTATUS
Ext2Open(
    PCHAR               FileName,
    PHANDLE             Handle,
    ULONG               DesiredAccess
);

VOID
Ext2Close(HANDLE*   Handle);

NT::NTSTATUS
Ext2WriteDisk(
    HANDLE              Handle,
    BOOLEAN             IsFile,
    ULONG               SectorSize,
    ULONGLONG           Offset,
    ULONG               Length,
    PVOID               Buffer
);

NT::NTSTATUS
Ext2Read(
    IN  HANDLE          Handle,
    IN  BOOLEAN         IsFile,
    IN  ULONG           SectorSize,
    IN  ULONGLONG       Offset,
    IN  ULONG           Length,
    IN  PVOID           Buffer
);

NTSTATUS
Ext2QueryDisk(
    HANDLE              Handle,
    PDISK_GEOMETRY      DiskGeometry
);

PVOLUME_DISK_EXTENTS
Ext2QueryVolumeExtents(
    HANDLE              hVolume
);

PVOLUME_DISK_EXTENTS
Ext2QueryDriveExtents(
    CHAR                DriveLetter
);

BOOLEAN
Ext2QueryDrvLetter(
    PEXT2_LETTER    drvLetter
);

NTSTATUS
Ext2QueryMediaType(
    HANDLE              Handle,
    PDWORD              MediaType
);

NT::NTSTATUS
Ext2QueryProperty(
    HANDLE              Handle,
    STORAGE_PROPERTY_ID Id,
    PVOID               DescBuf,
    ULONG               DescSize
);

PDRIVE_LAYOUT_INFORMATION_EXT
Ext2QueryDriveLayout(
    HANDLE              Handle,
    PUCHAR              NumOfParts
);

NTSTATUS
Ext2SetDriveLayout(
    HANDLE  Handle,
    PDRIVE_LAYOUT_INFORMATION_EXT Layout
);

BOOLEAN
Ext2SetPartitionType(
    PEXT2_PARTITION Part,
    BYTE            Type
);

PEXT2_PARTITION
Ext2QueryVolumePartition(
    PEXT2_VOLUME    Volume
);

BOOLEAN
Ext2FlushVolume(CHAR *Device);

BOOLEAN
Ext2QuerySysConfig();

BOOLEAN
Ext2CompareExtents(
    PVOLUME_DISK_EXTENTS ext1,
    PVOLUME_DISK_EXTENTS ext2
);

ULONGLONG
Ext2QueryVolumeDrvLetters(PEXT2_VOLUME Volume);

VOID
Ext2QueryVolumeDisks(PEXT2_VOLUME Volume);

ULONGLONG
Ext2QueryCdromDrvLetters(PEXT2_CDROM Cdrom);

BOOLEAN
Ext2QueryExt2Property (
    HANDLE                      Handle,
    PEXT2_VOLUME_PROPERTY2      EVP
);

BOOLEAN
Ext2QueryPerfStat (
    HANDLE                      Handle,
    PEXT2_QUERY_PERFSTAT        Stat,
    PEXT2_PERF_STATISTICS_V1   *PerfV1,
    PEXT2_PERF_STATISTICS_V2   *PerfV2
);

BOOLEAN Ext2IsNullUuid (__u8 * uuid);
BOOLEAN
Ext2CheckVolumeRegistryProperty(
    PEXT2_VOLUME_PROPERTY2 EVP
);

VOID
Ext2SetDefaultVolumeRegistryProperty(
    PEXT2_VOLUME_PROPERTY2 EVP
);

VOID
Ext2StorePropertyinRegistry(
    PEXT2_VOLUME_PROPERTY2 EVP
);

BOOLEAN
Ext2SetExt2Property (
    HANDLE                Handle,
    PEXT2_VOLUME_PROPERTY2 EVP
);

BOOLEAN
Ext2QueryGlobalProperty(
    ULONG *     ulStartup,
    BOOLEAN *   bReadonly,
    BOOLEAN *   bExt3Writable,
    CHAR *      Codepage,
    CHAR *      sPrefix,
    CHAR *      sSuffix,
    BOOLEAN *   bAutoMount
);

INT
Ext2QueryDrvVersion(
    CHAR *      Version,
    CHAR *      Date,
    CHAR *      Time
);

BOOLEAN
Ext2SetGlobalProperty (
    ULONG       ulStartup,
    BOOLEAN     bReadonly,
    BOOLEAN     bExt3Writable,
    CHAR *      Codepage,
    CHAR *      sPrefix,
    CHAR *      sSuffix,
    BOOLEAN     bAutoMount
);

BOOLEAN
Ext2IsServiceStarted();

BOOLEAN
Ext2StartService();

CString
Ext2SysInformation();

BOOLEAN
Ext2LoadDisks();

VOID
Ext2CleanupDisks();

BOOLEAN
Ext2LoadCdroms();

VOID
Ext2LoadCdromDrvLetters();

VOID
Ext2CleanupCdroms();

BOOLEAN
Ext2LoadDiskPartitions(PEXT2_DISK Disk);

VOID
Ext2LoadAllDiskPartitions();

VOID
Ext2MountingVolumes();

BOOLEAN
Ext2LoadVolumes();

VOID
Ext2LoadAllVolumeDrvLetters();

BOOLEAN
Ext2LoadRemovableVolumes();

CString
Ext2QueryVolumeLetterStrings(
    ULONGLONG       letters,
    PEXT2_LETTER *  first
);

VOID
Ext2RefreshVLVI(
    CListCtrl *List,
    PEXT2_VOLUME chain,
    int  nItem
);

VOID
Ext2InsertVolume(
    CListCtrl *List,
    PEXT2_VOLUME chain
);

VOID
Ext2RefreshVLCD(
    CListCtrl *List,
    PEXT2_CDROM Cdrom,
    int nItem
);

VOID
Ext2InsertCdromAsVolume(
    CListCtrl *List,
    PEXT2_CDROM Cdrom
);


VOID
Ext2RefreshVolumeList(CListCtrl *List);

VOID
Ext2RefreshDVPT(
    CListCtrl*      List,
    PEXT2_PARTITION Part,
    int nItem
);

VOID
Ext2InsertPartition(
    CListCtrl*      List,
    PEXT2_DISK      Disk,
    PEXT2_PARTITION Part
);

VOID
Ext2InsertDisk(
    CListCtrl *List,
    PEXT2_DISK Disk
);

VOID
Ext2RefreshDVCM(
    CListCtrl *List,
    PEXT2_CDROM Cdrom,
    int nItem
);

VOID
Ext2InsertCdromAsDisk(
    CListCtrl *List,
    PEXT2_CDROM Cdrom
);

VOID
Ext2RefreshDiskList(CListCtrl *List);

VOID
Ext2CleanupVolumes();

VOID
Ext2LoadDrvLetter(PEXT2_LETTER drvLetter, CHAR cLetter);

VOID
Ext2LoadDrvLetters();

VOID
Ext2CleanDrvLetter(PEXT2_LETTER drvLetter);

VOID
Ext2CleanupDrvLetters();

BOOLEAN
Ext2RemoveDrvLetter(
    PEXT2_LETTER   drvLetter
);

CHAR
Ext2QueryRegistryMountPoint (
    CHAR * devName
);

BOOLEAN
Ext2SetRegistryMountPoint (
    CHAR * dosPath,
    CHAR * devName,
    BOOLEAN bSet
);

BOOL
Ext2InsertMountPoint(
    CHAR * volume,
    UCHAR drvChar,
    BOOL  bGlobal
);

VOID
Ext2UpdateDrvLetter(
    PEXT2_LETTER   drvLetter,
    PCHAR          devPath
);

BOOLEAN
Ext2AssignDrvLetter(
    PEXT2_LETTER   drvLetter,
    PCHAR          devPath,
    BOOLEAN        bPermanent
);

VOID
Ext2RemoveMountPoint(
    PEXT2_LETTER    drvLetter,
    BOOLEAN         bPermanent
);

BOOLEAN
Ext2SetVolumeMountPoint (
    CHAR * dosPath,
    CHAR * devName
);

UCHAR
Ext2QueryMountPoint(
    CHAR *      volume
);

BOOL
Ext2RefreshVolumePoint(
    CHAR *          volume,
    UCHAR           drvChar
);

BOOL
Ext2NotifyVolumePoint(
    PEXT2_VOLUME    volume,
    UCHAR           drvChar
);

BOOL
Ext2VolumeArrivalNotify(PCHAR  VolumePath);

BOOL
Ext2SetAppAutorun(BOOL bInstall);

int
Ext2SetManagerAsService(BOOL bInstall);

extern BOOL g_bAutoRemoveDeadLetters;

VOID
Ext2AutoRemoveDeadLetters();

BOOLEAN
Ext2RemoveDosSymLink(CHAR drvChar);

#endif // _ENUM_DISK_INCLUDE_