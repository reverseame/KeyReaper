#ifndef KEYREAPER_WIN_NT_HEAP_H
#define KEYREAPER_WIN_NT_HEAP_H

#include <windows.h>

// SOURCES
//  https://www.nirsoft.net/kernel_struct/vista/
//  https://www.vergiliusproject.com/kernels/x86/windows-7/rtm/_HEAP_ENTRY

namespace nt_heap {

typedef struct _HEAP_ENTRY
{
  union
  {
    struct
    {
      USHORT Size;                                                    //0x0
      UCHAR Flags;                                                    //0x2
      UCHAR SmallTagIndex;                                            //0x3
    };
    struct
    {
      VOID* volatile SubSegmentCode;                                  //0x0
      USHORT PreviousSize;                                            //0x4
      union
      {
        UCHAR SegmentOffset;                                        //0x6
        UCHAR LFHFlags;                                             //0x6
      };
      UCHAR UnusedBytes;                                              //0x7
    };
    struct
    {
      USHORT FunctionIndex;                                           //0x0
      USHORT ContextValue;                                            //0x2
    };
    struct
    {
      ULONG InterceptorValue;                                         //0x0
      USHORT UnusedBytesLength;                                       //0x4
      UCHAR EntryOffset;                                              //0x6
      UCHAR ExtendedBlockSignature;                                   //0x7
    };
    struct
    {
      ULONG Code1;                                                    //0x0
      USHORT Code2;                                                   //0x4
      UCHAR Code3;                                                    //0x6
      UCHAR Code4;                                                    //0x7
    };
    ULONGLONG AgregateCode;                                             //0x0
  };
} HEAP_ENTRY, *PHEAP_ENTRY;

typedef struct _HEAP_TAG_ENTRY
{
  ULONG Allocs;
  ULONG Frees;
  ULONG Size;
  WORD TagIndex;
  WORD CreatorBackTraceIndex;
  WCHAR TagName[24];
} HEAP_TAG_ENTRY, *PHEAP_TAG_ENTRY;

typedef struct _HEAP_PSEUDO_TAG_ENTRY
{
  ULONG Allocs;
  ULONG Frees;
  ULONG Size;
} HEAP_PSEUDO_TAG_ENTRY, *PHEAP_PSEUDO_TAG_ENTRY;

typedef struct _HEAP_LOCK
{
  ULONG Lock;
} HEAP_LOCK, *PHEAP_LOCK;

typedef struct _HEAP_TUNING_PARAMETERS
{
  ULONG CommittThresholdShift;
  ULONG MaxPreCommittThreshold;
} HEAP_TUNING_PARAMETERS, *PHEAP_TUNING_PARAMETERS;


typedef struct _HEAP_COUNTERS
{
  ULONG TotalMemoryReserved;
  ULONG TotalMemoryCommitted;
  ULONG TotalMemoryLargeUCR;
  ULONG TotalSizeInVirtualBlocks;
  ULONG TotalSegments;
  ULONG TotalUCRs;
  ULONG CommittOps;
  ULONG DeCommitOps;
  ULONG LockAcquires;
  ULONG LockCollisions;
  ULONG CommitRate;
  ULONG DecommittRate;
  ULONG CommitFailures;
  ULONG InBlockCommitFailures;
  ULONG CompactHeapCalls;
  ULONG CompactedUCRs;
  ULONG InBlockDeccommits;
  ULONG InBlockDeccomitSize;
} HEAP_COUNTERS, *PHEAP_COUNTERS;

struct _HEAP;
typedef struct _HEAP
{
  HEAP_ENTRY Entry;
  ULONG SegmentSignature;
  ULONG SegmentFlags;
  LIST_ENTRY SegmentListEntry;
  _HEAP *Heap;
  PVOID BaseAddress;
  ULONG NumberOfPages;
  PHEAP_ENTRY FirstEntry;
  PHEAP_ENTRY LastValidEntry;
  ULONG NumberOfUnCommittedPages;
  ULONG NumberOfUnCommittedRanges;
  WORD SegmentAllocatorBackTraceIndex;
  WORD Reserved;
  LIST_ENTRY UCRSegmentList;
  ULONG Flags;
  ULONG ForceFlags;
  ULONG CompatibilityFlags;
  ULONG EncodeFlagMask;
  HEAP_ENTRY Encoding;
  ULONG PointerKey;
  ULONG Interceptor;
  ULONG VirtualMemoryThreshold;
  ULONG Signature;
  ULONG SegmentReserve;
  ULONG SegmentCommit;
  ULONG DeCommitFreeBlockThreshold;
  ULONG DeCommitTotalFreeThreshold;
  ULONG TotalFreeSize;
  ULONG MaximumAllocationSize;
  WORD ProcessHeapsListIndex;
  WORD HeaderValidateLength;
  PVOID HeaderValidateCopy;
  WORD NextAvailableTagIndex;
  WORD MaximumTagIndex;
  PHEAP_TAG_ENTRY TagEntries;
  LIST_ENTRY UCRList;
  ULONG AlignRound;
  ULONG AlignMask;
  LIST_ENTRY VirtualAllocdBlocks;
  LIST_ENTRY SegmentList;
  WORD AllocatorBackTraceIndex;
  ULONG NonDedicatedListLength;
  PVOID BlocksIndex;
  PVOID UCRIndex;
  PHEAP_PSEUDO_TAG_ENTRY PseudoTagEntries;
  LIST_ENTRY FreeLists;
  PHEAP_LOCK LockVariable;
  LONG * CommitRoutine;
  PVOID FrontEndHeap;
  WORD FrontHeapLockCount;
  UCHAR FrontEndHeapType;
  HEAP_COUNTERS Counters;
  HEAP_TUNING_PARAMETERS TuningParameters;
} HEAP, *PHEAP;

typedef struct _HEAP_SEGMENT {
  HEAP_ENTRY Entry;
  ULONG SegmentSignature;
  ULONG SegmentFlags;
  LIST_ENTRY SegmentListEntry;
  PHEAP Heap;
  PVOID BaseAddress;
  ULONG NumberOfPages;
  PHEAP_ENTRY FirstEntry;
  PHEAP_ENTRY LastValidEntry;
  ULONG NumberOfUnCommittedPages;
  ULONG NumberOfUnCommittedRanges;
  WORD SegmentAllocatorBackTraceIndex;
  WORD Reserved;
  LIST_ENTRY UCRSegmentList;
} HEAP_SEGMENT, *PHEAP_SEGMENT;

} // namespace nt_heap
#endif // KEYREAPER_WIN_NT_HEAP_H