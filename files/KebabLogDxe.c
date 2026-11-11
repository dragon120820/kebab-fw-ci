/** @file
  KebabLogDxe - a boot log that survives the crash.

  Why this exists
  ---------------
  Every attempt so far has ended with a black screen: the firmware prints a
  screenful of "Loading driver ..." lines and then dies, so the last thing we
  know is what was already on the panel when the panel itself went away.  The
  panel is not a logging channel - it is a debug print that disappears exactly
  when the interesting failure happens.

  This driver writes to flash instead.  It keeps a text log in RAM, records
  every newly loaded image (base address, entry point, size - the same numbers
  the firmware prints), and rewrites the log to the device's `kernel_log`
  partition once a second.  After a crash the log can be pulled back over 9008
  without the phone needing to boot:

      python rescue/rescue_flash.py read --lun 4 --start 547592 \
          --sectors 8 --out tmp/kernel_log.bin

  Design notes
  ------------
  * No filesystem: FAT mounting is later and more fragile than raw block I/O,
    and `kernel_log` is a partition nobody else is using right now (all zeros
    on this device).
  * The target disk is identified by geometry (LastBlock == 61753124, the UFS
    LUN4 size we audited from the 0485 log), not by handle order.  If the disk
    does not match, the driver refuses to write rather than scribbling on
    whatever else might be there.
  * Logging starts as soon as a candidate BlockIo shows up, so it covers the
    BDS/kernel-handover window - the part the panel cannot show.
  * Failure to find the disk or write is never fatal: this driver must not turn
    "no log" into "no boot".

  Copyright (c) 2026. SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/LoadedImage.h>

//
// `kernel_log` lives on UFS LUN4 (the boot/firmware LUN that also carries
// boot_a), first_lba 547592, 8096 sectors of 4096 bytes.  LUN0 is the 229 GiB
// data LUN where userdata lives - do not confuse the two.
//
// The window below used to read 2300..2420 MiB, which silently never matched:
// LUN4 is 582037 * 4096 = 2,384,023,552 bytes = 2273.6 MiB, i.e. *below* the
// old minimum.  The driver skipped every disk and wrote nothing, so the first
// two flashes produced no log at all while looking perfectly healthy.  Keep
// the window straddling the real capacity, and keep it far from LUN0 (229 GiB).
//
#define KEBAB_LOG_LUN4_MIN         (2200ULL * 1024 * 1024)  /* 2273.6 MiB actual */
#define KEBAB_LOG_LUN4_MAX         (2340ULL * 1024 * 1024)  /* tolerate rounding */
#define KEBAB_LOG_BYTE_OFFSET      (547592ULL * 4096ULL)  /* start of `kernel_log` */
#define KEBAB_LOG_BYTES            (8ULL * 4096ULL)       /* 32 KiB of log          */
#define KEBAB_LOG_CAP              (KEBAB_LOG_BYTES - 256)
#define KEBAB_LOG_MAX_IMAGES       192

STATIC EFI_BLOCK_IO_PROTOCOL *mBlk = NULL;
STATIC CHAR8              *mBuf;
STATIC UINTN               mLen;
STATIC EFI_HANDLE          mSeen[KEBAB_LOG_MAX_IMAGES];
STATIC UINT64              mBase[KEBAB_LOG_MAX_IMAGES];
STATIC UINT64              mSize[KEBAB_LOG_MAX_IMAGES];
STATIC UINTN               mSeenCount;

//
// The panel is the only channel that survives this board's broken USB stack, so
// the driver also paints a small always-current map of the last few loaded
// images into the top rows of the console.  When a crash prints its registers
// we can then say which image the faulting address belongs to, instead of
// guessing from a partially visible backtrace.
//
#define KEBAB_LOG_HUD_ROWS  4

/**
  Append one line to the RAM log.  Never fails and never wraps mid-line: if the
  line does not fit, the log is simply cut here (the tail is the interesting
  part, so we stop rather than overwrite the beginning).
**/
STATIC
VOID
LogLine (
  IN CONST CHAR8  *Format,
  IN ...
  )
{
  VA_LIST  Marker;
  UINTN    Left;

  if ((mBuf == NULL) || (mLen >= KEBAB_LOG_CAP)) {
    return;
  }

  Left = KEBAB_LOG_CAP - mLen;
  VA_START (Marker, Format);
  AsciiVSPrint (mBuf + mLen, Left, Format, Marker);
  VA_END (Marker);
  mLen = AsciiStrLen (mBuf);
  if (mLen < KEBAB_LOG_CAP) {
    mBuf[mLen++] = '\n';
    mBuf[mLen]   = 0;
  }
}

/**
  Rewrite the whole log to `kernel_log`.  Called from a TPL_APPLICATION timer,
  where block I/O is legal.
**/
STATIC
VOID
LogFlush (
  VOID
  )
{
  EFI_STATUS  Status;

  if ((mBlk == NULL) || (mBuf == NULL) || (mLen == 0)) {
    return;
  }

  ZeroMem (mBuf + mLen, KEBAB_LOG_CAP + 256 - mLen);
  Status = mBlk->WriteBlocks (
                   mBlk,
                   mBlk->Media->MediaId,
                   KEBAB_LOG_BYTE_OFFSET / mBlk->Media->BlockSize,
                   KEBAB_LOG_BYTES,
                   mBuf
                   );
  if (EFI_ERROR (Status)) {
    /* Do not spam: the next tick tries again anyway. */
    DEBUG ((DEBUG_WARN, "KebabLog: WriteBlocks failed - %r\n", Status));
  }
}

/**
  Record an image that has not been seen before.  The base and entry point are
  printed the same way the firmware's own "Loading driver at ... EntryPoint=..."
  lines print them, so a log line can be matched against a screen photo.
**/
STATIC
VOID
LogImage (
  IN EFI_HANDLE  Handle
  )
{
  EFI_LOADED_IMAGE_PROTOCOL  *Image;
  EFI_STATUS                  Status;
  UINTN                       i;
  UINT32                      EntryOffset;
  UINT64                      Base;

  for (i = 0; i < mSeenCount; i++) {
    if (mSeen[i] == Handle) {
      return;
    }
  }

  Status = gBS->HandleProtocol (Handle, &gEfiLoadedImageProtocolGuid, (VOID **)&Image);
  if (EFI_ERROR (Status) || (Image->ImageBase == NULL)) {
    return;
  }

  EntryOffset = 0;
  Base        = (UINT64)(UINTN)Image->ImageBase;
  if ((Image->ImageSize > 0x40) && (((UINT8 *)Image->ImageBase)[0] == 'M') &&
      (((UINT8 *)Image->ImageBase)[1] == 'Z'))
  {
    UINT32  PeOff;
    CopyMem (&PeOff, (UINT8 *)Image->ImageBase + 0x3C, sizeof (PeOff));
    if ((PeOff + 0x2C < Image->ImageSize) &&
        (*(UINT32 *)((UINT8 *)Image->ImageBase + PeOff) == 0x00004550))
    {
      CopyMem (&EntryOffset, (UINT8 *)Image->ImageBase + PeOff + 0x28, sizeof (EntryOffset));
    }
  }

  if (mSeenCount < KEBAB_LOG_MAX_IMAGES) {
    mBase[mSeenCount] = Base;
    mSize[mSeenCount] = (UINT64)Image->ImageSize;
    mSeen[mSeenCount] = Handle;
    mSeenCount++;
  }

  LogLine ("IMG base=0x%lx entry=0x%lx size=0x%lx",
           Base, Base + EntryOffset, (UINT64)Image->ImageSize);
}

/**
  Redraw the top rows of the console with the most recently loaded images.
  Errors are ignored: a console that refuses to cooperate must not stop the boot.
**/
STATIC
VOID
PaintHud (
  VOID
  )
{
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *Con;
  EFI_SIMPLE_TEXT_OUTPUT_MODE      *Mode;
  CHAR16                            Line[80];
  UINTN                             Row;
  UINTN                             Start;
  UINTN                             i;
  INT32                             SavedColumn;
  INT32                             SavedRow;

  if ((gST == NULL) || (gST->ConOut == NULL)) {
    return;
  }

  Con  = gST->ConOut;
  Mode = Con->Mode;
  if (Mode == NULL) {
    return;
  }

  SavedColumn = Mode->CursorColumn;
  SavedRow    = Mode->CursorRow;

  Start = (mSeenCount > KEBAB_LOG_HUD_ROWS) ? (mSeenCount - KEBAB_LOG_HUD_ROWS) : 0;
  for (i = Start; i < mSeenCount; i++) {
    Row = i - Start;
    if (EFI_ERROR (Con->SetCursorPosition (Con, 0, (UINTN)Row))) {
      return;
    }

    UnicodeSPrint (Line, sizeof (Line), L"IMG %010lx %06lx %02d/%02d   ",
                   mBase[i], mSize[i], (UINT32)(i + 1), (UINT32)mSeenCount);
    Con->OutputString (Con, Line);
  }

  Con->SetCursorPosition (Con, (UINTN)SavedColumn, (UINTN)SavedRow);
}

STATIC
VOID
EFIAPI
OnTimer (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  *Handles;
  UINTN       Count;
  UINTN       i;
  UINTN       Before;

  Before = mSeenCount;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiLoadedImageProtocolGuid,
                  NULL,
                  &Count,
                  &Handles
                  );
  if (!EFI_ERROR (Status)) {
    for (i = 0; i < Count; i++) {
      LogImage (Handles[i]);
    }

    FreePool (Handles);
  }

  if (mSeenCount != Before) {
    LogFlush ();
  }

  PaintHud ();
}

STATIC
BOOLEAN
LooksLikeOurDisk (
  IN EFI_BLOCK_IO_PROTOCOL  *Blk
  )
{
  UINT64  Size;

  if (Blk->Media == NULL) {
    return FALSE;
  }

  if (Blk->Media->LogicalPartition || (Blk->Media->BlockSize == 0)) {
    return FALSE;
  }

  //
  // Identify the disk by its size, not by handle order: (LastBlock + 1) * BlockSize
  // has to be the LUN4 capacity we audited.  Anything else is left alone.
  //
  Size = (Blk->Media->LastBlock + 1) * (UINT64)Blk->Media->BlockSize;
  if ((Size < KEBAB_LOG_LUN4_MIN) || (Size > KEBAB_LOG_LUN4_MAX)) {
    return FALSE;
  }

  return (KEBAB_LOG_BYTES % Blk->Media->BlockSize) == 0;
}

STATIC
VOID
EFIAPI
OnBlockIo (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS                    Status;
  EFI_HANDLE                    *Handles;
  UINTN                         Count;
  UINTN                         i;
  EFI_BLOCK_IO_PROTOCOL         *Blk;
  EFI_LOADED_IMAGE_PROTOCOL     *Self;
  UINT64                        Base;
  EFI_EVENT                     Timer;

  if (mBlk != NULL) {
    return;
  }

  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiBlockIoProtocolGuid, NULL, &Count, &Handles);
  if (EFI_ERROR (Status)) {
    return;
  }

  for (i = 0; i < Count; i++) {
    Status = gBS->HandleProtocol (Handles[i], &gEfiBlockIoProtocolGuid, (VOID **)&Blk);
    if (!EFI_ERROR (Status) && LooksLikeOurDisk (Blk)) {
      mBlk = Blk;
      break;
    }
  }

  FreePool (Handles);
  if (mBlk == NULL) {
    return;
  }

  mBuf = AllocateZeroPool (KEBAB_LOG_BYTES);
  if (mBuf == NULL) {
    mBlk = NULL;
    return;
  }

  mLen = 0;
  Base = 0;
  if (!EFI_ERROR (gBS->HandleProtocol (Context, &gEfiLoadedImageProtocolGuid, (VOID **)&Self))) {
    Base = (UINT64)(UINTN)Self->ImageBase;
  }

  LogLine ("KEBABLOG v1 -- written by KebabLogDxe, read with");
  LogLine ("  python rescue/rescue_flash.py read --lun 4 --start 547592 --sectors 8 --out x.bin");
  LogLine ("self base=0x%lx blocksize=0x%x lastblock=0x%lx lba=0x%lx",
           Base, (UINT64)mBlk->Media->BlockSize, (UINT64)mBlk->Media->LastBlock,
           (UINT64)(KEBAB_LOG_BYTE_OFFSET / mBlk->Media->BlockSize));
  LogLine ("this log starts once block I/O exists; earlier output is on the panel only");

  Status = gBS->CreateEvent (EVT_TIMER, TPL_APPLICATION, OnTimer, NULL, &Timer);
  if (!EFI_ERROR (Status)) {
    gBS->SetTimer (Timer, TimerPeriodic, 10000000ULL);  /* 1 s */
  }

  LogFlush ();
}

EFI_STATUS
EFIAPI
KebabLogEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_EVENT   Event;
  EFI_STATUS  Status;

  Status = gBS->CreateEvent (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  OnBlockIo,
                  ImageHandle,
                  &Event
                  );
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;   /* never block the boot for a log */
  }

  Status = gBS->RegisterProtocolNotify (&gEfiBlockIoProtocolGuid, Event, &Event);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  /* The disk may already be up by the time we are dispatched. */
  OnBlockIo (NULL, ImageHandle);
  return EFI_SUCCESS;
}
