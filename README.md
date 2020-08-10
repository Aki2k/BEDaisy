# BEDaisy

reverse engineering of bedaisy.sys (battleyes kernel driver). By registering on image load callbacks and IAT hooking BEDaisy's `MmGetSystemRoutineAddress` we can simply hook any imports
we want and have control flow over subsequent functions.

<img src="https://imgur.com/NFGyGrY.png"/>

# APCS

The below function will be executed in each thread that bedaisy registers an APC on.

```cpp
__int64 __usercall apc_callback@<rax>(char _CL@<cl>, char _BH@<bh>, __int64 *a3@<r9>)
{
  __int64 v4; // rbx

  __asm { rcl     bh, cl }
  v4 = *a3;
  *(_DWORD *)(v4 + 2160) = RtlWalkFrameChain(*a3 + 0x70, 256i64, 0i64);
  return KeSetEvent(v4 + 88, 0i64, 0i64);
}
```

Registeration of APCS:

```cpp
    status = PsLookupThreadByThreadId(thread_id, &some_pethread);
    v17 = 0;
    if ( (int)status >= 0 )
    {
      allocated_pool = ExAllocatePool(0x200i64, 0x878i64);
      allocated_pool_1 = allocated_pool;
      allocated_pool_2 = allocated_pool;
      if ( allocated_pool )
      {
        allocated_pool_plus_58 = allocated_pool + 0x58;
        KeInitializeEvent((PRKEVENT)(allocated_pool + 0x58), NotificationEvent, 0);
        __asm { rcl     cx, 0C6h }
        LOBYTE(v77) = 0;
        KeInitializeApc(allocated_pool_2, some_pethread, 0i64, j_apc_callback, 0i64, 0i64, v77, 0i64);
        if ( (unsigned __int8)KeInsertQueueApc(allocated_pool_2, allocated_pool_2, 0i64, 2i64) )
```

# HWID

BEDaisy opens a handle to DR0 (disk.sys).

```
02646022	190.98799133	[GoodEye]ZwOpenFile called from: 0xFFFFF804DEFDB904	
02646023	190.98799133	[GoodEye]     - ZwOpenFile(\Device\Harddisk0\DR0)	
02646024	190.98869324	[GoodEye]     - ZwOpenFile handle result: 0xFFFFFFFF80003E28
```

BEDaisy then sends a few IOCTL's to disk.sys using `ZwDeviceIoControlFile`
```
02646049	190.99142456	[GoodEye]ZwDeviceIoControlFile Called From 0xFFFFF804DEFDB94A	
02646050	190.99143982	[GoodEye]     - FileHandle: 0xFFFFFFFF80003E28	
02646051	190.99143982	[GoodEye]     - IoControlCode: 0x00000000002D1400	
02646052	190.99143982	[GoodEye]     - OutputBufferLength: 0x0000000000000008	
02646053	190.99143982	[GoodEye]     - InoutBufferLength: 0x000000000000000C

02646059	190.99192810	[GoodEye]ZwDeviceIoControlFile Called From 0xFFFFF804DEFDB960	
02646060	190.99192810	[GoodEye]     - FileHandle: 0xFFFFFFFF80003E28	
02646061	190.99192810	[GoodEye]     - IoControlCode: 0x00000000002D1400	
02646062	190.99192810	[GoodEye]     - OutputBufferLength: 0x0000000000000000	
02646063	190.99194336	[GoodEye]     - InoutBufferLength: 0x000000000000000C

02646072	190.99209595	[GoodEye]ZwDeviceIoControlFile Called From 0xFFFFF804DEFDB9B1	
02646073	190.99211121	[GoodEye]     - FileHandle: 0xFFFFFFFF80003E28	
02646074	190.99211121	[GoodEye]     - IoControlCode: 0x000000000007C088	
02646075	190.99211121	[GoodEye]     - OutputBufferLength: 0x0000000000000211	
02646076	190.99211121	[GoodEye]     - InoutBufferLength: 0x0000000000000021	
```

# IRP

BEDaisy checks the IRP's of every single loaded driver. Below is the checks done on dxgkrnl.sys on windows 10-2004. Base address of dxgkrnl.sys is `0xfffff80498f10000`.

```
00042942	92.55983734	[GoodEye]gh_wcsnicmp called from: 0xFFFFF804DEFDD874	
00042943	92.55983734	[GoodEye]     - string1: C:\Windows\System32\drivers\dxgkrnl.sys	
00042944	92.55983734	[GoodEye]     - string2: C:\Windows\System32\drivers\dxgkrnl.sys	
00042945	92.55983734	[GoodEye]     - count: 0x27	
00042946	92.55996704	[GoodEye]MmIsAddressValid Called From: 0xFFFFF804DEFDD8B6	
00042947	92.55996704	[GoodEye]     - NonPaged VirtualAddress: 0xFFFFF80498F10000	// base address of dxgkrnl.sys
00042951	92.56208801	[GoodEye]MmIsAddressValid Called From: 0xFFFFF804DEFE1116	
00042952	92.56209564	[GoodEye]     - NonPaged VirtualAddress: 0xFFFFF8049905E400	// address of DxgkCreateClose
00042953	92.56209564	[GoodEye]MmIsAddressValid Called From: 0xFFFFF804DEFE1116	
00042956	92.56209564	[GoodEye]     - NonPaged VirtualAddress: 0xFFFFF8049905E400	// address of DxgkCreateClose
00042957	92.56209564	[GoodEye]MmIsAddressValid Called From: 0xFFFFF804DEFE1116	
00042980	92.56213379	[GoodEye]     - NonPaged VirtualAddress: 0xFFFFF80498F516A0	// address of DxgkDeviceIoctl
00042981	92.56213379	[GoodEye]MmIsAddressValid Called From: 0xFFFFF804DEFE1116	
00042982	92.56213379	[GoodEye]     - NonPaged VirtualAddress: 0xFFFFF80499059670	// address of DxgkInternalDeviceIoctl
```

# Imports

All import addresses are stored in the `.data` section of the driver and can easily be changed to hook imported functions.

<img src="https://imgur.com/hafZdDd.png"/>
