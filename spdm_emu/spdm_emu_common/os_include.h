/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#ifndef __WIN_NT_INCLUDE_H__
#define __WIN_NT_INCLUDE_H__

#ifdef _MSC_VER
/* MSVC*/

/* Win32 include files do not compile clean with /W4, so we use the warning*/
/* pragma to suppress the warnings for Win32 only. This way our code can stil*/
/* compile at /W4 (highest warning level) with /WX (warnings cause build*/
/* errors).*/

#pragma warning(disable : 4115)
#pragma warning(disable : 4201)
#pragma warning(disable : 4028)
#pragma warning(disable : 4133)

#include "WinSock2.h"
#include "winioctl.h"
#include "windows.h"
#include "windowsx.h"
#include "WS2tcpip.h"


/* Set the warnings back on as the EFI code must be /W4.*/

#pragma warning(default : 4115)
#pragma warning(default : 4201)

#else
/* GCC*/
#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"
#include "errno.h"
#include "sys/socket.h"
#include "arpa/inet.h"
typedef int SOCKET;
#define closesocket(x) close(x)
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#endif

#endif
