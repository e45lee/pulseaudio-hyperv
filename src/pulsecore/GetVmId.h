#ifndef __GET_VMID_H__
#define __GET_VMID_H__

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif
    HRESULT GetVmID(GUID*, const char*, int*);

#ifdef __cplusplus
}
#endif
#endif
