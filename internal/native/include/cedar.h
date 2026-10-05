#ifndef CGW_NATIVE_CEDAR_H
#define CGW_NATIVE_CEDAR_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define CGW_NATIVE_ABI_VERSION 2u
#define CGW_AUTHORIZER 1u
#define CGW_ANALYSIS 2u
/* Status: 0 success, 1 operation error, 2 invalid handle/input, 3 panic, 4 response limit. */
typedef struct { uint32_t status; uint8_t *data; size_t len; } cgw_result;
/* Callback operations: 1 entity load, 2 entity read, 3 solver write, 4 solver read. */
/* Load returns response length; entity read and solver write return zero on completion. */
/* Solver read returns bytes written or zero at EOF. All operations return negative on error. */
typedef ptrdiff_t (*cgw_callback)(uintptr_t id, uint32_t operation, uint8_t *data, size_t len);
uint32_t cgw_native_abi_version(void);
/* Zero means invalid kind, exhausted identifiers, or failed construction. */
uint64_t cgw_native_new(uint32_t kind);
/* Rust borrows input and callback until return. The caller copies and frees each response. */
cgw_result cgw_native_call(uint64_t handle, const uint8_t *operation, size_t operation_len,
    const uint8_t *input, size_t input_len, uintptr_t callback_id, cgw_callback callback, size_t max_response);
/* Close rejects new calls and waits for active calls. Unknown handles return status 2. */
uint32_t cgw_native_close(uint64_t handle);
/* Free each unaltered response exactly once. Null responses have no effect. */
void cgw_native_free(cgw_result result);
#ifdef __cplusplus
}
#endif
#endif
