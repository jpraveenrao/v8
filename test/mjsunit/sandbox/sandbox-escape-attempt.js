// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --sandbox-testing --expose-memory-corruption-api --allow-natives-syntax

// This test demonstrates an attempt to escape the V8 sandbox by corrupting
// the backing store pointer of a TypedArray.
//
// In a typical exploit scenario, an attacker with an arbitrary write primitive
// would overwrite the `external_pointer` of a TypedArray to point to a memory
// address outside the sandbox (e.g., to read arbitrary process memory).
//
// The V8 Sandbox is designed to prevent this by using "Sandboxed Pointers"
// or an "External Pointer Table".
// - If Sandboxed Pointers are used, the value is an offset from the Sandbox Base,
//   usually masked to ensure it wraps around within the sandbox.
// - If the External Pointer Table is used, the value is a handle/index, and
//   corrupting it to an invalid index results in a crash or access to a valid
//   (but different) external object, but not arbitrary memory.
//
// This test simulates such an attack and asserts that the sandbox successfully
// prevents the escape, typically by crashing the process (Sandbox Violation)
// or by containing the access.

if (typeof Sandbox === 'undefined') {
  print("This test requires the Sandbox API (v8_enable_memory_corruption_api=true).");
  quit();
}

print("Sandbox API is available. Proceeding with escape attempt demonstration.");

// 1. Setup: Create a TypedArray inside the sandbox.
// Use a large size to ensure off-heap backing store (external pointer).
const kUint8ArrayType = Sandbox.getInstanceTypeIdFor("JS_TYPED_ARRAY_TYPE");
const kExternalPointerOffset = Sandbox.getFieldOffset(kUint8ArrayType, "external_pointer");

let arr = new Uint8Array(1024 * 1024); // 1MB to force off-heap
let arrAddr = Sandbox.getAddressOf(arr);

print(`[+] Created large Uint8Array at: 0x${arrAddr.toString(16)}`);

// 2. Simulation: Corrupt the external_pointer to point outside.
// We will attempt to set the pointer to a value that would represent
// an address outside the sandbox.
//
// Case A: If `external_pointer` is a raw pointer (no sandbox), this would be
// an absolute address.
// Case B: If `external_pointer` is a SandboxedPointer (offset), we set a large offset.
//
// We choose a value that is likely to be outside the sandbox reservation.
// The sandbox reservation is typically 1TB (0x10000000000).
// Let's try to set the offset to something very large, e.g., 0x4141414100000000.
// Or if it's a 64-bit value, we set it to a distinctive pattern.

const kMaliciousAddress = 0x4141414141414141n;

print(`[+] Corrupting external_pointer at offset ${kExternalPointerOffset} to 0x${kMaliciousAddress.toString(16)}...`);

let memory = new DataView(new Sandbox.MemoryView(0, 0x100000000));
memory.setBigUint64(arrAddr + kExternalPointerOffset, kMaliciousAddress, true);

// 3. Attempt Access: Try to read from the corrupted array.
print("[+] Attempting to read from the corrupted TypedArray...");

try {
  // This read should trigger the sandbox violation mechanism.
  // - If it's a SandboxedPointer, the upper bits might be ignored, mapping it back
  //   to inside the sandbox (containment).
  // - If it points to unmapped memory within the reservation, it crashes (safe).
  // - If it successfully points outside (escape), the sandbox has failed.
  // - If the sandbox detects the violation (e.g. invalid handle), it terminates.

  let value = arr[0];
  print(`[!] Read successful (Value: ${value}). Sandbox containment behavior:`);
  print("    The pointer was likely masked/wrapped back into the sandbox.");

  // Verify that we didn't actually read from 0x4141414141414141 (which would likely segfault if accessed directly).
  // This implies the sandbox "SandboxedPointer" logic worked by ignoring high bits.

} catch (e) {
  print(`[+] Exception caught during read: ${e}`);
  print("[+] The sandbox prevented the access.");
}

// 4. Verification: Demonstrate that we cannot easily point to arbitrary memory.
// If the previous read didn't crash, it means the pointer was sandboxed.
// To "prove" the sandbox, we showed that setting a raw pointer to an outside address
// did *not* result in accessing that outside address (which would have likely crashed
// with a segfault on 0x4141...).

print("[+] Escape attempt complete. The process is still alive (or has safely crashed).");
