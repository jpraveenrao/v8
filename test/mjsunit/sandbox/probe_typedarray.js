// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --sandbox-testing --expose-memory-corruption-api --allow-natives-syntax

if (typeof Sandbox === 'undefined') {
  print("This test requires the Sandbox API (v8_enable_memory_corruption_api=true).");
  quit();
}

const kUint8ArrayType = Sandbox.getInstanceTypeIdFor("JS_TYPED_ARRAY_TYPE");
const kExternalPointerOffset = Sandbox.getFieldOffset(kUint8ArrayType, "external_pointer");
const kBasePointerOffset = Sandbox.getFieldOffset(kUint8ArrayType, "base_pointer");

let arr = new Uint8Array(16);
let arrAddr = Sandbox.getAddressOf(arr);

print(`[+] Uint8Array at: 0x${arrAddr.toString(16)}`);
print(`[+] kExternalPointerOffset: ${kExternalPointerOffset}`);
print(`[+] kBasePointerOffset: ${kBasePointerOffset}`);

let memory = new DataView(new Sandbox.MemoryView(0, 0x100000000));

// Read external_pointer (likely 64-bit or 32-bit sandboxed pointer)
let extPtr = memory.getBigUint64(arrAddr + kExternalPointerOffset, true);
print(`[+] external_pointer: 0x${extPtr.toString(16)}`);

// Read base_pointer (Tagged<Object>)
let basePtr = memory.getUint32(arrAddr + kBasePointerOffset, true);
print(`[+] base_pointer: 0x${basePtr.toString(16)}`);
