// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --sandbox-testing --expose-memory-corruption-api --allow-natives-syntax

// This test demonstrates the capabilities of the V8 Sandbox testing API.
// It shows how memory corruption *inside* the sandbox can be simulated,
// allowing out-of-bounds access to other objects within the sandbox (intra-sandbox corruption).
// It also demonstrates that access *outside* the sandbox is prevented by the
// sandbox boundaries (enforced here by the API checks simulating the hardware/software constraints).

if (typeof Sandbox === 'undefined') {
  print("This test requires the Sandbox API (v8_enable_memory_corruption_api=true).");
  quit();
}

print("Sandbox API is available. Proceeding with demonstration.");

// 1. Setup: Create a victim object (a String) inside the sandbox.
const kSeqOneByteString = Sandbox.getInstanceTypeIdFor("SEQ_ONE_BYTE_STRING_TYPE");
const kStringLengthOffset = Sandbox.getFieldOffset(kSeqOneByteString, "length");

let victim = "A".repeat(16);
let victimAddr = Sandbox.getAddressOf(victim);

print(`[+] Created victim string at address: 0x${victimAddr.toString(16)}`);
print(`[+] Original victim length: ${victim.length}`);

// 2. Simulation: Corrupt the length of the victim string.
// This simulates an attacker who has achieved an arbitrary write primitive *inside* the sandbox
// and uses it to corrupt a specific object to gain further access.
let newLength = 0x1000; // 4096 bytes
print(`[+] Corrupting victim length to: ${newLength}`);

// Sandbox.corruptObjectField writes directly to the memory location of the field.
Sandbox.corruptObjectField(victim, kStringLengthOffset, newLength);

print(`[+] Victim length after corruption: ${victim.length}`);

if (victim.length !== newLength) {
  print("[-] Failed to corrupt string length.");
  quit();
}

// 3. Intra-Sandbox Corruption: Access memory out-of-bounds relative to the object.
// Since the string length is now larger, we can read data that follows the string in memory.
// This data belongs to other objects in the sandbox.
try {
  // Accessing index 20, which is outside the original bounds (0-15).
  let charCode = victim.charCodeAt(20);
  print(`[+] Successfully performed OOB read at index 20 (inside sandbox): ${charCode}`);
} catch (e) {
  print(`[-] Failed to read OOB: ${e}`);
}

// 4. Sandbox Containment: Attempt to access memory outside the sandbox.
// The V8 Sandbox isolates the heap from the rest of the process.
// Direct pointers are 32-bit offsets from the Sandbox Base, making it impossible
// to address memory outside the 4GB sandbox using standard references.
// The Sandbox API enforces this by checking bounds.

print("[+] Attempting to create a view outside the sandbox address space...");
try {
  // Attempt to create a view starting at 4GB + 1 (outside the 4GB sandbox).
  // In a real exploit, this would correspond to forging a pointer to outside memory.
  let memory = new DataView(new Sandbox.MemoryView(0x100000001, 4));
  print("[-] Successfully created view outside sandbox (Unexpected! API check failed?)");
} catch (e) {
  print(`[+] Caught expected error: ${e.message}`);
  print("[+] The sandbox correctly prevented access to memory outside the sandbox partition.");
}
