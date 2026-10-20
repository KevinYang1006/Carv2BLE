# Carv 2 BLE compatibility and protocol analysis

## Scope and evidence

This report analyzes the actual source of https://github.com/koyakei/carv-koyakei at commit `268e84df8090f915480ab1b18f9d04fbadcfdfc4` (the inspected `main` revision). Links below pin that revision. Findings describe this implementation, not a manufacturer protocol specification or a hardware validation of the application.

The Windows Bleak observations supplied by the user are:

- Two Carv 2 sensors successfully connect to service `2dfbffff-960d-4909-8d28-f353cb168e8a`.
- Characteristic `2dfbfffe` supports notify, `2dfbfffd` supports write, and `2dfbfffc` supports read, all using the same UUID suffix as the service.
- Each sensor delivers exactly one 33-byte notification on subscription, beginning with `0x01`, with no continuous motion data during 45 seconds of testing.

These are user-reported hardware results, not independently reproduced here. The remaining 32 notification bytes were not supplied. No sensor connection, BLE write, pairing change, or firmware operation was performed during this investigation. Repository inspection was read-only.

## Compatibility conclusion

**The repository explicitly targets Carv 2 as a motion-data monitor, but does not implement a standalone stream-start protocol.** Its service matches the user's sensors. Its decoder can interpret a 33-byte value, but neither the length nor the `0x01` prefix establishes that the observed notification is a motion sample.

The documented workflow starts recording in Carv before connecting this monitor. That dependency is the strongest source-supported explanation to investigate for the absence of streaming. Compatibility with the user's particular firmware and Windows BLE behavior remains unverified.

## Relevant source files

All paths below are relative to the upstream repository, not this report's repository.

| Source | Verified finding |
| --- | --- |
| [README.md, lines 1–15](https://github.com/koyakei/carv-koyakei/blob/268e84df8090f915480ab1b18f9d04fbadcfdfc4/README.md#L1-L15) | Calls itself a third-party monitor; advertises raw data and realtime 3D viewing; instructs users to boot Carv, start recording, then boot this app, connect and subscribe. |
| [carv-koyakei/Bluetooth/BluethoothCentralManager.swift, lines 14–37](https://github.com/koyakei/carv-koyakei/blob/268e84df8090f915480ab1b18f9d04fbadcfdfc4/carv-koyakei/Bluetooth/BluethoothCentralManager.swift#L14-L37) | Stores left/right peripheral identifiers, names `CARV 2`, and scans for the matching service UUID. |
| [BluethoothCentralManager.swift, lines 41–88](https://github.com/koyakei/carv-koyakei/blob/268e84df8090f915480ab1b18f9d04fbadcfdfc4/carv-koyakei/Bluetooth/BluethoothCentralManager.swift#L41-L88) | Retrieves connected peripherals, connects selected devices, recognizes left/right by peripheral identifier, and discovers the target service after connection. |
| [carv-koyakei/Carv2/DeviceRow.swift, lines 21–33](https://github.com/koyakei/carv-koyakei/blob/268e84df8090f915480ab1b18f9d04fbadcfdfc4/carv-koyakei/Carv2/DeviceRow.swift#L21-L33) | Connect, Subscribe, and Unsubscribe are separate UI actions. |
| [carv-koyakei/Bluetooth/Carv2DevicePeripheral.swift, lines 25–95](https://github.com/koyakei/carv-koyakei/blob/268e84df8090f915480ab1b18f9d04fbadcfdfc4/carv-koyakei/Bluetooth/Carv2DevicePeripheral.swift#L25-L95) | Discovers characteristics, enables notifications, and publishes received bytes unchanged. |
| [carv-koyakei/Carv2/Carv2Data.swift, lines 78–103](https://github.com/koyakei/carv-koyakei/blob/268e84df8090f915480ab1b18f9d04fbadcfdfc4/carv-koyakei/Carv2/Carv2Data.swift#L78-L103) | Implements the motion byte interpretation detailed below. |
| [carv-koyakei/Carv2/DataManager.swift, lines 38–66](https://github.com/koyakei/carv-koyakei/blob/268e84df8090f915480ab1b18f9d04fbadcfdfc4/carv-koyakei/Carv2/DataManager.swift#L38-L66) | Combines latest left/right notification data, decodes it, and updates motion/turn analysis. |

## BLE initialization and handshake

### Implemented sequence

1. The CoreBluetooth central scans for `2DFBFFFF-960D-4909-8D28-F353CB168E8A` when powered on (`BluethoothCentralManager.swift:35–37,69–76`).
2. Discovered devices are accepted as left/right only when their CoreBluetooth `peripheral.identifier` matches the stored values (`:58–64`). Although the variables contain “Charactaristic” in their names, these values are peripheral identifiers, not GATT characteristic UUIDs. The author's defaults should not be copied into Bleak as protocol constants.
3. A Connect action invokes CoreBluetooth connection; on connection, the app discovers the target service (`:48–51,79–88`).
4. The peripheral delegate discovers all characteristics for discovered services and prints their UUIDs (`Carv2DevicePeripheral.swift:25–35,70–79`).
5. A separate Subscribe action calls `subscribeAttitude()`. It selects a service by its peripheral's name and then takes that service's **first characteristic**, checks that it supports notify, and calls `setNotifyValue(true, for:)` (`:39–65`). It does not select the notification characteristic by UUID. Characteristic ordering is therefore an implementation assumption.
6. The notification-state callback logs success/error; incoming values are assigned directly to the published `data` property (`:82–95`).

Subscription entails the normal BLE notification configuration performed by CoreBluetooth. It is not evidence of a proprietary stream-start or authentication command.

### Not implemented or documented in the Carv 2 path

- No explicit application write to `2dfbfffd`, read of `2dfbfffc`, command opcode table, or stream-start/stop command.
- No challenge-response, application key exchange, token exchange, cryptographic processing, or authentication state machine.
- No explicit pairing or bonding procedure. Operating-system BLE security behavior is not enough documented here to determine the sensor's security requirements.
- No keepalive, negotiated sample rate, documented MTU requirement, or initialization response parser.

A source search found `writeValue` calls in `carv-koyakei/RTK/RTKPeripheral.swift:90,96`, which configure a separate RTK device. Those are not Carv commands and must not be reused for these sensors. See [RTKPeripheral.swift, lines 80–100](https://github.com/koyakei/carv-koyakei/blob/268e84df8090f915480ab1b18f9d04fbadcfdfc4/carv-koyakei/RTK/RTKPeripheral.swift#L80-L100).

The README's exact preparation is “boot carv”, “start Recording”, then “boot this App”, “connect and subscribe” (`README.md:9–15`). This supports an official-app preparation dependency, but does not reveal which BLE operations implement it or prove that recording state survives disconnection.

Absence of authentication code in this monitor does **not** prove that the sensors never require authentication: another app or the operating system could already have established necessary state.

## Packet framing and decoder

The following is the implementation's interpretation for a **33-byte notification**, derived from `Carv2Data.swift:78–103`. Offsets are zero-based and inclusive.

| Bytes | Code-derived interpretation |
| --- | --- |
| 0 | Dropped without examining its value. Meaning unknown. |
| 1–2 | Signed Int16 element 0 after dropping the first byte; not used in the output motion fields. Meaning unknown. |
| 3–10 | Four signed Int16 values divided by 32768, passed as quaternion vector x, y, z, w. |
| 11–16 | Three signed Int16 values divided by 32768 and multiplied by 16, used as acceleration x, y, z. |
| 17–28 | Three native 32-bit Float values, used as angular velocity x, y, z. |
| 29–32 | Fourth native Float parsed by the float helper for this length, but not used by the output fields. Meaning unknown. |

The code reads native Int16/Float memory representations, rather than explicitly specifying byte order. On its intended Apple hardware, this implies little-endian integers and IEEE-754 binary32 floats. This is a description of the decoder, not independently verified wire-format documentation. Acceleration and angular-velocity physical units are not established authoritatively by this source.

### Framing limitations

- The first byte is not validated or dispatched as an opcode. In particular, the code gives **no meaning to `0x01`**.
- No explicit packet-length assertion, checksum/CRC check, fragmentation/reassembly, or sequence-number handling is present in the receive/decode path.
- Each notification value is treated as a whole motion sample. No distinction is made between motion and status/control notifications.
- Unsafe pointer-based decoding and lack of length validation make this unsuitable as a robust validator for arbitrary malformed payloads.
- `Carv2Data.recordetTime` is assigned `Date.now` (`Carv2Data.swift:17`), not decoded from sensor time. [Source](https://github.com/koyakei/carv-koyakei/blob/268e84df8090f915480ab1b18f9d04fbadcfdfc4/carv-koyakei/Carv2/Carv2Data.swift#L13-L17).
- The paired data pipeline uses Combine `combineLatest` (`DataManager.swift:45–49`), rather than matching left/right samples by a decoded sequence or sensor timestamp. A pair can contain one new sample and the other sensor's previous sample.

A 33-byte packet therefore fits this decoder's field access pattern, but the implementation does not establish that 33 is the sole valid length or that every packet of that length contains motion.

## Interpretation of the Windows results

### Established by the supplied observations

- The sensors expose the same primary service used by the repository's Carv 2 path.
- Connection and notification subscription work sufficiently to deliver one value per sensor.
- Subscription alone did not produce a continuous stream during the reported 45-second interval.
- The payload length is compatible with the candidate decoder above.

### Not established

The single `0x01` notification cannot yet be classified as motion, status, an acknowledgment, a cached sample, or an authentication challenge. No full payload, official-app trace, or controlled motion-dependent byte changes are available. A single notification does not prove a subscription failure, and 45 seconds without streaming does not identify its cause.

### Hypotheses, explicitly unverified

1. **Recording-mode dependency:** the official app enables a state required for streaming. This has the strongest repository support because of the README procedure.
2. **Firmware/protocol differences:** current sensor firmware may behave differently from the author's devices. No firmware compatibility matrix is present in the inspected material.
3. **Security, keepalive, or other activation requirement:** possible, but the source provides no command bytes or handshake specification to support a particular mechanism.
4. **Platform/connection-state differences:** the iOS monitor can retrieve peripherals already connected through CoreBluetooth; a standalone Windows connection may not recreate that context. Whether this matters requires observation.

These hypotheses are diagnostic possibilities, not instructions to write to the control characteristic.

## Recommended next experiments

### 1. Observe a normal official-app recording session

This is the most informative next experiment because it tests the documented prerequisite without inventing BLE commands.

- Leave existing pairing intact and disconnect Bleak normally.
- If supported by the phone, enable Bluetooth HCI logging using its normal diagnostic facilities. Start capture before the official app connects, then start and stop a normal recording through the app. Do not change pairing or firmware.
- Mark a brief interval of gentle rotation of one sensor, separately from the other. Confirm whether the official app receives live data.
- Inspect GATT discovery, notification enablement, reads, writes, security events, notification lengths, timing, and raw payloads. Resolve ATT handles to UUIDs from discovery; do not infer characteristic identities from handle numbers alone.
- Determine whether repeated notifications begin after subscription, after an app write, or after another observable event. Identify traffic on `fffe`, `fffd`, and `fffc` using the full UUIDs.
- Compare motion-dependent bytes with the candidate quaternion, acceleration, and angular-velocity layout. Check finite floats, plausible quaternion norm, and repeatable response to rotation; numerical plausibility alone is not proof.

A captured write is evidence of a candidate initialization operation, **not authorization or sufficient justification to replay it**. Interpret its purpose and side effects first. HCI logs can contain identifiers or sensitive traffic; retain and share only what the investigation requires.

If HCI logging is unavailable, record the official app's live-data behavior and proceed with the limited notification-only comparison below. No pairing changes are needed to compensate for unavailable logging.

### 2. Repeat the existing notification-only Bleak test after normal app use

After normal official-app disconnection, repeat the already tested subscription to the known notify characteristic. Do not force concurrent central connections or issue proprietary writes.

- Save complete notification hex, timestamp, sensor identity, length, connection/subscription events, and motion timing.
- Compare idle versus gentle rotation, one sensor at a time initially.
- Compare baseline subscription with subscription following official-app recording, documenting the app's recording and connection state precisely.
- If streaming appears, determine its observed rate and whether it stops after normal recording termination or reconnection. Do not assume state persistence before measuring it.

This can test a persistent recording-state dependency. A negative result does not exclude a requirement for the official app to remain connected, or a platform-specific behavior.

### 3. Analyze captured bytes offline before further device operations

Use bounds-checked, explicit little-endian decoding offline. Preserve the raw frames and distinguish candidate motion frames from unknown types. Compare the first byte, bytes 1–2, and bytes 29–32 across time and sensors without assigning them speculative labels. No additional sensor operation is required for this analysis.

## Validation limits and safety boundary

This was source inspection, not an execution test of the Swift application or an independent sensor test. The repository's example unit test contains no assertions (`carv-koyakeiTests/carv_koyakeiTests.swift:10–14`), so it supplies no protocol validation. [Source](https://github.com/koyakei/carv-koyakei/blob/268e84df8090f915480ab1b18f9d04fbadcfdfc4/carv-koyakeiTests/carv_koyakeiTests.swift#L10-L14).

No verified proprietary initialization payload or authentication algorithm was recovered. Do not guess control writes, replay unrelated RTK commands, reset bonding, or alter firmware. The next useful evidence is a normal official-app session trace and complete motion-correlated notification payloads.
