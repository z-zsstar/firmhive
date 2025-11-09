# _AC1450-V1.0.0.36_10.0.17.chk.extracted - Verification Report (3 findings)

---

## Original Information

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0x1a1c0 fcn.0001a1c0 and acos_service:0x19ce8 fcn.00019ce8`
- **Description:** A command injection vulnerability was discovered in function fcn.0001a1c0. When the number of parameters (param_1) is greater than 1, the function obtains user input from the command line argument (param_2[1]) and passes it to fcn.00019ce8. In fcn.00019ce8, the input is directly used in the sprintf format string 'ifconfig %s del %s/%s', which is then executed via system without any filtering or escaping. Attackers can execute arbitrary commands by injecting shell metacharacters (such as semicolons, backticks). Trigger condition: An attacker executes 'acos_service' and passes malicious parameters (e.g., via web interface or CLI), and the NVRAM configuration check (acosNvramConfig_match) might affect the path, but as a logged-in user, the attacker can manipulate settings or trigger it directly. Exploitation method: Construct parameters such as 'eth0; malicious_command', leading to command execution.
- **Code Snippet:**
  ```
  // fcn.0001a1c0 snippet
  if (param_1 != 1 && param_1 + -1 < 0 == SBORROW4(param_1,1)) {
      // ... NVRAM check ...
      fcn.00019ce8(*0x1a2c4, *(param_2 + 4)); // Pass user input
  }
  // fcn.00019ce8 snippet
  sym.imp.sprintf(puVar7 + -0x84, *0x19f30, param_2, uVar3); // param_2 is user input, format string is 'ifconfig %s del %s/%s'
  sym.imp.system(puVar7 + -0x84); // Execute the formatted command
  ```
- **Notes:** The vulnerability has high exploitability: the attack chain is complete (from input point to command execution), and as a logged-in user, the attacker can likely trigger it via binary execution. It is recommended to further verify the parameter source (e.g., web backend calls), but current evidence is sufficient to confirm the risk. Other system calls (e.g., sym.imp.system(*0x1a2c8)) should also be checked.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert accurately describes a command injection vulnerability. Evidence is as follows: In fcn.0001a1c0, when the number of parameters (param_1) is greater than 1, user input is obtained from the command line argument (param_2[1]) and passed to fcn.00019ce8. In fcn.00019ce8, the user input is directly used in the sprintf format string 'ifconfig %s del %s/%s' (address 0x00019e6c), which is then executed via system (address 0x00019e7c) without filtering or escaping. The attacker model is a logged-in user (executing the binary via web interface or CLI) who can control the input and trigger the path. Complete attack chain: input is controllable (command line argument), path is reachable (parameter count > 1 and passes NVRAM check), actual impact (arbitrary command execution). PoC: As a logged-in user, execute './acos_service dummy "eth0; touch /tmp/pwned"', which generates the command 'ifconfig eth0; touch /tmp/pwned del ...', causing the injected command 'touch /tmp/pwned' to execute. The vulnerability risk is high because it allows arbitrary command execution.

## Verification Metrics

- **Verification Duration:** 172.26 s
- **Token Usage:** 92746

---

## Original Information

- **File/Directory Path:** `sbin/rc`
- **Location:** `rc:0x0000f4f8-0x0000f610 (main function)`
- **Description:** A command injection vulnerability exists in the hotplug event handling code of the 'rc' binary. The NVRAM variable `lan_ifnames` is retrieved and used to construct a shell command via `_eval` without proper sanitization for shell metacharacters. When MODALIAS is 'platform:coma_dev', the code parses `lan_ifnames` for interface names and executes 'wl -i <interface> down'. An attacker with write access to `lan_ifnames` can inject malicious commands by including semicolons, backticks, or other metacharacters. For example, setting `lan_ifnames` to 'eth0; malicious_command' results in the execution of 'malicious_command' with root privileges. The trigger condition is a hotplug event with MODALIAS='platform:coma_dev', which could be induced by hardware events or potentially simulated by an attacker.
- **Code Snippet:**
  ```
  0x0000f4f8      ldr r0, str.lan_ifnames     ; 'lan_ifnames'
  0x0000f500      bl sym.imp.nvram_get        ; Get value from NVRAM
  ...
  0x0000f524      mov r2, 0x20                ; 32 bytes
  0x0000f528      mov r1, sl                  ; Source string from NVRAM
  0x0000f52c      mov r0, r4                  ; Destination buffer
  0x0000f530      bl sym.imp.strncpy          ; Copy interface name
  ...
  0x0000f5fc      str r8, [var_2ch]           ; 'wl'
  0x0000f600      str sb, [var_30h]           ; '-i'
  0x0000f604      str r4, [var_34h]           ; Interface name from buffer
  0x0000f608      str fp, [var_38h]           ; 'down'
  0x0000f60c      str ip, [var_3ch]           ; Null terminator
  0x0000f610      bl sym.imp._eval            ; Execute command
  ```
- **Notes:** This vulnerability requires the attacker to have write access to the `lan_ifnames` NVRAM variable, which may be possible via web interfaces or CLI tools if access controls are weak. The hotplug event trigger might be exploitable through physical device insertion or other means. Further analysis is needed to confirm the availability of NVRAM write operations to non-root users and the frequency of 'platform:coma_dev' events. The use of `strncpy` with a fixed size limits the injection length to 32 bytes, but this is sufficient for many payloads. Additional vulnerabilities may exist in other command handlers (e.g., 'erase', 'write'), but this chain is the most directly exploitable.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Alert description is accurate: In the main function of 'sbin/rc', when handling hotplug events (MODALIAS='platform:coma_dev'), the code retrieves the 'lan_ifnames' variable via nvram_get, copies it to a buffer using strncpy (limited to 32 bytes), and directly executes the 'wl -i <interface> down' command via _eval without sanitizing the input. Attacker model: The attacker needs write access to the NVRAM variable (e.g., through web interfaces or CLI tools with weak access controls) and must be able to trigger a hotplug event (e.g., by physical device insertion or by simulating the MODALIAS environment variable via software). Complete attack chain: The attacker sets 'lan_ifnames' to a malicious value (e.g., 'eth0; touch /tmp/pwned'). When the event is triggered, the command 'wl -i eth0; touch /tmp/pwned down' is executed with root privileges, resulting in arbitrary command injection. Evidence comes from the decompiled code: nvram_get call (0x0000f4f8-0x0000f500), strncpy (0x0000f524-0x0000f530), command construction (0x0000f5fc-0x0000f60c), and _eval execution (0x0000f610). Path reachability is confirmed through MODALIAS check (0x0000f4d4-0x0000f4e0) and hotplug handling (0x0000f47c-0x0000f484). The actual impact is root privilege command execution, resulting in high risk.

## Verification Metrics

- **Verification Duration:** 363.45 s
- **Token Usage:** 207446

---

## Original Information

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0x19f38 fcn.00019f38`
- **Description:** A command injection vulnerability was discovered in function fcn.00019f38. When param_1 is not equal to 3 and is less than 3, the function retrieves data from the user input structure (offsets 4 and 8 of param_2), uses sprintf to embed it into a command string (address *0x1a1b8), and then executes it via system. The input is not filtered, allowing an attacker to inject arbitrary commands. Trigger condition: depends on the param_1 value and NVRAM check (acosNvramConfig_match), but as a logged-in user, the attacker may control the trigger path via parameters. Exploitation method: manipulate input parameters to contain malicious commands (e.g., 'eth0; rm -rf /'), leading to privilege escalation or device compromise.
- **Code Snippet:**
  ```
  // fcn.00019f38 snippet
  else if (param_1 != 3 && param_1 + -3 < 0 == SBORROW4(param_1,3)) {
      iVar1 = puVar7 + -0x100;
      uVar5 = *(param_2 + 4);
      uVar2 = *(param_2 + 8);
      *(puVar7 + -0x108) = *(param_2 + 0xc);
      sym.imp.sprintf(iVar1, *0x1a1b8, uVar5, uVar2); // User input embedded into command
      sym.imp.printf(*0x1a1bc, iVar1);
      sym.imp.system(iVar1); // Execute command
      return 0;
  }
  ```
- **Notes:** High exploitability, but requires more detailed verification of trigger conditions (such as the specific impact of param_1 and NVRAM settings). The attack chain from input to command execution is complete, but confidence is slightly lower due to dependency conditions. Recommend analyzing the calling context to confirm attacker controllability.

## Verification Conclusion

- **Description Accuracy:** `partially`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** After detailed analysis of the code, the existence of the command injection vulnerability was verified, but the alert description is inaccurate regarding the trigger condition. The actual vulnerability trigger condition is when param_1 (argc) > 3, not when param_1 != 3 and param_1 < 3 as described in the alert. The vulnerable code is at 0x1a13c-0x1a16c in function fcn.00019f38, using sprintf to directly embed user-input argv[1], argv[2], and argv[3] into the 'ifconfig %s add %s/%s' command string, which is then executed via system without input filtering. The attacker model is a locally authenticated user or an attacker with shell access, capable of controlling the startup parameters of acos_service. Exploitation method: by creating a symbolic link with the program name containing 'dhcp6c_up' or by direct invocation, passing at least three parameters where the third parameter contains a command injection payload (e.g., '24; malicious_command'), resulting in the execution of arbitrary commands with root privileges. PoC steps: 1) ln -s /sbin/acos_service /tmp/dhcp6c_up; 2) /tmp/dhcp6c_up eth0 192.168.1.1 '24; malicious_command'. The generated command 'ifconfig eth0 add 192.168.1.1/24; malicious_command' will be executed, achieving privilege escalation or device compromise.

## Verification Metrics

- **Verification Duration:** 417.81 s
- **Token Usage:** 275246

---

