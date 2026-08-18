/*
 * FirmLab operator firmware policy — defensive heuristics for extracted Linux root filesystems.
 *
 * These are NOT malware-family signatures and must never be described as attribution. Each rule requires a
 * compound signal, declares its own severity and documents the most likely benign explanation. A match is a
 * triage lead that must be read in its file context. Known-malware coverage comes from the separately pinned
 * YARA Forge corpus.
 *
 * Compatible with YARA 4.2.3. No external variables or optional modules are used.
 */

rule FIRMLAB_FW_Script_Download_And_Execute : firmware heuristic script execution
{
    meta:
        description = "Shell script downloads a payload into a temporary path and makes or invokes it"
        author = "FirmLab homelab operator"
        date = "2026-08-18"
        version = "1.0.0"
        severity = "high"
        confidence = "medium"
        category = "firmware-policy-heuristic"
        reference_1 = "https://attack.mitre.org/techniques/T1105/"
        reference_2 = "https://attack.mitre.org/techniques/T1059/004/"
        false_positive = "Legitimate first-boot installers and vendor updaters may download and execute from /tmp"
        scope = "POSIX shell scripts smaller than 2 MiB"

    strings:
        $shebang = "#!" ascii
        $tmp = "/tmp/" ascii
        $wget = /(^|[;|& \t\r\n])wget[ \t]+[^\r\n]+/ ascii
        $curl = /(^|[;|& \t\r\n])curl[ \t]+[^\r\n]+/ ascii
        $tftp = /(^|[;|& \t\r\n])tftp[ \t]+[^\r\n]+/ ascii
        $chmod = /chmod[ \t]+(\+x|[0-7]*7[0-7]*)[ \t]+\/tmp\// ascii
        $invoke = /(sh|ash|bash)[ \t]+\/tmp\// ascii

    condition:
        filesize < 2MB and $shebang at 0 and $tmp and 1 of ($wget, $curl, $tftp) and
        1 of ($chmod, $invoke)
}

rule FIRMLAB_FW_Telnetd_Unauthenticated_Shell : firmware heuristic telnet authentication
{
    meta:
        description = "Startup shell script launches telnetd with a command shell as the login program"
        author = "FirmLab homelab operator"
        date = "2026-08-18"
        version = "1.0.0"
        severity = "high"
        confidence = "high"
        category = "firmware-policy-heuristic"
        reference_1 = "https://cwe.mitre.org/data/definitions/306.html"
        reference_2 = "https://attack.mitre.org/techniques/T1059/004/"
        false_positive = "Factory diagnostics may intentionally expose a maintenance shell on an isolated interface"
        scope = "POSIX shell scripts smaller than 2 MiB"

    strings:
        $shebang = "#!" ascii
        $telnet_shell_1 = /telnetd[^\r\n]{0,160}-l[ \t]*\/bin\/(ba|a)?sh/ ascii nocase
        $telnet_shell_2 = /telnetd[^\r\n]{0,160}--login-program(=|[ \t])+\/bin\/(ba|a)?sh/ ascii nocase

    condition:
        filesize < 2MB and $shebang at 0 and any of ($telnet_shell_*)
}

rule FIRMLAB_FW_Script_Reverse_Shell : firmware heuristic script reverse_shell
{
    meta:
        description = "Shell script contains a direct /dev/tcp or netcat command-shell reverse shell recipe"
        author = "FirmLab homelab operator"
        date = "2026-08-18"
        version = "1.0.0"
        severity = "high"
        confidence = "high"
        category = "firmware-policy-heuristic"
        reference_1 = "https://attack.mitre.org/techniques/T1059/004/"
        reference_2 = "https://attack.mitre.org/techniques/T1095/"
        false_positive = "Security test fixtures or deliberately shipped support diagnostics"
        scope = "POSIX shell scripts smaller than 2 MiB"

    strings:
        $shebang = "#!" ascii
        $dev_tcp = "/dev/tcp/" ascii
        $shell_redirect = /(bash|sh|ash)[^\r\n]{0,120}>&[^\r\n]{0,80}\/dev\/tcp\// ascii
        $nc_exec_1 = /(nc|netcat)[ \t][^\r\n]{0,160}-e[ \t]*\/bin\/(ba|a)?sh/ ascii nocase
        $nc_exec_2 = /(nc|netcat)[ \t][^\r\n]{0,160}--exec(=|[ \t])+\/bin\/(ba|a)?sh/ ascii nocase

    condition:
        filesize < 2MB and $shebang at 0 and
        (($dev_tcp and $shell_redirect) or any of ($nc_exec_*))
}

rule FIRMLAB_FW_Web_Handler_OS_Command_Execution : firmware heuristic web command_execution
{
    meta:
        description = "Web-facing script combines request-controlled input markers with an OS-command execution primitive"
        author = "FirmLab homelab operator"
        date = "2026-08-18"
        version = "1.0.0"
        severity = "medium"
        confidence = "medium"
        category = "firmware-policy-heuristic"
        reference_1 = "https://cwe.mitre.org/data/definitions/78.html"
        reference_2 = "https://owasp.org/www-community/attacks/Command_Injection"
        false_positive = "Administrative CGI handlers legitimately invoke tightly validated system utilities"
        scope = "Shell, PHP, Lua and Perl-style web handlers smaller than 2 MiB"

    strings:
        $shebang = "#!" ascii
        $php = "<?php" ascii nocase
        $request_1 = "QUERY_STRING" ascii
        $request_2 = "CONTENT_LENGTH" ascii
        $request_3 = "HTTP_COOKIE" ascii
        $request_4 = "$_GET[" ascii
        $request_5 = "$_POST[" ascii
        $request_6 = "cgi.FieldStorage" ascii
        $exec_1 = "system(" ascii
        $exec_2 = "popen(" ascii
        $exec_3 = "exec(" ascii
        $exec_4 = "os.execute(" ascii
        $exec_5 = "io.popen(" ascii
        $exec_6 = "shell_exec(" ascii
        $exec_7 = "passthru(" ascii
        $exec_8 = "`$" ascii

    condition:
        filesize < 2MB and ($shebang at 0 or $php at 0) and
        any of ($request_*) and any of ($exec_*)
}

rule FIRMLAB_FW_Update_TLS_Verification_Disabled : firmware heuristic update tls
{
    meta:
        description = "Firmware-image update script explicitly disables TLS certificate verification while downloading"
        author = "FirmLab homelab operator"
        date = "2026-08-18"
        version = "1.0.0"
        severity = "medium"
        confidence = "high"
        category = "firmware-policy-heuristic"
        reference_1 = "https://cwe.mitre.org/data/definitions/295.html"
        reference_2 = "https://owasp.org/www-project-iot-security-testing-guide/"
        false_positive = "Lab firmware installers using a private CA; production firmware should ship and validate that trust anchor"
        scope = "POSIX shell scripts smaller than 2 MiB"

    strings:
        $shebang = "#!" ascii
        $firmware_1 = "firmware" ascii nocase
        $firmware_2 = "sysupgrade" ascii nocase
        $firmware_3 = "fw_update" ascii nocase
        $firmware_4 = "mtd write" ascii nocase
        $firmware_5 = "upgrade.bin" ascii nocase
        $firmware_6 = "image.bin" ascii nocase
        $firmware_7 = "/tmp/upgrade" ascii nocase
        $wget_insecure = /wget[^\r\n]{0,200}--no-check-certificate/ ascii nocase
        $curl_insecure = /curl[^\r\n]{0,200}(--insecure|[ \t]-k([ \t]|$))/ ascii nocase

    condition:
        filesize < 2MB and $shebang at 0 and any of ($firmware_*) and
        any of ($wget_insecure, $curl_insecure)
}

rule FIRMLAB_FW_LD_Preload_Persistence_Write : firmware heuristic persistence loader
{
    meta:
        description = "Shell script writes a shared-object path into /etc/ld.so.preload"
        author = "FirmLab homelab operator"
        date = "2026-08-18"
        version = "1.0.0"
        severity = "high"
        confidence = "high"
        category = "firmware-policy-heuristic"
        reference_1 = "https://attack.mitre.org/techniques/T1574/006/"
        reference_2 = "https://man7.org/linux/man-pages/man8/ld.so.8.html"
        false_positive = "Vendor instrumentation or compatibility shims deliberately preloaded for every dynamic process"
        scope = "POSIX shell scripts smaller than 2 MiB"

    strings:
        $shebang = "#!" ascii
        $preload = "/etc/ld.so.preload" ascii
        $writer_1 = /echo[^\r\n]{0,200}\.so[^\r\n]{0,80}>+[^\r\n]*\/etc\/ld\.so\.preload/ ascii nocase
        $writer_2 = /printf[^\r\n]{0,200}\.so[^\r\n]{0,80}>+[^\r\n]*\/etc\/ld\.so\.preload/ ascii nocase
        $writer_3 = /tee[ \t]+(-a[ \t]+)?\/etc\/ld\.so\.preload/ ascii nocase

    condition:
        filesize < 2MB and $shebang at 0 and $preload and any of ($writer_*)
}
