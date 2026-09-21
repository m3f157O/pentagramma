import "pe"
import "math"

rule suspicious_powershell_download
{
    meta:
        description = "Detects PowerShell download/cradle commands"
        author = "sandbox"
        note = "2026-09-11: bare API-name strings (Invoke-WebRequest/DownloadString/FromBase64String) removed -- they matched any script merely CONTAINING the token (e.g. a benign FromBase64String round-trip), not just cradles. Invocation-context shapes added instead. Backup of previous version: backups/yara-20260911/."
    strings:
        // command-line shape: powershell ... <download verb>
        $a = /powershell.{0,200}(IWR|Invoke-WebRequest|Net\.WebClient|DownloadString|DownloadFile|FromBase64String)/ nocase
        $b = "-enc "
        $c = /bypass.{0,40}executionpolicy/ nocase
        // cradle shape: IEX over downloaded/decoded content
        $d = /(IEX|Invoke-Expression).{0,80}(DownloadString|DownloadFile|FromBase64String|Net\.WebClient)/ nocase
        // invocation shape: actual method call, not a mention
        $e = /\.(DownloadString|DownloadFile|DownloadData)\s*\(/ nocase
        // download-to-disk shape: IWR ... -OutFile
        $f = /(IWR|Invoke-WebRequest).{0,120}-OutFile/ nocase
        $g = /New-Object\s+Net\.WebClient/ nocase
    condition:
        any of them
}

rule suspicious_cmd_commands
{
    meta:
        description = "Detects suspicious cmd.exe patterns"
        author = "sandbox"
        note = "2026-09-21: PE files now need 2+ strings -- real-world goodware embeds these literals legitimately (ripgrep contains 'cmd.exe /e:ON /v:OFF /d /c' and scored +15 static on 2026-09-21). Script files (non-PE) still match on any single string. Backup of previous version: backups/yara-20260921/."
    strings:
        $a = /cmd\.exe.{0,100}(\/c|\/k)/ nocase
        $b = /rundll32\.exe\s+[^\s]+,#\d+/ nocase
        $c = /regsvr32\.exe\s+\/s\s+\/i\s*:/ nocase
        $d = /mshta\.exe\s+(http|vbscript|javascript)/ nocase
        $e = /certutil\.exe.{0,80}(decode|urlcache|encode)/ nocase
    condition:
        (not uint16(0) == 0x5A4D and any of them) or (uint16(0) == 0x5A4D and 2 of them)
}

rule suspicious_urls
{
    meta:
        description = "Detects hardcoded suspicious URLs"
        author = "sandbox"
    strings:
        $a = /https?:\/\/[a-zA-Z0-9.\-]{5,}\/[a-zA-Z0-9._\-]{5,}\.(exe|dll|bat|ps1|vbs|js|scr|cmd)/ nocase
        $b = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
    condition:
        any of them
}

rule high_entropy_section
{
    meta:
        description = "Flags PE sections with very high entropy (likely encrypted/packed)"
        author = "sandbox"
    condition:
        uint16(0) == 0x5A4D and
        for any section in pe.sections :
            (section.characteristics & pe.SECTION_MEM_EXECUTE != 0 and
             math.entropy(section.raw_data_offset, section.raw_data_size) > 7.2)
}

rule reflective_dll_loading
{
    meta:
        description = "Detects API patterns commonly used for reflective DLL loading"
        author = "sandbox"
    strings:
        $a = "NtUnmapViewOfSection" ascii wide
        $b = "VirtualAllocEx" ascii wide
        $c = "WriteProcessMemory" ascii wide
        $d = "CreateRemoteThread" ascii wide
        $e = "RtlCreateUserThread" ascii wide
        $f = "NtCreateThreadEx" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}
