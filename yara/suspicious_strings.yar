import "pe"
import "math"

rule suspicious_powershell_download
{
    meta:
        description = "Detects PowerShell download/cradle commands"
        author = "sandbox"
    strings:
        $a = /powershell.{0,200}(IWR|Invoke-WebRequest|Net\.WebClient|DownloadString|DownloadFile|FromBase64String)/ nocase
        $b = "-enc "
        $c = /bypass.{0,40}executionpolicy/ nocase
        $d = "Invoke-WebRequest" nocase
        $e = "DownloadString" nocase
        $f = "FromBase64String" nocase
    condition:
        any of them
}

rule suspicious_cmd_commands
{
    meta:
        description = "Detects suspicious cmd.exe patterns"
        author = "sandbox"
    strings:
        $a = /cmd\.exe.{0,100}(\/c|\/k)/ nocase
        $b = /rundll32\.exe\s+[^\s]+,#\d+/ nocase
        $c = /regsvr32\.exe\s+\/s\s+\/i\s*:/ nocase
        $d = /mshta\.exe\s+(http|vbscript|javascript)/ nocase
        $e = /certutil\.exe.{0,80}(decode|urlcache|encode)/ nocase
    condition:
        any of them
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
