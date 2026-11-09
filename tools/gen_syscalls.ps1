# Generates src/generated/syscall_data.h from the ntdll that is running now.
# The injector still resolves service numbers and the syscall gadget at runtime;
# these constants are only the fallback for a hooked/patched ntdll.
#
# The script is intentionally self-contained: no PDB, no symbols, no network.

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$out_dir = Join-Path $root 'src\generated'
$out = Join-Path $out_dir 'syscall_data.h'
New-Item -ItemType Directory -Force -Path $out_dir | Out-Null

$ntdll = if ([Environment]::Is64BitProcess) {
    Join-Path $env:SystemRoot 'System32\ntdll.dll'
} else {
    Join-Path $env:SystemRoot 'Sysnative\ntdll.dll'
}
if (-not (Test-Path -LiteralPath $ntdll)) {
    throw "ntdll not found: $ntdll"
}

$bytes = [System.IO.File]::ReadAllBytes($ntdll)

function U16([long]$offset) { return [BitConverter]::ToUInt16($bytes, [int]$offset) }
function U32([long]$offset) { return [BitConverter]::ToUInt32($bytes, [int]$offset) }

$pe = [BitConverter]::ToInt32($bytes, 0x3C)
if ((U32 $pe) -ne 0x00004550) { throw "bad PE signature in $ntdll" }

$file_header = $pe + 4
$section_count = U16 ($file_header + 2)
$optional_size = U16 ($file_header + 16)
$optional = $pe + 24
$magic = U16 $optional
if ($magic -eq 0x20B) {
    $export_directory = $optional + 112
    $image_size_offset = $optional + 56
} elseif ($magic -eq 0x10B) {
    $export_directory = $optional + 96
    $image_size_offset = $optional + 56
} else {
    throw ("unknown optional header magic 0x{0:X}" -f $magic)
}

$export_rva = U32 $export_directory
$image_size = U32 $image_size_offset
$section_table = $optional + $optional_size

$sections = @()
for ($i = 0; $i -lt $section_count; $i++) {
    $at = $section_table + 40 * $i
    $name_bytes = $bytes[$at..($at + 7)]
    $name = ([System.Text.Encoding]::ASCII.GetString($name_bytes)).Trim([char]0)
    $sections += [pscustomobject]@{
        Name = $name
        VirtualSize = U32 ($at + 8)
        VirtualAddress = U32 ($at + 12)
        RawSize = U32 ($at + 16)
        RawPointer = U32 ($at + 20)
        Characteristics = U32 ($at + 36)
    }
}

function RvaToOffset([long]$rva) {
    foreach ($section in $sections) {
        $span = [Math]::Max($section.VirtualSize, $section.RawSize)
        if ($rva -ge $section.VirtualAddress -and
            $rva -lt ($section.VirtualAddress + $span)) {
            $delta = $rva - $section.VirtualAddress
            if ($delta -ge $section.RawSize) { return -1 }
            return [long]$section.RawPointer + $delta
        }
    }
    return -1
}

$export_offset = RvaToOffset $export_rva
if ($export_offset -lt 0) { throw "cannot map export directory RVA" }

$name_count = U32 ($export_offset + 24)
$function_count = U32 ($export_offset + 20)
$names_rva = U32 ($export_offset + 32)
$functions_rva = U32 ($export_offset + 28)
$ordinals_rva = U32 ($export_offset + 36)

$names_offset = RvaToOffset $names_rva
$functions_offset = RvaToOffset $functions_rva
$ordinals_offset = RvaToOffset $ordinals_rva
if ($names_offset -lt 0 -or $functions_offset -lt 0 -or $ordinals_offset -lt 0) {
    throw "cannot map export tables"
}

$wanted = @(
    'NtOpenProcess',
    'NtAllocateVirtualMemory',
    'NtFreeVirtualMemory',
    'NtProtectVirtualMemory',
    'NtWriteVirtualMemory',
    'NtReadVirtualMemory',
    'NtCreateThreadEx',
    'NtWaitForSingleObject',
    'NtTerminateThread',
    'NtClose',
    'NtQueryInformationProcess'
)

$service_numbers = @{}
$missing = @()

foreach ($target in $wanted) {
    $found = $false
    for ($i = 0; $i -lt $name_count; $i++) {
        $name_rva = U32 ($names_offset + 4 * $i)
        $name_offset = RvaToOffset $name_rva
        if ($name_offset -lt 0) { continue }

        $end = $name_offset
        while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
        $name = [System.Text.Encoding]::ASCII.GetString(
            $bytes, [int]$name_offset, [int]($end - $name_offset))
        if ($name -ne $target) { continue }

        $ordinal = U16 ($ordinals_offset + 2 * $i)
        if ($ordinal -ge $function_count) { break }
        $function_rva = U32 ($functions_offset + 4 * $ordinal)
        $function_offset = RvaToOffset $function_rva
        if ($function_offset -lt 0) { break }

        $ssn = -1
        if (($bytes[$function_offset] -eq 0x4C) -and
            ($bytes[$function_offset + 1] -eq 0x8B) -and
            ($bytes[$function_offset + 2] -eq 0xD1) -and
            ($bytes[$function_offset + 3] -eq 0xB8)) {
            $ssn = U32 ($function_offset + 4)
        } elseif ($bytes[$function_offset] -eq 0xB8) {
            $ssn = U32 ($function_offset + 1)
        }

        if ($ssn -ge 0 -and $ssn -lt 0x10000) {
            $service_numbers[$target] = $ssn
            $found = $true
        }
        break
    }
    if (-not $found) {
        $service_numbers[$target] = -1
        $missing += $target
    }
}

# First `syscall; ret` in .text, then anywhere executable. Every hit belongs to
# an Nt stub on a healthy ntdll; jumping to any of them is equivalent because
# the trampoline puts the service number in eax first.
$gadget_rva = -1
foreach ($section in ($sections | Where-Object { $_.Name -eq '.text' })) {
    $raw_end = $section.RawPointer + $section.RawSize
    for ($i = $section.RawPointer; $i -lt $raw_end - 2; $i++) {
        if ($bytes[$i] -eq 0x0F -and $bytes[$i + 1] -eq 0x05 -and
            $bytes[$i + 2] -eq 0xC3) {
            $gadget_rva = $section.VirtualAddress + ($i - $section.RawPointer)
            break
        }
    }
    if ($gadget_rva -ge 0) { break }
}
if ($gadget_rva -lt 0) {
    foreach ($section in ($sections | Where-Object {
            ($_.Characteristics -band 0x20000000) -ne 0 })) {
        $raw_end = $section.RawPointer + $section.RawSize
        for ($i = $section.RawPointer; $i -lt $raw_end - 2; $i++) {
            if ($bytes[$i] -eq 0x0F -and $bytes[$i + 1] -eq 0x05 -and
                $bytes[$i + 2] -eq 0xC3) {
                $gadget_rva = $section.VirtualAddress + ($i - $section.RawPointer)
                break
            }
        }
        if ($gadget_rva -ge 0) { break }
    }
}

$version = (Get-Item $ntdll).VersionInfo.FileVersion
$os = [Environment]::OSVersion.VersionString
$stamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('#pragma once')
$lines.Add('// Generated by tools/gen_syscalls.ps1. Do not edit by hand.')
$lines.Add("// ntdll: $ntdll")
$lines.Add("// version: $version")
$lines.Add("// os: $os")
$lines.Add("// generated: $stamp")
$lines.Add('//')
$lines.Add('// Runtime resolution in syscalls.cpp is authoritative; these values are')
$lines.Add('// only used when ntdll stubs are hooked or unreadable.')
$lines.Add('')
$lines.Add('namespace ll_gen {')
$lines.Add('')
$lines.Add(("inline constexpr unsigned k_gadget_rva = 0x{0:X}u;" -f [uint32]$gadget_rva) + '  // syscall; ret')
$lines.Add('')

foreach ($target in $wanted) {
    $value = [int64]$service_numbers[$target]
    if ($value -lt 0) {
        $lines.Add(("inline constexpr unsigned k{0} = 0xFFFFFFFFu;  // not resolved" -f $target))
    } else {
        $lines.Add(("inline constexpr unsigned k{0} = 0x{1:X}u;" -f $target, $value))
    }
}
$lines.Add('')
$lines.Add('}  // namespace ll_gen')

[System.IO.File]::WriteAllLines($out, $lines, (New-Object System.Text.UTF8Encoding($false)))

Write-Host ("generated {0}" -f $out)
Write-Host ("gadget RVA 0x{0:X}" -f $gadget_rva)
if ($missing.Count -gt 0) {
    Write-Warning ("unresolved (hooked?) stubs: {0}" -f ($missing -join ', '))
}
