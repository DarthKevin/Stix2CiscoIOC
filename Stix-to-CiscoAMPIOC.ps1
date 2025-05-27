<#
.Disclaimer that disclaims things that needed disclaiming
	Coded via many, many iterations of Open AI's o4-mini-high model with some manual tweaking by me. 
	Use at your own risk. You have been warned.
.SYNOPSIS
    Makes a valiant attempt to convert a STIX XML file into a Cisco Secure Endpoint–compatible OpenIOC file. 
	GFL getting the file to actually validate in the Cisco console.
.DESCRIPTION
    This barely-tested script prompts you for a STIX file, then makes a passing attempt at 
    extracting the IOC contexts Cisco demands and ONLY those contexts. Unsupported
    stuff that isn't supported per Cisco's documentation is summarily ignored. Hopefully.

    Supported contexts (yes, we actually care about these):
      • DriverItem  
      • EventLogItem  
      • FileDownloadHistoryItem  
      • FileItem  
      • PortItem  
      • PrefetchItem  
      • ProcessItem  
      • RegistryItem  
      • ServiceItem  
      • SystemRestoreItem  
      • TaskItem  
      • DnsEntryItem  

.NOTES
    USE AT YOUR OWN RISK! This script is like handing nuclear launch codes to a toddler.
    If the XML gods smite your environment, don’t blame me.
#>
# -----------------------------------------------------------------------------
# 1. Ask user for STIX file path — because guessing is for amateurs
# -----------------------------------------------------------------------------
$inputPath = Read-Host -Prompt "Enter full path to STIX XML file"
if (-not (Test-Path $inputPath)) {
    Write-Error "Seriously? '$inputPath' doesn't exist. Did you typo?"
    exit 1
}

# -----------------------------------------------------------------------------
# 2. Create output path by swapping that extension — magical, right?
# -----------------------------------------------------------------------------
$outputPath = [System.IO.Path]::ChangeExtension($inputPath, ".ioc")

# -----------------------------------------------------------------------------
# 3. Load your perfectly formed STIX XML
# -----------------------------------------------------------------------------
[xml]$stix = Get-Content -Path $inputPath

# -----------------------------------------------------------------------------
# 4. Namespace manager: because STIX wouldn't be confusing enough otherwise. If the output file doesn't validate, the next 3 sections are probably why.
# -----------------------------------------------------------------------------
$nsmgr = New-Object System.Xml.XmlNamespaceManager($stix.NameTable)
$nsmgr.AddNamespace("xsi","http://www.w3.org/2001/XMLSchema-instance")

# -----------------------------------------------------------------------------
# 5. Set up XML writer (indentation for readability, ASCII because RFC says so)
# -----------------------------------------------------------------------------
$xmlSettings = New-Object System.Xml.XmlWriterSettings
$xmlSettings.Indent   = $true
$xmlSettings.Encoding = [System.Text.Encoding]::ASCII
$writer = [System.Xml.XmlWriter]::Create($outputPath, $xmlSettings)

# -----------------------------------------------------------------------------
# 6. Blast out the XML declaration and root <ioc> in the proper namespace. 
#    This section is written this way because it's the only way I could get the file to validate. 
#    Don't blame me for Cisco's haphazard implementation of OpenIOC.
# -----------------------------------------------------------------------------
$writer.WriteStartDocument()
$writer.WriteStartElement("ioc", "http://schemas.mandiant.com/2010/ioc")

# Declare only the namespaces Cisco expects (no extras, because reasons)
$writer.WriteAttributeString("xmlns", "http://schemas.mandiant.com/2010/ioc")
$writer.WriteAttributeString("xmlns", "xsi", $null, "http://www.w3.org/2001/XMLSchema-instance")
$writer.WriteAttributeString("xmlns", "xsd", $null, "http://www.w3.org/2001/XMLSchema")

# Required attributes: id and last-modified (because the documentation I didn't read probably requires it)
$writer.WriteAttributeString("id",             [Guid]::NewGuid().ToString())
$writer.WriteAttributeString("last-modified", (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss"))

# Only the prefixed xsi:schemaLocation is allowed — everything else no worky
$writer.WriteAttributeString(
    "xsi", "schemaLocation", "http://www.w3.org/2001/XMLSchema-instance",
    "http://schemas.mandiant.com/2010/ioc http://schemas.mandiant.com/2010/ioc/ioc.xsd"
)

# -----------------------------------------------------------------------------
# 7. Shove in some metadata — make it look fancy
# -----------------------------------------------------------------------------
$writer.WriteElementString("short_description","Converted STIX indicators (rememeber Cisco limits this, not me)")
$writer.WriteElementString("description",      "OpenIOC file generated from STIX for Cisco AMP")
$writer.WriteElementString("authored_by",      "PowerShell STIX→OpenIOC Converter (extra janky alpha version)")
$writer.WriteElementString("authored_date",    (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss"))

# Empty <links/> because Cisco demands it, even if it's pointless
$writer.WriteStartElement("links")
$writer.WriteEndElement()

# -----------------------------------------------------------------------------
# 8. Kick off the <definition> and single <Indicator> block with OR logic
# -----------------------------------------------------------------------------
$writer.WriteStartElement("definition")
$writer.WriteStartElement("Indicator")
$writer.WriteAttributeString("operator","OR")
$writer.WriteAttributeString("id",[Guid]::NewGuid().ToString())

# -----------------------------------------------------------------------------
# 9. The all-important helper that writes each <IndicatorItem> section.
#	 This sometimes gets confused so make sure to look through the output file
#	 for wonky entries. (IP address entries that contain e-mail addresses for example)
# -----------------------------------------------------------------------------
function Add-IndicatorItem {
    param(
        [string]$ContextPath,
        [string]$Value,
        [string]$DocumentType
    )
    $writer.WriteStartElement("IndicatorItem")
    $writer.WriteAttributeString("id",        [Guid]::NewGuid().ToString())
    $writer.WriteAttributeString("condition", "is")

    $writer.WriteStartElement("Context")
    $writer.WriteAttributeString("document",$DocumentType)
    $writer.WriteAttributeString("search",  $ContextPath)
    $writer.WriteAttributeString("type",    "mir")
    $writer.WriteEndElement()  # Context

    $writer.WriteStartElement("Content")
    $writer.WriteAttributeString("type","string")
    $writer.WriteString($Value)
    $writer.WriteEndElement()  # Content

    $writer.WriteEndElement()  # IndicatorItem
}

# -----------------------------------------------------------------------------
# 10. Set up some regex patterns and allowed registry types 
# -----------------------------------------------------------------------------
$ipv4Regex = '^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
$ipv6Regex = '^[0-9A-Fa-f:]+$'
$allowedRegistryTypes = @(
    'REG_NONE','REG_SZ','REG_EXPAND_SZ','REG_BINARY','REG_DWORD',
    'REG_DWORD_BIG_ENDIAN','REG_LINK','REG_MULTI_SZ','REG_RESOURCE_LIST',
    'REG_FULL_RESOURCE_DESCRIPTOR','REG_RESOURCE_REQUIREMENTS_LIST',
    'REG_QWORD','REG_INVALID_TYPE','REG_KEY'
)

# -----------------------------------------------------------------------------
# 11. Map exactly which STIX element names map to Cisco’s precious contexts
# -----------------------------------------------------------------------------
$contextMap = @{
    "DriverItem" = @{
        "DriverItem/DriverName"                       = "DriverName"
        "DriverItem/Md5sum"                           = "Md5sum"
        "DriverItem/PEInfo/Exports/DllName"           = "DllName"
        "DriverItem/PEInfo/Exports/ExportedFunctions" = "ExportedFunctions"
    }
    "EventLogItem" = @{
        "EventLogItem/EID"     = "EID"
        "EventLogItem/log"     = "Log"
        "EventLogItem/message" = "Message"
    }
    "FileDownloadHistoryItem" = @{
        "FileDownloadHistoryItem/FileName" = "FileName"
    }
    "FileItem" = @{
        "FileItem/Created"        = "Created"
        "FileItem/FullPath"       = "FullPath"
        "FileItem/FileName"       = "FileName"
        "FileItem/FileAttributes" = "FileAttributes"
        "FileItem/FileExtension"  = "FileExtension"
        "FileItem/Modified"       = "Modified"
    }
    "PortItem" = @{
        "PortItem/remoteIP" = "Address_Value"
    }
    "PrefetchItem" = @{
        "PrefetchItem/ApplicationFullPath" = "ApplicationFullPath"
        "PrefetchItem/FullPath"           = "FullPath"
        "PrefetchItem/ApplicationFileName"= "ApplicationFileName"
    }
    "ProcessItem" = @{
        "ProcessItem/name"                   = "Name"
        "ProcessItem/path"                   = "Path"
        "ProcessItem/arguments"              = "Arguments"
        "ProcessItem/HandleList/Handle/Name" = "Name"
    }
    "RegistryItem" = @{
        "RegistryItem/Hive"    = "Hive"
        "RegistryItem/KeyPath" = "Key"
        "RegistryItem/Value"   = "Value"
        "RegistryItem/Type"    = "Type"
        "RegistryItem/Path"    = "Path"
    }
    "ServiceItem" = @{
        "ServiceItem/name"      = "Name"
        "ServiceItem/path"      = "Path"
        "ServiceItem/arguments" = "Arguments"
    }
    "SystemRestoreItem" = @{
        "SystemRestoreItem/OriginalFileName" = "OriginalFileName"
    }
    "TaskItem" = @{
        "TaskItem/Name"                             = "Name"
        "TaskItem/ApplicationName"                  = "Application_Name"
        "TaskItem/ActionList/Action/ExecProgramPath" = "Exec_Program_Path"
    }
    "DnsEntryItem" = @{
        "DnsEntryItem/RecordName" = "Value"
    }
}

# -----------------------------------------------------------------------------
# 12. Main loop: extract, filter, and emit supported items
# -----------------------------------------------------------------------------
foreach ($docType in $contextMap.Keys) {
    foreach ($map in $contextMap[$docType].GetEnumerator()) {
        $ctx   = $map.Key
        $local = $map.Value
        $nodes = $stix.SelectNodes("//*[local-name()='$local']", $nsmgr)

        foreach ($node in $nodes) {
            $val = $node.InnerText.Trim()
            switch ($ctx) {
                'PortItem/remoteIP' {
                    if ($val -match $ipv4Regex -or $val -match $ipv6Regex) {
                        Add-IndicatorItem $ctx $val $docType
                    }
                }
                'RegistryItem/Type' {
                    if ($allowedRegistryTypes -contains $val) {
                        Add-IndicatorItem $ctx $val $docType
                    }
                }
                default {
                    Add-IndicatorItem $ctx $val $docType
                }
            }
        }
    }
}

# -----------------------------------------------------------------------------
# 13. Close all open XML elements and finish up
# -----------------------------------------------------------------------------
$writer.WriteEndElement()  # </Indicator>
$writer.WriteEndElement()  # </definition>
$writer.WriteEndElement()  # </ioc>
$writer.WriteEndDocument()
$writer.Flush()
$writer.Close()

# -----------------------------------------------------------------------------
# 14. Brag about success and beg for divine favor
# -----------------------------------------------------------------------------
Write-Host "OpenIOC file has hopefully been created at: $outputPath"
Write-Host "Now pray to the XML gods that it actually validates when you upload it to the Cisco AMP console."
