rule SUSP_Office_Dropper_Strings {
   meta:
      description = "Detects Office droppers that include a notice to enable active content"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-09-13"
   strings:
      $a1 = "_VBA_PROJECT" fullword wide

      $s1 = "click enable editing" fullword ascii
      $s2 = "click enable content" fullword ascii
      $s3 = "\"Enable Editing\"" fullword ascii
      $s4 = "\"Enable Content\"" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 500KB and $a1 and 1 of ($s*)
}

rule SUSP_EnableContent_String_Gen {
   meta:
      description = "Detects suspicious string that asks to enable active content in Office Doc"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-02-12"
      hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"
   strings:
      $e1 = "Enable Editing" fullword ascii
      $e2 = "Enable Content" fullword ascii
      $e3 = "Enable editing" fullword ascii
      $e4 = "Enable content" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and (
            $e1 in (0..3000) or
            $e2 in (0..3000) or
            $e3 in (0..3000) or
            $e4 in (0..3000) or
            2 of them
      )
}

rule SUSP_WordDoc_VBA_Macro_Strings {
   meta:
      description = "Detects suspicious strings in Word Doc that indcate malicious use of VBA macros"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-02-12"
      score = 60
      hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"
   strings:
      $a1 = "\\Microsoft Shared\\" ascii
      $a2 = "\\VBA\\" ascii
      $a3 = "Microsoft Office Word" fullword ascii
      $a4 = "PROJECTwm" fullword wide

      $s1 = "AppData" fullword ascii
      $s2 = "Document_Open" fullword ascii
      $s3 = "Project1" fullword ascii
      $s4 = "CreateObject" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 800KB and all of them
}

rule SUSP_OfficeDoc_VBA_Base64Decode {
   meta:
      description = "Detects suspicious VBA code with Base64 decode functions"
      author = "Florian Roth"
      reference = "https://github.com/cpaton/Scripting/blob/master/VBA/Base64.bas"
      date = "2019-06-21"
      score = 70
      hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"
   strings:
      $s1 = "B64_CHAR_DICT" ascii
      $s2 = "Base64Decode" ascii
      $s3 = "Base64Encode" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 60KB and 2 of them
}

rule SUSP_VBA_FileSystem_Access {
   meta:
      description = "Detects suspciius VBA that writes to disk and is activated on document open"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-06-21"
      score = 60
      hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"
   strings:
      $s1 = "\\Common Files\\Microsoft Shared\\" wide
      $s2 = "Scripting.FileSystemObject" ascii

      $a1 = "Document_Open" ascii
      $a2 = "WScript.Shell" ascii
      $a3 = "AutoOpen" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 100KB and all of ($s*) and 1 of ($a*)
}
