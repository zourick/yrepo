rule Unknown_botnet_bin
{
    meta:
    description = "Unknown botnet"
        author = "James_inthe_box"
    reference = "https://app.any.run/tasks/5a12dfe2-ba7a-4efe-8062-d710e7350c94"
        date = "2019/01"
        maltype = "Bot"
       
    strings:
    $mz = { 4d 5a }
        $string1 = "[%d] ERROR: %d, %s: %d"
    $string2 = "download|update|delete|nothing|plugin_start|plugin_stop|plugin_delete"
        $string3 = "plugin_start"
        $string4 = "plugin_stop"
        $string5 = "plugin_delete"
       
    condition:
    ($mz at 0) and all of ($string*) and filesize < 100KB
}
 
rule Unknown_botnet_mem
{
    meta:
        description = "Unknown botnet"
        author = "James_inthe_box"
        reference = "https://app.any.run/tasks/5a12dfe2-ba7a-4efe-8062-d710e7350c94"
        date = "2019/01"
        maltype = "Bot"
 
    strings:
        $string1 = "[%d] ERROR: %d, %s: %d"
        $string2 = "download|update|delete|nothing|plugin_start|plugin_stop|plugin_delete"
        $string3 = "plugin_start"
        $string4 = "plugin_stop"
        $string5 = "plugin_delete"
 
    condition:
        all of ($string*) and filesize > 100KB
}
