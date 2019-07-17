rule Adobe_Flash_DRM_Use_After_Free
{    
    meta:
        note  = "This YARA rule is intended to run atop of decompiled Flash."

    strings:
        $as   = "package"
        $exp1 = "import com.adobe.tvsdk.mediacore" 	// covers .*
        $exp2 = "createDispatcher("
        $exp3 = "createMediaPlayer("
        $exp4 = "drmManager.initialize("    		// com.adobe.tvsdk.mediacore.DRMOperationCompleteListener;
        $vara_1 = "push(this)"
        $vara_2 = "push(null)"
        $vara_3 = /pop\(\)\..+\s*=\s*.+pop\(\)/
        $varb_1 = /push\([^\)]{1,24}drmManager.initialize/

        // all the requisite pieces in a single function.
        $varc_1 = /\{[^\}]+createDispatcher\s*\([^\}]+createMediaPlayer\s*\([^\}]+drmManager\.initialize\s*\([^\}]+=\s*null[^\}]+\}/

    condition:
        $as at 0 and all of ($exp*) and (all of ($vara*) or $varb_1 or $varc_1)
}
