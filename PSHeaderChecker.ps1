[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $Uri
)

$headerSts = "Strict-Transport-Security"
$headerFrameOpt = "X-Frame-Options"
$headerXssProt = "X-XSS-Protection"
$headerContentType = "X-Content-Type-Options"
$headerCsp = "Content-Security-Policy"
$headerRefPol = "Referrer-Policy"
$headerFeaturePol = "Feature-Policy"

try {
    $req = Invoke-WebRequest -Uri $Uri
    $requestHeaders = $req.Headers

    <# $headerAnalysis = [PSCustomObject]@{
        "$headerSts" = $null
        "$headerFrameOpt" = $null
        "$headerXssProt" = $null
        "$headerContentType" = $null
        "$headerCsp" = $null
        "$headerRefPol" = $null
    } #>

    $headerAnalysis = @()

    #region Strict-Transport-Security
    $headerStsObj = New-Object -TypeName psobject
    Add-Member -InputObject $headerStsObj -MemberType NoteProperty -Name "HTTP Header" -Value $headerSts
    Add-Member -InputObject $headerStsObj -MemberType NoteProperty -Name "Value" -Value ""
    Add-Member -InputObject $headerStsObj -MemberType NoteProperty -Name "Result" -Value ""
    Add-Member -InputObject $headerStsObj -MemberType NoteProperty -Name "Recommendation" -Value ""

    $headerStsValue = $requestHeaders[$headerSts]
    
    if($null -ne $headerStsValue) {
        $headerStsObj.Value = $headerStsValue
        
        if($headerStsValue -ne "max-age=31536000; includeSubDomains") {
            $headerStsObj.Result = "ISSUE"
            $headerStsObj.Recommendation = "Should be set to `"max-age=31536000; includeSubDomains`""
        }
        else {
            $headerStsObj.Result = "OK"
        }
    }
    else {
        $headerStsObj.Result = "MISSING"
        $headerStsObj.Recommendation = "Should be added and set to `"max-age=31536000; includeSubDomains`""
    }

    $headerAnalysis += $headerStsObj
    #endregion

    #region X-Frame-Options
    $headerFrameOptObj = New-Object -TypeName psobject
    Add-Member -InputObject $headerFrameOptObj -MemberType NoteProperty -Name "HTTP Header" -Value $headerFrameOpt
    Add-Member -InputObject $headerFrameOptObj -MemberType NoteProperty -Name "Value" -Value ""
    Add-Member -InputObject $headerFrameOptObj -MemberType NoteProperty -Name "Result" -Value ""
    Add-Member -InputObject $headerFrameOptObj -MemberType NoteProperty -Name "Recommendation" -Value ""

    $headerFrameOptValue = $requestHeaders[$headerFrameOpt]

    if($null -ne $headerFrameOptValue) {
        $headerFrameOptObj.Value = $headerFrameOptValue

        if(($headerFrameOptValue -ne "SAMEORIGIN") -and ($headerFrameOptValue -ne "DENY")) {
            $headerFrameOptObj.Result = "ISSUE"
            $headerFrameOptObj.Recommendation = "Should be set to `"DENY`" or `"SAMEORIGIN`""
        }
        else {
            $headerFrameOptObj.Result = "OK"
        }
    }
    else {
        $headerFrameOptObj.Result = "MISSING"
        $headerFrameOptObj.Recommendation = "Should be added and set to `"DENY`" or `"SAMEORIGIN`""
    }

    $headerAnalysis += $headerFrameOptObj
    #endregion

    #region X-XSS-Protection
    $headerXssProtObj = New-Object -TypeName psobject
    Add-Member -InputObject $headerXssProtObj -MemberType NoteProperty -Name "HTTP Header" -Value $headerXssProt
    Add-Member -InputObject $headerXssProtObj -MemberType NoteProperty -Name "Value" -Value ""
    Add-Member -InputObject $headerXssProtObj -MemberType NoteProperty -Name "Result" -Value ""
    Add-Member -InputObject $headerXssProtObj -MemberType NoteProperty -Name "Recommendation" -Value ""

    $headerXssProtValue = $requestHeaders[$headerXssProt]

    if($null -ne $headerXssProtValue) {
        $headerXssProtObj.Value = $headerXssProtValue

        if($headerXssProtValue -ne "1; mode=block") {
            $headerXssProtObj.Result = "ISSUE"
            $headerXssProtObj.Recommendation = "Should be set to `"1; mode=block`""
        }
        else {
            $headerXssProtObj.Result = "OK"
        }
    }
    else {
        $headerXssProtObj.Result = "MISSING"
        $headerXssProtObj.Recommendation = "Should be added and set to `"1; mode=block`""
    }

    $headerAnalysis += $headerXssProtObj
    #endregion

    #region X-Content-Type-Options
    $headerContentTypeObj = New-Object -TypeName psobject
    Add-Member -InputObject $headerContentTypeObj -MemberType NoteProperty -Name "HTTP Header" -Value $headerContentType
    Add-Member -InputObject $headerContentTypeObj -MemberType NoteProperty -Name "Value" -Value ""
    Add-Member -InputObject $headerContentTypeObj -MemberType NoteProperty -Name "Result" -Value ""
    Add-Member -InputObject $headerContentTypeObj -MemberType NoteProperty -Name "Recommendation" -Value ""

    $headerContentTypeValue = $requestHeaders[$headerContentType]

    if($null -ne $headerContentTypeValue) {
        $headerContentTypeObj.Value = $headerContentTypeValue

        if($headerContentTypeValue -ne "nosniff") {
            $headerContentTypeObj.Result = "ISSUE"
            $headerContentTypeObj.Recommendation = "Should be set to `"nosniff`""
        }
        else {
            $headerContentTypeObj.Result = "OK"
        }
    }
    else {
        $headerContentTypeObj.Result = "MISSING"
        $headerContentTypeObj.Recommendation = "Should be added and set to `"nosniff`""
    }

    $headerAnalysis += $headerContentTypeObj
    #endregion

    #region Referrer-Policy
    $headerRefPolObj = New-Object -TypeName psobject
    Add-Member -InputObject $headerRefPolObj -MemberType NoteProperty -Name "HTTP Header" -Value $headerRefPol
    Add-Member -InputObject $headerRefPolObj -MemberType NoteProperty -Name "Value" -Value ""
    Add-Member -InputObject $headerRefPolObj -MemberType NoteProperty -Name "Result" -Value ""
    Add-Member -InputObject $headerRefPolObj -MemberType NoteProperty -Name "Recommendation" -Value ""

    $headerRefPolValue = $requestHeaders[$headerRefPol]

    if($null -ne $headerRefPolValue) {
        $headerRefPolObj.Value = $headerRefPolValue

        if($headerRefPolValue -match "(^|,\s{0,1})(origin-when-cross-origin|unsafe-url|origin)($|,\s{0,1})") {
            $headerRefPolObj.Result = "ISSUE"
            $headerRefPolObj.Recommendation = "`"origin-when-cross-origin`", `"origin`" and `"unsafe-url`" can leak sensitive information via HTTP connections"
        }
        else {
            $headerRefPolObj.Result = "OK"
        }
    }
    else {
        $headerRefPolObj.Result = "MISSING"
        $headerRefPolObj.Recommendation = "Should be added (note: `"origin-when-cross-origin`", `"origin`" and `"unsafe-url`" can leak sensitive information via HTTP connections)"
    }

    $headerAnalysis += $headerRefPolObj
    #endregion

    #region Content-Security-Policy
    # TODO
    #endregion

    #region Feature-Policy
    # TODO
    #endregion

    $headerAnalysis

} catch [System.Net.WebException] {
    $statusCode = [int]$_.Exception.Response.StatusCode
    $statusDesc = $_.Exception.Response.StatusDescription

    Write-Error "Web Request failed: $($statusCode): $statusDesc"
}
