@{
    # Every default rule at every severity (Error, Warning, Information), plus
    # the formatting rules that are off by default.
    Severity     = @('Error', 'Warning', 'Information')
    IncludeDefaultRules = $true
    Rules        = @{
        PSUseConsistentIndentation = @{ Enable = $true; IndentationSize = 4; Kind = 'space' }
        PSUseConsistentWhitespace  = @{ Enable = $true; CheckOpenBrace = $true; CheckOpenParen = $true; CheckOperator = $false; CheckSeparator = $true; CheckInnerBrace = $true; CheckPipe = $true }
        PSPlaceOpenBrace           = @{ Enable = $true; OnSameLine = $true; NewLineAfter = $true; IgnoreOneLineBlock = $true }
        PSPlaceCloseBrace          = @{ Enable = $true; NewLineAfter = $true; IgnoreOneLineBlock = $true; NoEmptyLineBefore = $false }
        PSUseCompatibleSyntax      = @{ Enable = $true; TargetVersions = @('5.1', '7.4') }
    }
}
