<#
.SYNOPSIS
Generates a secure, pronounceable passphrase for use in password managers like LastPass.

.DESCRIPTION
This script generates a secure, pronounceable, obfuscated passphrase. 
It supports customizing total length, word count, minimum digits, special characters, and separators.

.EXAMPLE
# Default usage
New-LRPassphrase

# Customize everything
New-LRPassphrase -Length 25 -WordCount 4 -MinDigits 3 -MinSpecialChars 2 -Separator "_"

# No separator (compact)
New-LRPassphrase -WordCount 3 -Separator ""

# Shorter passphrase
New-LRPassphrase -Length 15 -WordCount 2 -MinDigits 1 -MinSpecialChars 1

# Longer passphrase
New-LRPassphrase -Length 30 -WordCount 5 -MinDigits 4 -MinSpecialChars 3
#>

function New-LRPassphrase {
    [CmdletBinding()]
    param (
        [int]$Length = 14,
        [int]$WordCount = 2,
        [int]$MinDigits = 2,
        [int]$MinSpecialChars = 1,
        [string]$Separator = "_"
    )

    # Word list (safe, pronounceable, no confusing characters)
    $AllWords = @(
        "Brisk", "Tango", "Mellow", "Nimbus", "Quartz", "Vortex",
        "Javelin", "Pixel", "Rocket", "Cubat", "Delta", "Fusion",
        "Lumen", "Vapor", "Zephyr", "Krypta", "Glitch",
        "Echo", "Fable", "Griffin", "Helix", "Jargon", "Kodiak"
    )

    # Filter out ambiguous letters (l, I)
    $WordList = $AllWords | Where-Object { $_ -notmatch '[lI]' }

    $SpecialChars = '!@#$%^&*()-_=+'
    $Digits = @(0, 2, 3, 4, 5, 6, 7, 8, 9)
    $rand = [System.Random]::new()

    # Obfuscation mapping (case-insensitive)
    $subMap = @{
        'o' = '0'
        'a' = '@'
        'i' = '1'
    }

    function Obfuscate-Word {
        param ([string]$word)
        $result = ""
        foreach ($char in $word.ToCharArray()) {
            $charStr = [string]$char
            $charKey = $charStr.ToLowerInvariant()
            if ($subMap.ContainsKey($charKey)) {
                $result += $subMap[$charKey]
            }
            else {
                $result += $charStr
            }
        }
        return $result
    }

    # Pick and obfuscate words
    $words = 1..$WordCount | ForEach-Object {
        Obfuscate-Word -word ($WordList[$rand.Next(0, $WordList.Count)])
    }

    # Build base phrase with separator
    $base = $words -join $Separator

    # Inject digits
    for ($i = 0; $i -lt $MinDigits; $i++) {
        $index = $rand.Next(0, $base.Length)
        $digit = $Digits[$rand.Next(0, $Digits.Count)]
        $base = $base.Insert($index, "$digit")
    }

    # Inject special characters
    for ($i = 0; $i -lt $MinSpecialChars; $i++) {
        $index = $rand.Next(0, $base.Length)
        $symbol = $SpecialChars[$rand.Next(0, $SpecialChars.Length)]
        $base = $base.Insert($index, "$symbol")
    }

    # Ensure final length meets $Length minimum
    $safeUpper = @([char[]]([char]'A'..[char]'Z') | Where-Object { $_ -ne 'O' -and $_ -ne 'I' })
    while ($base.Length -lt $Length) {
        $base += $safeUpper[$rand.Next(0, $safeUpper.Count)]
    }

    return $base
}


