function Initialize-TopMetric{
    Write-Verbose -Message "$(Get-Date -F 'dd-MM-yy hh:mm:ss') $($s = Get-PSCallStack;">Entering {0}" -f $s[0].FunctionName)"
        
    Try{
        Get-Variable -Name TopMetrics -Scope Script -ErrorAction Stop > $null
    }
    Catch{
        $Script:TopMetric = Get-Content -Path "$($PSScriptRoot)\TopMetric.json" -Raw | ConvertFrom-Json
    }

    Write-Verbose -Message "$(Get-Date -F 'dd-MM-yy hh:mm:ss') $($s = Get-PSCallStack;"<Leaving {0}" -f $s[0].FunctionName)" 
}

function Get-TopMetric{
    [CmdletBinding()]
    param()

    Begin{
        Initialize-TopMetric
    }

    Process{
        Write-Verbose -Message "$(Get-Date -F 'dd-MM-yy hh:mm:ss') $($s = Get-PSCallStack;">Entering {0}" -f $s[0].FunctionName)"
        
        $Script:TopMetric.EsxTopMetrics | select -Property EsxTop,TopMetric,Formula

        Write-Verbose -Message "$(Get-Date -F 'dd-MM-yy hh:mm:ss') $($s = Get-PSCallStack;"<Leaving {0}" -f $s[0].FunctionName)" 
    }
}

function Get-TopStatRaw{
    [CmdletBinding()]
    param(
        [int]$Duration,
        [string[]]$EsxTopMetric,
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost,
        [PSCredential]$Credential,
        [ref]$StatValue,
        [ref]$TopValue,
        [Switch]$GetStat
    )

    Begin{
        Initialize-TopMetric
    }

    Process{
        Write-Verbose -Message "$(Get-Date -F 'dd-MM-yy hh:mm:ss') $($s = Get-PSCallStack;">Entering {0}" -f $s[0].FunctionName)"
        
        $TopInterval = $Script:TopMetric.EsxTopConfig.TopInterval
        $StatInterval = $Script:TopMetric.EsxTopConfig.StatInterval

        $statRuns = [math]::Ceiling($Duration/$StatInterval)
        $topRuns = $statRuns*($StatInterval/$TopInterval)
        
        if($GetStat){
            $statStat = @()
        }
        $tempTopCounter = @()
        $Script:TopMetric.EsxTopMetrics | where{$EsxTopMetric -contains $_.EsxTop} | %{
            $tempTopCounter += ($_.TopMetric).Split('/')[0]
            if($GetStat){
                $statStat += $_.StatMetric
            }
        }
        $topStatMetrics = @{}
        foreach($counter in ($tempTopCounter | Sort-Object -Unique)){
            $counterProp = $Script:TopMetric.EsxTopMetrics | where{$_.TopMetric -match "^$($counter)"} | %{
                 $_.TopMetric.Split('/')[1]
            }
            $Script:TopMetric.EsxTopConfig.FixedFields | where{$_.Counter -eq $counter} | %{
                $counterProp += $_.Fields
            }
            $topStatMetrics.Add($counter,$counterProp)
        }

        $EventArgs = New-Object -TypeName PSObject -Property @{
            VMHost = $VMHost
            TopStatMetric = $topStatMetrics
            StatStat = $statStat
            TopRef = $TopValue
            StatRef = $StatValue
        }

        $topCode = {
            $global:topCounter++
            $Event.MessageData.TopRef.Value += &{
                $now = Get-Date
                $metrics = Get-EsxTop -Server $Event.MessageData.VMHost.Name -CounterName ([string[]]$Event.MessageData.TopStatMetric.Keys)
                foreach($counter in ([string[]]$Event.MessageData.TopStatMetric.Keys)){
                    foreach($metric in ($metrics | where{$_.Counter -eq $counter})){
                        $obj = [ordered]@{
                            Timestamp = $now
                            Counter = $counter
                        }
                        $Event.MessageData.TopStatMetric[$counter] | %{
                            $obj.Add($_,$metric."$($_)")
                        }
                        New-Object PSObject -Property $obj
                    }
                }
            }
        }
        if($GetStat){
            $statCode = {
                $global:statCounter++
                $Event.MessageData.StatRef.Value += Get-Stat -Entity $Event.MessageData.VMHost -Stat $Event.MessageData.StatStat -Realtime -MaxSamples 1
            }
        }

        $topTimer = New-Object System.Timers.Timer
        $topTimer.AutoReset = $true
        $topTimer.Interval = $TopInterval * 1000
        $topTimer.Enabled = $true

        if($GetStat){
            $statTimer = New-Object System.Timers.Timer
            $statTimer.AutoReset = $True
            $statTimer.Interval = $statInterval * 1000
            $statTimer.Enabled = $true
        }
        
        Get-EventSubscriber -SourceIdentifier TopTimer -ErrorAction SilentlyContinue | Unregister-Event -Confirm:$false
        Register-ObjectEvent -InputObject $topTimer -MessageData $EventArgs -EventName elapsed –SourceIdentifier TopTimer -Action $topCode > $null

        if($GetStat){
            Get-EventSubscriber -SourceIdentifier StatTimer -ErrorAction SilentlyContinue | Unregister-Event -Confirm:$false
            Register-ObjectEvent -InputObject $statTimer -MessageData $EventArgs -EventName elapsed –SourceIdentifier StatTimer -Action $statCode > $null
        }

        $global:statCounter = $global:topCounter = $prevTop = $prevStat = 0

        $topTimer.Start()
        if($GetStat){
            $statTimer.Start()
            Write-Verbose "$(Get-Date -Format 'dd-MM-yy hh:mm:ss') Stat: $($global:statCounter) Top: $($global:topCounter)"
        }
        else{
            Write-Verbose "$(Get-Date -Format 'dd-MM-yy hh:mm:ss') Top: $($global:topCounter)"
        }
        if($GetStat){
            while($global:statCounter -le $statRuns -and $global:topCounter -le $topRuns){
                if($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue){
                    if($prevTop -lt $global:topCounter -or $prevStat -lt $global:statCounter){
                        Write-Verbose "$(Get-Date -Format 'dd-MM-yy hh:mm:ss') Stat: $($global:statCounter) Top: $($global:topCounter)"
                    }
                }
                $prevTop = $global:topCounter
                $prevStat = $global:statCounter
            }
        }
        else{
            while($global:topCounter -le $topRuns){
                if($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue){
                    if($prevTop -lt $global:topCounter){
                        Write-Verbose "$(Get-Date -Format 'dd-MM-yy hh:mm:ss') Top: $($global:topCounter)"
                    }
                }
                $prevTop = $global:topCounter
            }
        }

        Unregister-Event TopTimer
        $topTimer.Dispose()
        if($GetStat){
            Unregister-Event StatTimer
            $statTimer.Dispose()
        }

        Write-Verbose -Message "$(Get-Date -F 'dd-MM-yy hh:mm:ss') $($s = Get-PSCallStack;"<Leaving {0}" -f $s[0].FunctionName)" 
    }
}

function Invoke-TopCalc{
    [CmdletBinding()]
    param(
        [ref]$TopValue
    )
    Begin{
        Initialize-TopMetric
        $metricTab = @{}
        $topTab = @{}
        $Script:TopMetric.EsxTopMetrics | %{
            $metricTab.Add($_.TopMetric,$_.Formula)
            $topTab.Add($_.TopMetric,$_.EsxTop)
        }
    }

    Process{
        Write-Verbose -Message "$(Get-Date -F 'dd-MM-yy hh:mm:ss') $($s = Get-PSCallStack;">Entering {0}" -f $s[0].FunctionName)"
        
        $TopInterval = $Script:TopMetric.EsxTopConfig.TopInterval

        $topSlices = $TopValue.Value | Group-Object -Property Timestamp

        for($sCounter=1; $sCounter -lt $topSlices.Count; $sCounter++){
            for($cCounter=0; $cCounter -lt $topSlices[$sCounter].Group.Count; $cCounter++){
                $counter = $topSlices[$sCounter].Group[$cCounter]
                $obj = [ordered]@{}
                $counter | Get-Member -MemberType NoteProperty | %{
                    if($metricTab.ContainsKey("$($counter.Counter)/$($_.Name)")){
                        $formula = $metricTab["$($counter.Counter)/$($_.Name)"]                        $n = $counter."$($_.Name)"                        $p = $topSlices[$sCounter-1].Group[$cCounter]."$($_.Name)"                        $value = Invoke-Expression -Command $formula
                        $obj.Add($topTab["$($counter.Counter)/$($_.Name)"],$value)
                    }
                    else{
                        $obj.Add($_.Name,$counter."$($_.Name)")
                    }
                }
                New-Object PSObject -Property $obj
            }
        }

        Write-Verbose -Message "$(Get-Date -F 'dd-MM-yy hh:mm:ss') $($s = Get-PSCallStack;"<Leaving {0}" -f $s[0].FunctionName)" 
    }
}

function Get-TopStat{
    [CmdletBinding()]
    param(
        [int]$Duration,
        [string[]]$EsxTopMetric,
        [Parameter(Mandatory=$true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost,
        [PSCredential]$Credential,
        [Switch]$GetStat
    )

    Write-Verbose -Message "$(Get-Date -F 'dd-MM-yy hh:mm:ss') $($s = Get-PSCallStack;">Entering {0}" -f $s[0].FunctionName)"
       
    $topArray = @()
    $statArray = @()
    
    if($global:DefaultVIServers.Name -notcontains $VMHost.Name){
        Connect-VIServer -Server $VMHost.Name -Credential $Credential > $null
        $wasConnected = $false
    } 

    $sTopStatRaw = @{
        VMHost = $VMHost
        Credential = $cred
        Duration = $Duration
        EsxTopMetric = $EsxTopMetric
        TopValue = [ref]$topArray
        StatValue = [ref]$statArray
        GetStat = $GetStat
        Verbose = $VerbosePreference
    }

    Get-TopStatRaw @sTopStatRaw

    $sTopStatCalc = @{
        TopValue = [ref]$topArray
        Verbose = $VerbosePreference
    }
    New-Object PSObject -Property @{
        VMHost = $VMHost
        EsxTop = Invoke-TopCalc @sTopStatCalc
        GetStat = $statArray
    }

    if(!$wasConnected){
        Disconnect-VIServer -Server $VMHost.Name -Confirm:$false
    }

    Write-Verbose -Message "$(Get-Date -F 'dd-MM-yy hh:mm:ss') $($s = Get-PSCallStack;"<Leaving {0}" -f $s[0].FunctionName)" 
}

function Format-TopData{
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSObject[]]$InputObject,
        [ValidateSet('CpuHeader','PortHeader')]
        [String[]]$Page,
        [Switch]$GetStat
    )

    Process{
        Write-Verbose -Message "$(Get-Date -F 'dd-MM-yy hh:mm:ss') $($s = Get-PSCallStack;">Entering {0}" -f $s[0].FunctionName)"
        
        foreach($p in $Page){
            switch($p){
                'CpuHeader'{
                    $lineProps = 'PCPU USED(%)','PCPU UTIL(%)','CORE UTIL(%)'
                    $htActive = $InputObject.VMHost.HyperthreadingActive
                    if($GetStat){
                        $statSlices = @($InputObject.GetStat | Group-Object -Property Timestamp)
                        $statIndex = 0
                        $halfTopInterval = New-TimeSpan -Seconds ([math]::Floor($TopInterval/2))
                        $statPassed = $false
                    }
                    $InputObject.EsxTop |
                    where{$_.Counter -eq 'LCPU'} | 
                    Group-Object -Property TimeStamp | %{
                        foreach($lineProp in $lineProps){
                            $topTimestamp = [DateTime]::Parse($_.Name)
                            $line = @()
                            $line += $topTimestamp.ToLongTimeString()
                            $line += "$($lineProp):"
                            $total = 0
                            $count= 0
                            $_.Group | Group-Object -Property LCPUID | %{
                                if($lineProp -eq 'CORE UTIL(%)' -and $htActive -and ([int]$_.Name % 2 -eq 1)){
                                    $line += (' '*5)
                                }
                                else{
                                    $line += ("{0,5}" -f ("{0:G2}" -f $_.Group."$($lineProp)"))
                                    $total += $_.Group."$($lineProp)"
                                    $count++
                                }
                            }
                            $avg = $total/$Count
                            $line += "{0,-9}" -f "AVG: $([math]::Round($avg,1))"
                            if($GetStat -and $statIndex -lt $statSlices.Count){
                                $statTimestamp = ([DateTime]::Parse($statSlices[$statIndex].Name))
                                if($topTimestamp -ge $statTimestamp){
                                    $statPassed = $true
                                    $line += "`t$($statTimestamp.ToLongTimeString())"
                                    $metric = $Script:TopMetric.EsxTopMetrics | where{$_.EsxTop -eq $lineProp} | Select -ExpandProperty StatMetric
                                    $line += ('{0,30}' -f $metric)
                                    $total = 0
                                    $count = 0
                                    $statSlices[$statIndex].Group | where{$_.MetricId -eq $metric -and $_.Instance -ne ''} |
                                    Sort-Object -Property Instance | %{
                                        if($lineProp -eq 'CORE UTIL(%)' -and $htActive -and ([int]$_.Instance % 2 -eq 1)){
                                            $line += (' '*5)
                                        }
                                        else{
                                            $line += ("{0,5}" -f $_.Value)
                                            $total += $_.Value
                                            $count++
                                        }
                                    }
                                    $avg = $total/$count
                                    $line += "{0,-9}" -f "AVG: $([math]::Round($avg,1))"
                                }
                            }
                            $line -join ' '
                        }
                        if($statPassed){
                            $statIndex++
                            $statPassed = $false
                        }
                    }
                }
                'PortHeader'{}
            }
        }

        Write-Verbose -Message "$(Get-Date -F 'dd-MM-yy hh:mm:ss') $($s = Get-PSCallStack;"<Leaving {0}" -f $s[0].FunctionName)" 
    }
}
