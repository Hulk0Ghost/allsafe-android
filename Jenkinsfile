pipeline {
  agent any

  options {
    timestamps()
    skipDefaultCheckout(true)
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('MobSFScan (Docker, code-only)') {
      steps {
        powershell '''
          $ErrorActionPreference = "Stop"

          $ws = $env:WORKSPACE.Replace("\\","/")
          Write-Host "WORKSPACE  = $env:WORKSPACE"
          Write-Host "MOUNT PATH = $ws"

          docker pull opensecurity/mobsfscan:latest | Out-Host

          # Run scan (mobsfscan may return exit code 1 if findings exist; ignore it)
          docker run --rm -v "${ws}:/src" opensecurity/mobsfscan /src --json -o /src/mobsfscan-report.json
          $scanExit = $LASTEXITCODE
          Write-Host "mobsfscan exit code = $scanExit (ignored here)"

          if (!(Test-Path "mobsfscan-report.json")) {
            Write-Error "mobsfscan-report.json was not created!"
            exit 1
          }

          # Always succeed this stage
          exit 0
        '''
      }
    }

    stage('MobSFScan Summary (do not block)') {
      steps {
        powershell '''
          $report = "mobsfscan-report.json"
          if (!(Test-Path $report)) {
            Write-Host "⚠️ mobsfscan report not found: $report (continuing)"
            exit 0
          }

          $json = Get-Content $report -Raw | ConvertFrom-Json

          $rulesTriggered = 0
          $totalMatches = 0

          $sevCounts = @{
            ERROR=0; WARNING=0; INFO=0; UNKNOWN=0
          }

          $top = @()

          foreach ($p in $json.results.PSObject.Properties) {
            $rulesTriggered++
            $ruleId = $p.Name
            $ruleObj = $p.Value

            $sev = $ruleObj.metadata.severity
            if (-not $sev) { $sev = "UNKNOWN" }
            $sev = $sev.ToString().ToUpper()
            if (-not $sevCounts.ContainsKey($sev)) { $sevCounts[$sev] = 0 }

            $files = $ruleObj.files
            if ($files) {
              $count = @($files).Count
              $totalMatches += $count
              $sevCounts[$sev] += $count

              foreach ($f in $files | Select-Object -First 10) {
                $top += [PSCustomObject]@{
                  rule_id  = $ruleId
                  severity = $sev
                  file     = $f.file_path
                  lines    = ($f.match_lines -join "-")
                }
              }
            } else {
              # Rule present without files list
              $sevCounts[$sev] += 1
            }
          }

          Write-Host "================ MobSFScan Summary ================"
          Write-Host ("Rules triggered : {0}" -f $rulesTriggered)
          Write-Host ("Total matches   : {0}" -f $totalMatches)
          Write-Host ""
          Write-Host "Severity breakdown (by matches):"
          $sevCounts.GetEnumerator() | Sort-Object Name | Format-Table Name,Value -AutoSize | Out-String | Write-Host

          Write-Host ""
          Write-Host "Top findings (sample):"
          $top | Select-Object -First 15 | Format-Table -AutoSize | Out-String | Write-Host
          Write-Host "==================================================="

          Write-Host "✅ PASS (policy): Not blocking PR on findings."
          exit 0
        '''
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'mobsfscan-report.json', fingerprint: true
    }
  }
}
