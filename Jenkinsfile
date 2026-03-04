pipeline {
  agent any

  options {
    timestamps()
    // If you keep your own Checkout stage, avoid the automatic one
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

          # Run scan (do NOT fail build here; gating happens next)
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

    stage('Gate (fail on High/Critical)') {
      steps {
        powershell '''
          $ErrorActionPreference = "Stop"

          $json = Get-Content "mobsfscan-report.json" -Raw | ConvertFrom-Json

          # mobsfscan JSON shape can vary: results/findings/issues
          $findings = @()
          if ($json.results) { $findings = $json.results }
          elseif ($json.findings) { $findings = $json.findings }
          elseif ($json.issues) { $findings = $json.issues }

          function Get-Sev($f) {
            foreach ($k in @("severity","level","risk","issue_severity")) {
              if ($f.PSObject.Properties.Name -contains $k -and $f.$k) {
                return $f.$k.ToString().ToUpper()
              }
            }
            return "UNKNOWN"
          }

          $hc = @()
          foreach ($f in $findings) {
            $s = Get-Sev $f
            if ($s -eq "HIGH" -or $s -eq "CRITICAL") { $hc += $f }
          }

          Write-Host ("Total findings: {0}" -f $findings.Count)
          Write-Host ("High/Critical: {0}" -f $hc.Count)

          if ($hc.Count -gt 0) {
            Write-Host "❌ FAIL: High/Critical findings detected."
            exit 2
          }

          Write-Host "✅ PASS: No High/Critical findings."
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
