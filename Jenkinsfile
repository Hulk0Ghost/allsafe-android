pipeline {
  agent any

  options {
    timestamps()
    skipDefaultCheckout(true)
  }

  environment {
    // Tune semgrep rulesets if you want
    SEMGREP_CONFIGS = "p/owasp-top-ten p/security-audit p/java p/javascript"
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

          # mobsfscan may return exit code 1 when findings exist; ignore it
          docker run --rm -v "${ws}:/src" opensecurity/mobsfscan /src --json -o /src/mobsfscan-report.json
          $scanExit = $LASTEXITCODE
          Write-Host "mobsfscan exit code = $scanExit (ignored)"

          if (!(Test-Path "mobsfscan-report.json")) {
            Write-Error "mobsfscan-report.json was not created!"
            exit 1
          }

          exit 0
        '''
      }
    }

    stage('Semgrep (Docker) - Java/Kotlin/JS') {
      steps {
        powershell '''
          $ErrorActionPreference = "Stop"
          $ws = $env:WORKSPACE.Replace("\\","/")

          docker pull returntocorp/semgrep:latest | Out-Host

          # Build semgrep args from env var list
          $configs = $env:SEMGREP_CONFIGS.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
          $configArgs = @()
          foreach ($c in $configs) { $configArgs += @("--config", $c) }

          # Run semgrep; do not fail pipeline on findings (exit code might be non-zero)
          docker run --rm -v "${ws}:/src" returntocorp/semgrep semgrep `
            @configArgs `
            --json -o /src/semgrep-report.json /src

          if (!(Test-Path "semgrep-report.json")) {
            Write-Error "semgrep-report.json was not created!"
            exit 1
          }

          exit 0
        '''
      }
    }

    stage('Gitleaks (Docker) - Secrets') {
      steps {
        powershell '''
          $ErrorActionPreference = "Stop"
          $ws = $env:WORKSPACE.Replace("\\","/")

          docker pull zricethezav/gitleaks:latest | Out-Host

          # detect returns non-zero if leaks found; we ignore exit code and rely on the report
          docker run --rm -v "${ws}:/src" zricethezav/gitleaks:latest detect `
            --source="/src" `
            --report-format="json" `
            --report-path="/src/gitleaks-report.json" `
            --redact
          $exitCode = $LASTEXITCODE
          Write-Host "gitleaks exit code = $exitCode (ignored)"

          # If no leaks, gitleaks may still write an empty report; ensure file exists
          if (!(Test-Path "gitleaks-report.json")) {
            # Create empty report for consistency
            "[]" | Out-File -Encoding utf8 "gitleaks-report.json"
          }

          exit 0
        '''
      }
    }

    stage('Console Summary (do not block)') {
      steps {
        powershell '''
          $ErrorActionPreference = "Stop"

          function Read-Json($path) {
            if (Test-Path $path) { return (Get-Content $path -Raw | ConvertFrom-Json) }
            return $null
          }

          # ---- MobSFScan summary ----
          $mobsf = Read-Json "mobsfscan-report.json"
          $mobsfRules = 0
          $mobsfMatches = 0
          $mobsfSev = @{ ERROR=0; WARNING=0; INFO=0; UNKNOWN=0 }

          if ($mobsf -and $mobsf.results) {
            foreach ($p in $mobsf.results.PSObject.Properties) {
              $mobsfRules++
              $rule = $p.Value
              $sev = $rule.metadata.severity
              if (-not $sev) { $sev = "UNKNOWN" }
              $sev = $sev.ToString().ToUpper()
              if (-not $mobsfSev.ContainsKey($sev)) { $mobsfSev[$sev] = 0 }

              if ($rule.files) {
                $c = @($rule.files).Count
                $mobsfMatches += $c
                $mobsfSev[$sev] += $c
              } else {
                $mobsfSev[$sev] += 1
              }
            }
          }

          # ---- Semgrep summary ----
          $sem = Read-Json "semgrep-report.json"
          $semTotal = 0
          if ($sem -and $sem.results) { $semTotal = @($sem.results).Count }

          # ---- Gitleaks summary ----
          $gl = Read-Json "gitleaks-report.json"
          $glTotal = 0
          if ($gl) { $glTotal = @($gl).Count }

          Write-Host "================ Security Summary ================"
          Write-Host ("MobSFScan: rules={0} matches={1} | ERROR={2} WARNING={3} INFO={4}" -f `
            $mobsfRules, $mobsfMatches, $mobsfSev["ERROR"], $mobsfSev["WARNING"], $mobsfSev["INFO"])
          Write-Host ("Semgrep : findings={0}" -f $semTotal)
          Write-Host ("Gitleaks: leaks={0}" -f $glTotal)
          Write-Host "=================================================="
          Write-Host "✅ PASS (policy): Not blocking PR on findings."
        '''
      }
    }

    stage('Comment on GitHub PR (summary)') {
      when {
        expression { return env.CHANGE_ID != null && env.CHANGE_ID.trim() != "" }
      }
      steps {
        withCredentials([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
          powershell '''
            $ErrorActionPreference = "Stop"

            function Read-Json($path) {
              if (Test-Path $path) { return (Get-Content $path -Raw | ConvertFrom-Json) }
              return $null
            }

            # Parse owner/repo from CHANGE_URL: https://github.com/<owner>/<repo>/pull/<id>/
            $changeUrl = $env:CHANGE_URL
            if (-not $changeUrl) {
              Write-Host "No CHANGE_URL; skipping PR comment."
              exit 0
            }

            $m = [regex]::Match($changeUrl, "github\\.com/(?<owner>[^/]+)/(?<repo>[^/]+)/pull/(?<pr>\\d+)")
            if (-not $m.Success) {
              Write-Host "Could not parse GitHub owner/repo/pr from CHANGE_URL: $changeUrl"
              exit 0
            }

            $owner = $m.Groups["owner"].Value
            $repo  = $m.Groups["repo"].Value
            $prNum = $m.Groups["pr"].Value

            # ---- MobSFScan summary ----
            $mobsf = Read-Json "mobsfscan-report.json"
            $mobsfRules = 0
            $mobsfMatches = 0
            $mobsfSev = @{ ERROR=0; WARNING=0; INFO=0; UNKNOWN=0 }

            if ($mobsf -and $mobsf.results) {
              foreach ($p in $mobsf.results.PSObject.Properties) {
                $mobsfRules++
                $rule = $p.Value
                $sev = $rule.metadata.severity
                if (-not $sev) { $sev = "UNKNOWN" }
                $sev = $sev.ToString().ToUpper()
                if (-not $mobsfSev.ContainsKey($sev)) { $mobsfSev[$sev] = 0 }

                if ($rule.files) {
                  $c = @($rule.files).Count
                  $mobsfMatches += $c
                  $mobsfSev[$sev] += $c
                } else {
                  $mobsfSev[$sev] += 1
                }
              }
            }

            # ---- Semgrep summary ----
            $sem = Read-Json "semgrep-report.json"
            $semTotal = 0
            if ($sem -and $sem.results) { $semTotal = @($sem.results).Count }

            # ---- Gitleaks summary ----
            $gl = Read-Json "gitleaks-report.json"
            $glTotal = 0
            if ($gl) { $glTotal = @($gl).Count }

            # Build comment body (markdown)
            $body = @"
### ✅ Security Scan Summary (Jenkins)

| Tool | Result |
|---|---|
| MobSFScan | Rules: **$mobsfRules**, Matches: **$mobsfMatches** (ERROR: **$($mobsfSev["ERROR"])**, WARNING: **$($mobsfSev["WARNING"])**, INFO: **$($mobsfSev["INFO"])**) |
| Semgrep | Findings: **$semTotal** |
| Gitleaks | Leaks: **$glTotal** |

Artifacts in Jenkins:
- `mobsfscan-report.json`
- `semgrep-report.json`
- `gitleaks-report.json`

_Policy: This pipeline reports findings but does **not** block merges._
"@

            $api = "https://api.github.com/repos/$owner/$repo/issues/$prNum/comments"

            $headers = @{
              "Authorization" = "token $env:GITHUB_TOKEN"
              "Accept"        = "application/vnd.github+json"
              "User-Agent"    = "jenkins"
            }

            $payload = @{ body = $body } | ConvertTo-Json

            Write-Host "Posting comment to PR #$prNum in $owner/$repo ..."
            Invoke-RestMethod -Method Post -Uri $api -Headers $headers -Body $payload -ContentType "application/json" | Out-Null
            Write-Host "✅ PR comment posted."
          '''
        }
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'mobsfscan-report.json, semgrep-report.json, gitleaks-report.json', fingerprint: true
    }
  }
}
