pipeline {
  agent any

  options {
    timestamps()
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
          Write-Host "WORKSPACE = $env:WORKSPACE"

          docker version
          docker info

          $ws = $env:WORKSPACE.Replace("\\","/")
          Write-Host "MOUNT PATH = $ws"

          docker pull opensecurity/mobsfscan:latest
          docker run --rm -v "${ws}:/src" opensecurity/mobsfscan /src --json -o /src/mobsfscan-report.json

          if (!(Test-Path "mobsfscan-report.json")) {
            Write-Error "mobsfscan-report.json not created!"
            exit 1
          }

          Get-Item mobsfscan-report.json | Format-List
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
