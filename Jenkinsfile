stage('MobSFScan (Docker, code-only)') {
  steps {
    powershell '''
      Write-Host "WORKSPACE = $env:WORKSPACE"
      docker version
      docker info

      # Make sure path uses backslashes removed for docker mount
      $ws = $env:WORKSPACE.Replace("\\","/")
      Write-Host "MOUNT PATH = $ws"

      # Pull (ok)
      docker pull opensecurity/mobsfscan:latest

      # Run scan (this is the important part)
      docker run --rm -v "${ws}:/src" opensecurity/mobsfscan /src --json -o /src/mobsfscan-report.json

      # Verify file exists
      dir mobsfscan-report.json
    '''
  }
}
