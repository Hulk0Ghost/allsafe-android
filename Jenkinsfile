pipeline {
  agent any

  stages {
    stage('Checkout') {
      steps { checkout scm }
    }

    stage('MobSFScan (Docker, code-only)') {
      steps {
        powershell '''
          docker pull opensecurity/mobsfscan:latest

          # Run scan and write JSON into workspace
          docker run --rm -v "${env:WORKSPACE}:/src" opensecurity/mobsfscan /src --json -o /src/mobsfscan-report.json
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
