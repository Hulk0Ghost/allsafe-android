pipeline {
    agent any

    environment {
        MOBSF_SERVER  = "http://mobsf:8000"
        MOBSF_API_KEY = credentials('MOBSF_API_KEY')
        APK_PATH      = "samples/allsafe.apk"
    }

    stages {

        stage('Checkout') {
            steps {
                echo '📥 Pulling code from GitHub...'
                checkout scm
            }
        }

        stage('Verify APK') {
            steps {
                echo '🔍 Checking APK exists...'
                sh '''
                    if [ ! -f "${APK_PATH}" ]; then
                        echo "APK not found!"
                        exit 1
                    fi
                    echo "APK found: $(ls -lh ${APK_PATH})"
                '''
            }
        }

        stage('Upload APK to MobSF') {
            steps {
                echo '📤 Uploading APK to MobSF...'
                script {
                    def upload = sh(
                        script: '''
                            curl -s \
                            -F "file=@${APK_PATH}" \
                            -H "Authorization: ${MOBSF_API_KEY}" \
                            ${MOBSF_SERVER}/api/v1/upload
                        ''',
                        returnStdout: true
                    ).trim()

                    echo "Response: ${upload}"
                    env.FILE_HASH = sh(
                        script: "echo '${upload}' | jq -r '.hash'",
                        returnStdout: true
                    ).trim()
                    echo "File Hash: ${env.FILE_HASH}"
                }
            }
        }

        stage('Trigger SAST Scan') {
            steps {
                echo '🔬 Scanning with MobSF...'
                sh '''
                    curl -s \
                    -d "hash=${FILE_HASH}&re_scan=0" \
                    -H "Authorization: ${MOBSF_API_KEY}" \
                    ${MOBSF_SERVER}/api/v1/scan
                '''
                echo 'Scan complete!'
            }
        }

        stage('Download Report') {
            steps {
                echo '📄 Getting PDF report...'
                sh '''
                    curl -s \
                    -d "hash=${FILE_HASH}" \
                    -H "Authorization: ${MOBSF_API_KEY}" \
                    ${MOBSF_SERVER}/api/v1/download_pdf \
                    -o mobsf_report.pdf

                    curl -s \
                    -d "hash=${FILE_HASH}" \
                    -H "Authorization: ${MOBSF_API_KEY}" \
                    ${MOBSF_SERVER}/api/v1/report_json \
                    -o mobsf_report.json
                '''
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    def score = sh(
                        script: "cat mobsf_report.json | jq -r '.average_cvss'",
                        returnStdout: true
                    ).trim().toFloat()

                    echo "🔐 CVSS Score: ${score}"

                    if (score > 6.0) {
                        error("❌ FAILED! CVSS ${score} exceeds threshold 6.0")
                    } else {
                        echo "✅ PASSED! Score: ${score}"
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'mobsf_report.pdf, mobsf_report.json',
                             allowEmptyArchive: true
        }
        success { echo '✅ Build PASSED' }
        failure { echo '❌ Build FAILED - Security issues found!' }
    }
}