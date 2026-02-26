pipeline {
    agent any

    environment {
        MOBSF_SERVER  = "http://mobsf:8000"
        MOBSF_API_KEY = credentials('MOBSF_API_KEY')
        APK_PATH      = "samples/allsafe.apk"
    }

    stages {

        stage('1. Checkout Code') {
            steps {
                echo '📥 Pulling code from GitHub...'
                checkout scm
                echo '✅ Code pulled successfully'
            }
        }

        stage('2. Verify APK') {
            steps {
                echo '🔍 Checking APK exists...'
                sh '''
                    if [ ! -f "${APK_PATH}" ]; then
                        echo "❌ APK not found at ${APK_PATH}"
                        exit 1
                    fi
                    echo "✅ APK found: $(ls -lh ${APK_PATH})"
                '''
            }
        }

        stage('3. Upload APK to MobSF') {
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

                    echo "📦 Upload Response: ${upload}"

                    // Check for error in response
                    if (upload.contains('"error"')) {
                        error("❌ Upload failed: ${upload}")
                    }

                    env.FILE_HASH = sh(
                        script: "echo '${upload}' | jq -r '.hash'",
                        returnStdout: true
                    ).trim()

                    echo "✅ Upload successful! Hash: ${env.FILE_HASH}"
                }
            }
        }

        stage('4. Trigger SAST Scan') {
            steps {
                echo '🔬 Starting MobSF SAST scan...'
                script {
                    def scanResult = sh(
                        script: '''
                            curl -s \
                            -d "hash=${FILE_HASH}&re_scan=0" \
                            -H "Authorization: ${MOBSF_API_KEY}" \
                            ${MOBSF_SERVER}/api/v1/scan
                        ''',
                        returnStdout: true
                    ).trim()
                    echo "🔬 Scan Response: ${scanResult}"
                    echo '✅ Scan triggered successfully!'
                }
            }
        }

        stage('5. Fetch JSON Report') {
            steps {
                echo '📊 Fetching JSON report...'
                sh '''
                    curl -s \
                    -d "hash=${FILE_HASH}" \
                    -H "Authorization: ${MOBSF_API_KEY}" \
                    ${MOBSF_SERVER}/api/v1/report_json \
                    -o mobsf_report.json

                    echo "Report size: $(ls -lh mobsf_report.json)"
                '''
                echo '✅ JSON report saved!'
            }
        }

        stage('6. Download PDF Report') {
            steps {
                echo '📄 Downloading PDF report...'
                sh '''
                    curl -s \
                    -d "hash=${FILE_HASH}" \
                    -H "Authorization: ${MOBSF_API_KEY}" \
                    ${MOBSF_SERVER}/api/v1/download_pdf \
                    -o mobsf_report.pdf

                    echo "PDF size: $(ls -lh mobsf_report.pdf)"
                '''
                echo '✅ PDF report saved!'
            }
        }

        stage('7. Security Gate') {
    steps {
        echo '🚦 Evaluating security score...'
        script {
            // First lets see whats in the report
            sh "cat mobsf_report.json | jq '{score: .average_cvss, security_score: .security_score}'"

            def score = sh(
                script: """
                    cat mobsf_report.json | jq -r '
                    if .average_cvss != null then .average_cvss
                    elif .security_score != null then .security_score
                    else "0"
                    end'
                """,
                returnStdout: true
            ).trim()

            echo "🔐 Score found: ${score}"

            if (score == "null" || score == "" || score == "0") {
                echo "⚠️ Score is null/empty - printing full report keys for debug:"
                sh "cat mobsf_report.json | jq 'keys'"
                error("❌ Could not extract security score from report!")
            }

            def scoreFloat = score.toFloat()
            echo "🔐 CVSS Score: ${scoreFloat}"

            if (scoreFloat > 6.0) {
                error("❌ SECURITY GATE FAILED! Score ${scoreFloat} exceeds threshold 6.0")
            } else {
                echo "✅ SECURITY GATE PASSED! Score: ${scoreFloat}"
            }
        }
    }
}
    }

    post {
        always {
            echo '📁 Archiving reports...'
            archiveArtifacts artifacts: 'mobsf_report.pdf, mobsf_report.json',
                             allowEmptyArchive: true
        }
        success {
            echo '🎉 Pipeline PASSED - App is secure enough!'
        }
        failure {
            echo '🚨 Pipeline FAILED - Check the stage that went red!'
        }
    }
}