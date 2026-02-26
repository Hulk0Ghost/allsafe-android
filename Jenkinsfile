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
            // appsec contains the real score
            sh "cat mobsf_report.json | jq '.appsec'"

            def score = sh(
                script: "cat mobsf_report.json | jq -r '.appsec.security_score'",
                returnStdout: true
            ).trim()

            echo "🔐 Security Score: ${score}"

            if (score == "null" || score == "") {
                // Try alternative fields
                score = sh(
                    script: "cat mobsf_report.json | jq -r '.appsec.total_trackers // .trackers | length // 0'",
                    returnStdout: true
                ).trim()
                echo "⚠️ Fallback score: ${score}"
            }

            def scoreFloat = score.toFloat()
            echo "🔐 Final Score: ${scoreFloat} / 100"

            if (scoreFloat < 50) {
                error("❌ SECURITY GATE FAILED! Score ${scoreFloat}/100 is below threshold of 50")
            } else {
                echo "✅ SECURITY GATE PASSED! Score: ${scoreFloat}/100"
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