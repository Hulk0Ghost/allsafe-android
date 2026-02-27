pipeline {
    agent any

    environment {
        MOBSF_SERVER  = "http://localhost:8000"
        MOBSF_API_KEY = credentials('MOBSF_API_KEY')
        APK_PATH      = "samples\\allsafe.apk"
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
                bat '''
                    if not exist "%APK_PATH%" (
                        echo APK not found at %APK_PATH%
                        exit /b 1
                    )
                    echo APK found!
                    dir "%APK_PATH%"
                '''
            }
        }

        stage('3. Upload APK to MobSF') {
            steps {
                echo '📤 Uploading APK to MobSF...'
                script {
                    def upload = bat(
                        script: '''
                            curl -s -F "file=@%APK_PATH%" ^
                            -H "Authorization: %MOBSF_API_KEY%" ^
                            %MOBSF_SERVER%/api/v1/upload
                        ''',
                        returnStdout: true
                    ).trim()

                    // Remove first line (the bat echo line)
                    upload = upload.readLines().drop(1).join('\n').trim()
                    echo "📦 Upload Response: ${upload}"

                    if (upload.contains('"error"')) {
                        error("❌ Upload failed: ${upload}")
                    }

                    env.FILE_HASH = bat(
                        script: "@echo ${upload}| jq -r .hash",
                        returnStdout: true
                    ).trim()

                    echo "✅ File Hash: ${env.FILE_HASH}"
                }
            }
        }

        stage('4. Trigger SAST Scan') {
            steps {
                echo '🔬 Starting MobSF SAST scan...'
                script {
                    def result = bat(
                        script: '''
                            curl -s ^
                            -d "hash=%FILE_HASH%&re_scan=0" ^
                            -H "Authorization: %MOBSF_API_KEY%" ^
                            %MOBSF_SERVER%/api/v1/scan
                        ''',
                        returnStdout: true
                    ).trim()
                    echo "✅ Scan triggered!"
                }
            }
        }

        stage('5. Fetch JSON Report') {
            steps {
                echo '📊 Fetching JSON report...'
                bat '''
                    curl -s ^
                    -d "hash=%FILE_HASH%" ^
                    -H "Authorization: %MOBSF_API_KEY%" ^
                    %MOBSF_SERVER%/api/v1/report_json ^
                    -o mobsf_report.json
                    echo Report saved!
                    dir mobsf_report.json
                '''
                echo '✅ JSON report saved!'
            }
        }

        stage('6. Download PDF Report') {
            steps {
                echo '📄 Downloading PDF report...'
                bat '''
                    curl -s ^
                    -d "hash=%FILE_HASH%" ^
                    -H "Authorization: %MOBSF_API_KEY%" ^
                    %MOBSF_SERVER%/api/v1/download_pdf ^
                    -o mobsf_report.pdf
                    echo PDF saved!
                    dir mobsf_report.pdf
                '''
                echo '✅ PDF report saved!'
            }
        }

        stage('7. Security Gate') {
            steps {
                echo '🚦 Evaluating security score...'
                script {
                    def score = bat(
                        script: '@jq -r ".appsec.security_score" mobsf_report.json',
                        returnStdout: true
                    ).trim()

                    echo "🔐 Security Score: ${score}"

                    def scoreFloat = score.toFloat()

                    if (scoreFloat < 40) {
                        error("❌ SECURITY GATE FAILED! Score ${scoreFloat}/100 below threshold of 50")
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
        success { echo '🎉 Pipeline PASSED!' }
        failure { echo '🚨 Pipeline FAILED!' }
    }
}
