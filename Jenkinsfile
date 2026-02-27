pipeline {
    agent any

    environment {
        MOBSF_SERVER  = "http://localhost:8000"
        MOBSF_API_KEY = credentials('MOBSF_API_KEY')
        APK_PATH      = "samples\\allsafe.apk"
        PACKAGE_NAME  = "infosecadventures.allsafe"
    }

    stages {

        // ─── SAST STAGES ────────────────────────────────────────

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
                        echo APK not found!
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

                    upload = upload.readLines().drop(1).join('\n').trim()
                    echo "📦 Upload Response: ${upload}"

                    if (upload.contains('"error"')) {
                        error("❌ Upload failed: ${upload}")
                    }

                    env.FILE_HASH = bat(
                        script: "@echo ${upload}| C:\\Windows\\System32\\jq.exe -r .hash",
                        returnStdout: true
                    ).trim()

                    echo "✅ File Hash: ${env.FILE_HASH}"
                }
            }
        }

        stage('4. Trigger SAST Scan') {
            steps {
                echo '🔬 Starting SAST scan...'
                bat '''
                    curl -s ^
                    -d "hash=%FILE_HASH%&re_scan=0" ^
                    -H "Authorization: %MOBSF_API_KEY%" ^
                    %MOBSF_SERVER%/api/v1/scan
                '''
                echo '✅ SAST scan complete!'
            }
        }

        stage('5. Fetch SAST Report') {
            steps {
                echo '📊 Fetching SAST JSON report...'
                bat '''
                    curl -s ^
                    -d "hash=%FILE_HASH%" ^
                    -H "Authorization: %MOBSF_API_KEY%" ^
                    %MOBSF_SERVER%/api/v1/report_json ^
                    -o sast_report.json
                    dir sast_report.json
                '''
                echo '✅ SAST report saved!'
            }
        }

        // ─── DAST STAGES ────────────────────────────────────────

        stage('6. Start Dynamic Analysis') {
            steps {
                echo '📱 Starting DAST on emulator...'
                script {
                    def dastStart = bat(
                        script: '''
                            curl -s ^
                            -d "hash=%FILE_HASH%&re_install=1&activity=1" ^
                            -H "Authorization: %MOBSF_API_KEY%" ^
                            %MOBSF_SERVER%/api/v1/dynamic/start_analysis
                        ''',
                        returnStdout: true
                    ).trim()

                    dastStart = dastStart.readLines().drop(1).join('\n').trim()
                    echo "📱 DAST Start Response: ${dastStart}"

                    if (dastStart.contains('"error"')) {
                        error("❌ DAST start failed: ${dastStart}")
                    }
                    echo '✅ App installed and DAST started!'
                }
            }
        }

        stage('7. Exercise App (ADB Monkey)') {
            steps {
                echo '🐒 Running ADB Monkey to exercise app...'
                bat '''
                    :: Wait for app to fully launch
                    timeout /t 10 /nobreak

                    :: Launch the app
                    adb shell am start -n %PACKAGE_NAME%/.MainActivity

                    :: Wait for app to load
                    timeout /t 5 /nobreak

                    :: Run monkey to simulate user interactions (500 events)
                    adb shell monkey -p %PACKAGE_NAME% ^
                        --throttle 300 ^
                        --ignore-crashes ^
                        --ignore-timeouts ^
                        -v 500

                    echo Monkey testing complete!
                '''
                echo '✅ App exercised successfully!'
            }
        }

        stage('8. Stop Dynamic Analysis') {
            steps {
                echo '🛑 Stopping DAST and collecting results...'
                script {
                    def dastStop = bat(
                        script: '''
                            curl -s ^
                            -d "hash=%FILE_HASH%" ^
                            -H "Authorization: %MOBSF_API_KEY%" ^
                            %MOBSF_SERVER%/api/v1/dynamic/stop_analysis
                        ''',
                        returnStdout: true
                    ).trim()

                    dastStop = dastStop.readLines().drop(1).join('\n').trim()
                    echo "🛑 DAST Stop Response: ${dastStop}"
                    echo '✅ DAST stopped!'
                }
            }
        }

        stage('9. Fetch DAST Report') {
            steps {
                echo '📊 Fetching DAST report...'
                bat '''
                    curl -s ^
                    -d "hash=%FILE_HASH%" ^
                    -H "Authorization: %MOBSF_API_KEY%" ^
                    %MOBSF_SERVER%/api/v1/report_json ^
                    -o dast_report.json
                    dir dast_report.json
                '''
                echo '✅ DAST report saved!'
            }
        }

        stage('10. Download PDF Reports') {
            steps {
                echo '📄 Downloading PDF reports...'
                bat '''
                    curl -s ^
                    -d "hash=%FILE_HASH%" ^
                    -H "Authorization: %MOBSF_API_KEY%" ^
                    %MOBSF_SERVER%/api/v1/download_pdf ^
                    -o mobsf_final_report.pdf
                    dir mobsf_final_report.pdf
                '''
                echo '✅ PDF report saved!'
            }
        }

        // ─── SECURITY GATE ──────────────────────────────────────

        stage('11. Combined Security Gate') {
    steps {
        echo '🚦 Evaluating combined SAST + DAST score...'
        script {
            def sastScore = bat(
                script: '@C:\\Windows\\System32\\jq.exe -r ".appsec.security_score // 0" sast_report.json',
                returnStdout: true
            ).trim().toFloat()

            def dastScore = bat(
                script: '@C:\\Windows\\System32\\jq.exe -r ".appsec.security_score // 0" dast_report.json',
                returnStdout: true
            ).trim().toFloat()

            def combinedScore = (sastScore + dastScore) / 2

            echo "📊 SAST Score:     ${sastScore}/100"
            echo "📊 DAST Score:     ${dastScore}/100"
            echo "📊 Combined Score: ${combinedScore}/100"

            if (combinedScore < 40) {
                error("❌ FAILED! Combined score ${combinedScore}/100")
            } else {
                echo "✅ PASSED! Score: ${combinedScore}/100"
            }
        }
    }
}
    post {
        always {
            echo '📁 Archiving all reports...'
            archiveArtifacts artifacts: 'sast_report.json, dast_report.json, mobsf_final_report.pdf',
                             allowEmptyArchive: true
        }
        success { echo '🎉 Full SAST + DAST Pipeline PASSED!' }
        failure { echo '🚨 Pipeline FAILED - Check the red stage!' }
    }
}
