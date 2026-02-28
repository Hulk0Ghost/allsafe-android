pipeline {
    agent any

    environment {
        MOBSF_SERVER  = "http://localhost:8000"
        MOBSF_API_KEY = credentials('MOBSF_API_KEY')
        GROQ_API_KEY  = credentials('GROQ_API_KEY')
        APK_PATH      = "samples\\allsafe.apk"
        PACKAGE_NAME  = "infosecadventures.allsafe"
        OUTPUT_DIR    = "validation_output"
    }

    stages {

        // ─── STAGE 1 ────────────────────────────
        stage('1. Checkout Code') {
            steps {
                echo 'Pulling code from GitHub...'
                checkout scm
                echo 'Code pulled successfully'
            }
        }

        // ─── STAGE 2 ────────────────────────────
        stage('2. Verify APK') {
            steps {
                echo 'Checking APK exists...'
                bat '''
                    if not exist "samples\\allsafe.apk" (
                        echo APK not found!
                        exit /b 1
                    )
                    echo APK found!
                    dir "samples\\allsafe.apk"
                '''
            }
        }

        // ─── STAGE 3 ────────────────────────────
        stage('3. Upload APK to MobSF') {
            steps {
                echo 'Uploading APK to MobSF...'
                script {
                    def upload = bat(
                        script: '''
                            curl -s -F "file=@samples\\allsafe.apk" ^
                            -H "Authorization: %MOBSF_API_KEY%" ^
                            http://localhost:8000/api/v1/upload
                        ''',
                        returnStdout: true
                    ).trim()

                    upload = upload.readLines().drop(1).join('\n').trim()
                    echo "Upload Response: ${upload}"

                    if (upload.contains('"error"')) {
                        error("Upload failed: ${upload}")
                    }

                    env.FILE_HASH = bat(
                        script: "@echo ${upload}| C:\\Windows\\System32\\jq.exe -r .hash",
                        returnStdout: true
                    ).trim()

                    echo "File Hash: ${env.FILE_HASH}"
                }
            }
        }

        // ─── STAGE 4 ────────────────────────────
        stage('4. Trigger SAST Scan') {
            steps {
                echo 'Starting SAST scan...'
                bat '''
                    curl -s ^
                    -d "hash=%FILE_HASH%&re_scan=0" ^
                    -H "Authorization: %MOBSF_API_KEY%" ^
                    http://localhost:8000/api/v1/scan
                '''
                echo 'SAST scan complete!'
            }
        }

        // ─── STAGE 5 ────────────────────────────
        stage('5. Fetch SAST Report') {
            steps {
                echo 'Fetching SAST report...'
                bat '''
                    curl -s ^
                    -d "hash=%FILE_HASH%" ^
                    -H "Authorization: %MOBSF_API_KEY%" ^
                    http://localhost:8000/api/v1/report_json ^
                    -o sast_report.json
                '''
                echo 'SAST report saved!'
            }
        }

        // ─── STAGE 6 ────────────────────────────
        stage('6. Start Dynamic Analysis') {
            steps {
                echo 'Starting DAST on emulator...'
                script {
                    def dastStart = bat(
                        script: '''
                            curl -s ^
                            -d "hash=%FILE_HASH%&re_install=1&activity=1" ^
                            -H "Authorization: %MOBSF_API_KEY%" ^
                            http://localhost:8000/api/v1/dynamic/start_analysis
                        ''',
                        returnStdout: true
                    ).trim()
                    dastStart = dastStart.readLines().drop(1).join('\n').trim()
                    echo "DAST Start Response: ${dastStart}"
                    echo 'DAST started!'
                }
            }
        }

        // ─── STAGE 7 ────────────────────────────
        stage('7. Exercise App (ADB Monkey)') {
            steps {
                echo 'Running ADB Monkey...'
                bat '''
                    timeout /t 10 /nobreak
                    adb shell am start -n infosecadventures.allsafe/.MainActivity
                    timeout /t 5 /nobreak
                    adb shell monkey -p infosecadventures.allsafe ^
                        --throttle 300 ^
                        --ignore-crashes ^
                        --ignore-timeouts ^
                        -v 500
                    echo Monkey testing complete!
                '''
                echo 'App exercised successfully!'
            }
        }

        // ─── STAGE 8 ────────────────────────────
        stage('8. Stop Dynamic Analysis') {
            steps {
                echo 'Stopping DAST...'
                script {
                    def dastStop = bat(
                        script: '''
                            curl -s ^
                            -d "hash=%FILE_HASH%" ^
                            -H "Authorization: %MOBSF_API_KEY%" ^
                            http://localhost:8000/api/v1/dynamic/stop_analysis
                        ''',
                        returnStdout: true
                    ).trim()
                    dastStop = dastStop.readLines().drop(1).join('\n').trim()
                    echo "DAST Stop Response: ${dastStop}"
                    echo 'DAST stopped!'
                }
            }
        }

        // ─── STAGE 9 ────────────────────────────
        stage('9. Fetch DAST Report') {
            steps {
                echo 'Fetching DAST report...'
                bat '''
                    curl -s ^
                    -d "hash=%FILE_HASH%" ^
                    -H "Authorization: %MOBSF_API_KEY%" ^
                    http://localhost:8000/api/v1/report_json ^
                    -o dast_report.json
                '''
                echo 'DAST report saved!'
            }
        }

        // ─── STAGE 10 ───────────────────────────
        stage('10. Download PDF Report') {
            steps {
                echo 'Downloading PDF report...'
                bat '''
                    curl -s ^
                    -d "hash=%FILE_HASH%" ^
                    -H "Authorization: %MOBSF_API_KEY%" ^
                    http://localhost:8000/api/v1/download_pdf ^
                    -o mobsf_final_report.pdf
                '''
                echo 'PDF report saved!'
            }
        }

        // ─── STAGE 11 ───────────────────────────
        stage('11. Combined Security Gate') {
            steps {
                echo 'Evaluating combined SAST + DAST score...'
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

                    echo "SAST Score:     ${sastScore}/100"
                    echo "DAST Score:     ${dastScore}/100"
                    echo "Combined Score: ${combinedScore}/100"

                    if (combinedScore < 50) {
                        echo "WARNING: Score ${combinedScore}/100 below threshold - continuing for AI validation"
                    } else {
                        echo "PASSED: Score ${combinedScore}/100"
                    }

                    env.COMBINED_SCORE = combinedScore.toString()
                }
            }
        }

        // ─── STAGE 12 ───────────────────────────
        stage('12. AI Validate Findings') {
            steps {
                echo 'Running AI validation with Groq...'
                script {
                    def ws = pwd()
                    bat """
                        if not exist validation_output mkdir validation_output
                        cd scripts
                        set PYTHONIOENCODING=utf-8
                        set PYTHONLEGACYWINDOWSSTDIO=utf-8
                        set MOBSF_SERVER=http://localhost:8000
                        set MOBSF_API_KEY=%MOBSF_API_KEY%
                        set CLAUDE_API_KEY=%GROQ_API_KEY%
                        set PACKAGE_NAME=infosecadventures.allsafe
                        set OUTPUT_DIR=${ws}\\validation_output
                        python validate_findings.py ${ws}\\sast_report.json ${ws}\\dast_report.json %FILE_HASH%
                    """
                }
                echo 'AI validation complete!'
            }
        }

        // ─── STAGE 13 ───────────────────────────
        stage('13. Generate HTML Report') {
            steps {
                echo 'Generating HTML validation report...'
                script {
                    def ws = pwd()
                    bat """
                        cd scripts
                        set PYTHONIOENCODING=utf-8
                        set PYTHONLEGACYWINDOWSSTDIO=utf-8
                        set OUTPUT_DIR=${ws}\\validation_output
                        set PACKAGE_NAME=infosecadventures.allsafe
                        python report_generator.py ${ws}\\validation_output\\validation_results.json
                    """
                }
                echo 'HTML report generated!'
            }
        }

    }

    // ─── POST ACTIONS ───────────────────────
    post {
        always {
            echo 'Archiving all reports...'
            archiveArtifacts artifacts: 'sast_report.json,dast_report.json,mobsf_final_report.pdf,validation_output/validation_results.json,validation_output/validation_report.html,validation_output/screenshots/*.png',
                             allowEmptyArchive: true
        }
        success {
            echo 'Pipeline PASSED! All 13 stages completed.'
        }
        failure {
            echo 'Pipeline FAILED - Check the red stage!'
        }
    }
}
