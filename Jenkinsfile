pipeline {
    agent any
    
    environment {
        PYTHON_PATH = "C:\\Users\\Snehal\\AppData\\Local\\Programs\\Python\\Python39\\python.exe"
        REPORT_DIR = 'reports'
    }
    
    triggers {
        githubPush()
    }
    
    stages {
        
        stage('1. Build Environment') {
            steps {
                bat """
                    ${PYTHON_PATH} --version
                    
                    if not exist venv (
                        ${PYTHON_PATH} -m venv venv
                    )
                    
                    call venv\\Scripts\\activate.bat
                    
                    venv\\Scripts\\pip install --upgrade pip
                    venv\\Scripts\\pip install -r requirements.txt
                    venv\\Scripts\\pip install bandit
                """
            }
        }
        
        stage('1.5 Functional Testing') {
            steps {
                bat """
                    echo "[*] Running Functional Regression Tests..."
                    call venv\\Scripts\\activate.bat
                    venv\\Scripts\\pytest test_functional.py -v
                """
            }
        }
        
        stage('2. Static Security Scan (Bandit)') {
            steps {
                // We use catchError so the pipeline continues to the GA Fuzzer even if Bandit finds something
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    bat """
                        if not exist reports mkdir reports
                        call venv\\Scripts\\activate.bat
                        
                        venv\\Scripts\\bandit -r . -f json -o reports\\bandit_report.json
                    """
                }
            }
        }
        
        stage('3. AI Red Team (GA Fuzzer)') {
            steps {
                bat """
                    call venv\\Scripts\\activate.bat
                    
                    echo "[*] Booting up live Flask application in the background..."
                    start "Flask_App" /b venv\\Scripts\\python.exe app.py
                    
                    echo "[*] Waiting 3 seconds for server to bind to port 5000..."
                    timeout /t 3 /nobreak > NUL
                    
                    echo "[*] Unleashing Genetic Algorithm Fuzzer..."
                    venv\\Scripts\\python.exe ga_fuzzer.py
                    
                    set FUZZ_EXIT=%ERRORLEVEL%
                    
                    echo "[*] Shutting down Flask application..."
                    for /f "tokens=5" %%a in ('netstat -aon ^| find ":5000" ^| find "LISTENING"') do taskkill /F /PID %%a
                    
                    exit /b %FUZZ_EXIT%
                """
            }
        }
        
        stage('4. Enforce Security Gate') {
            steps {
                script {
                    echo "[*] Checking all security reports..."
                    // If the build reached here and is already marked FAILURE from Stage 2 or 3, it will trigger post-failure.
                }
            }
        }
    }
    
    post {
        always {
            echo "========== ADVERSARIAL PIPELINE COMPLETE =========="
        }
        success {
            echo "[SUCCESS] Application withstood Functional Tests, Static Scans, and the Genetic Algorithm. Secure deployment allowed."
        }
        failure {
            script {
                if (env.BRANCH_NAME == 'main' || env.GIT_BRANCH == 'origin/main' || env.GIT_BRANCH == 'main') {
                    echo "[!] VULNERABILITY DETECTED ON MAIN! Triggering AI Blue Team (LLM Auto-Remediator)..."
                    bat """
                        call venv\\Scripts\\activate.bat
                        venv\\Scripts\\python.exe ai_auto_remediator.py
                    """
                } else {
                    echo "[!] PIPELINE FAILED ON PR BRANCH '${env.BRANCH_NAME}'."
                    echo "[!] AI Remediation will not run on Pull Requests to prevent infinite loops."
                }
            }
        }
    }
}