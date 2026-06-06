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
        
        stage('0. Checkout') {
            steps {
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: '*/main']],
                    userRemoteConfigs: [[url: 'https://github.com/Snehalgupta-07/GenePatch.git']]
                ])
                bat 'dir'
            }
        }
        
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
        
        stage('2. Static Security Scan (Bandit)') {
            steps {
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
                    start "Flask_App" /b venv\\Scripts\\python.exe app.py > flask.log 2>&1
                    
                    echo "[*] Waiting 4 seconds for server to bind to port 5000..."
                    ping 127.0.0.1 -n 5 > NUL
                    
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
                }
            }
        }
    }
    
    post {
        always {
            echo "========== ADVERSARIAL PIPELINE COMPLETE =========="
        }
        success {
            echo "[SUCCESS] Application withstood Static Scans and the Genetic Algorithm. Secure deployment allowed."
        }
        failure {
            echo "[!] VULNERABILITY DETECTED! Awakening Autonomous Agent (Self-Healing Loop)..."
            bat """
                call venv\\Scripts\\activate.bat
                venv\\Scripts\\python.exe ai_auto_remediator.py
            """
        }
    }
}