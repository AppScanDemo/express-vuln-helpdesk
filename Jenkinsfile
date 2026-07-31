pipeline {
    agent any

    environment {
        SEVERITY_THRESHOLD = 'HIGH'
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }
        stage('Install') {
            steps { sh 'npm install --no-audit --no-fund || true' }
        }
        stage('Unit Tests') {
            steps { sh 'npm test || true' }
        }
        stage('Secret Scan') {
            steps { echo 'PLACEHOLDER - run gitleaks/trufflehog CLI, publish report' }
        }
        stage('SAST Scan') {
            steps { echo 'PLACEHOLDER - run vendor SAST CLI (Checkmarx/Fortify/Semgrep/SonarQube/etc.)' }
        }
        stage('SCA + SBOM') {
            steps { echo 'PLACEHOLDER - run npm audit + vendor SCA CLI + CycloneDX SBOM generation' }
        }
        stage('Severity Gate') {
            steps { echo "PLACEHOLDER - fail pipeline if findings >= ${SEVERITY_THRESHOLD}" }
        }
    }

    post {
        always {
            echo 'Archive SAST/SCA/secret-scan reports here for POC evidence.'
        }
    }
}
