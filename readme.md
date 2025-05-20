# POC Documentation: SonarQube Integration with GitLab Ultimate for Merge Request Analysis

## 1. Overview

This Proof of Concept (POC) demonstrates the integration of SonarQube with GitLab Ultimate to perform static code analysis during merge requests and generate reports. The solution leverages GitLab's built-in CI/CD capabilities to trigger SonarQube scans when merge requests are created or updated.

## 2. Objectives

- Automate SonarQube analysis during merge request workflows
- Display SonarQube analysis results directly in GitLab merge requests
- Enforce quality gates before merge approval
- Generate comprehensive reports for stakeholders
- Maintain security of analysis results

## 3. Prerequisites

- GitLab Ultimate license (version 13.0+ recommended)
- SonarQube server (version 8.9 LTS or higher)
- Runner with Docker or Kubernetes executor
- Project repository in GitLab
- Appropriate network connectivity between GitLab and SonarQube

## 4. Architecture

```
GitLab Repository → GitLab CI/CD Pipeline → SonarQube Scanner → SonarQube Server → Quality Report → GitLab Merge Request
```

## 5. Implementation Steps

### 5.1 SonarQube Configuration

1. **Create Project in SonarQube**:
   - Navigate to your SonarQube instance
   - Create a new project or use an existing one
   - Generate a project token (Settings → Security → Tokens)

2. **Configure Quality Gates and Profiles**:
   - Set up appropriate quality gates for your project
   - Configure language-specific analysis profiles

### 5.2 GitLab Configuration

1. **Add CI/CD Variables**:
   - Navigate to Settings → CI/CD → Variables
   - Add the following protected variables:
     - `SONAR_HOST_URL` - URL of your SonarQube instance
     - `SONAR_TOKEN` - SonarQube project token
     - `SONAR_PROJECT_KEY` - Unique project key in SonarQube

2. **Create `.gitlab-ci.yml` File**:

```yaml
stages:
  - test
  - sonarqube-check

sonarqube:
  stage: sonarqube-check
  image:
    name: sonarsource/sonar-scanner-cli:latest
    entrypoint: [""]
  variables:
    SONAR_USER_HOME: "${CI_PROJECT_DIR}/.sonar"
    GIT_DEPTH: "0"
  script:
    - sonar-scanner
      -Dsonar.projectKey=${SONAR_PROJECT_KEY}
      -Dsonar.projectName=${CI_PROJECT_NAME}
      -Dsonar.projectVersion=${CI_COMMIT_SHORT_SHA}
      -Dsonar.sources=.
      -Dsonar.host.url=${SONAR_HOST_URL}
      -Dsonar.login=${SONAR_TOKEN}
      -Dsonar.gitlab.project_id=${CI_PROJECT_ID}
      -Dsonar.gitlab.commit_sha=${CI_COMMIT_SHA}
      -Dsonar.gitlab.ref_name=${CI_COMMIT_REF_NAME}
      -Dsonar.qualitygate.wait=true
  allow_failure: false
  only:
    - merge_requests
```

### 5.3 Merge Request Report Integration

1. **SonarQube GitLab Plugin**:
   - Install the SonarQube GitLab plugin on your SonarQube server
   - Configure the plugin with GitLab URL and API token

2. **GitLab Service Integration**:
   - Navigate to Settings → Integrations
   - Add SonarQube service
   - Configure with SonarQube URL and token

### 5.4 Quality Gate Enforcement

```yaml
quality_gate:
  stage: test
  script:
    - |
      if [ "$SONAR_STATUS" != "OK" ]; then
        echo "Quality gate failed"
        exit 1
      fi
  allow_failure: false
```

## 6. Expected Outcomes

1. **Merge Request Widget**:
   - SonarQube analysis results appear in the merge request widget
   - Direct links to SonarQube issues
   - Quality gate status visible

2. **Comment Integration**:
   - SonarQube adds comments for new issues in merge request diffs
   - Resolved issues are automatically acknowledged

3. **Report Generation**:
   - PDF/HTML reports available as pipeline artifacts
   - Trend analysis visible in SonarQube dashboard

## 7. Validation Criteria

1. Successfully triggers SonarQube scan on merge request creation
2. Displays analysis results in merge request interface
3. Blocks merge if quality gate fails (configurable)
4. Generates downloadable reports
5. Maintains historical analysis data

## 8. Troubleshooting

**Common Issues**:
- Scanner fails: Verify network connectivity and token permissions
- Missing reports: Check GitLab plugin configuration in SonarQube
- Quality gate not enforced: Verify `sonar.qualitygate.wait=true` parameter

## 9. Security Considerations

- Store SonarQube tokens as protected variables
- Limit SonarQube instance access
- Use HTTPS for all communications
- Regularly update SonarQube and plugins

## 10. Next Steps

1. Expand to multiple projects
2. Implement custom quality gates per team/project
3. Integrate with security scanning tools
4. Set up notification system for critical issues

## Appendix A: Sample Report Screenshot

[Include screenshot of merge request with SonarQube widget]

## Appendix B: Performance Metrics

[Include metrics on analysis time impact on merge request workflow]

This POC demonstrates a robust integration between SonarQube and GitLab Ultimate that enhances code quality visibility during the merge request process while maintaining development velocity.
