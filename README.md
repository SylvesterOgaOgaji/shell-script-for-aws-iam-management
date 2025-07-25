# ### AWS IAM Management Script Implementation Guide  
**A Comprehensive Walkthrough with Security Best Practices**

---

#### **1. AWS CLI Verification**  
![Confirming AWS CLI](./img/1.%20Confirming%20aws-cli.jpg)  
```bash
aws --version
# Output: aws-cli/2.27.22 Python/3.13.3 Linux/6.8.0-1029-aws
```  
**Best Practice**:  
- Always use the latest AWS CLI version for security patches and feature support  
- Regularly update with `sudo ./aws/install --update`  

**Limitation**:  
- Kernel mismatches may cause compatibility issues (e.g., 6.8.0 vs 6.14.0)  

---

#### **2. Script Creation**  
![Creating bash file](./img/2.%20Creating%20bash%20file.jpg)  
```bash
vi iam-manager.sh
```  
**Security Considerations**:  
- Store scripts in isolated directories (e.g., `~/iam-scripts/`)  
- Use `chmod 700 iam-manager.sh` to restrict access  

---

#### **3. Script Content**  
![Script content](./img/3.%20Script.jpg)
![Creating bash file](./img/4.%20scrpt%20b.jpg) 
![Creating bash file](./img/5.%20Script%20c.jpg) 
![Creating bash file](./img/6.%20Script%20d.jpg)   
```bash
IAM_USER_NAMES=("devops1" "devops2" "devops3" "devops4" "devops5")
```  
**Best Practice**:  
- Avoid hardcoding credentials - use IAM roles instead  
- Parameterize usernames via environment variables  

**Limitation**:  
- Max 100 IAM users per account by default (request quota increase)  

---

#### **4. Group Creation Logic**  
![Script section](./img/4.%20scrpt%20b.jpg)  
```bash
if aws iam get-group --group-name "admin" &>/dev/null; then
  echo "Group exists - skipping"
fi
```  
**Error Handling Improvement**:  
```bash
aws iam create-group ... || handle_error "Group creation failed"
```  
**Security Note**:  
- `AdministratorAccess` is overprivileged - prefer custom policies  

---

#### **5. User Assignment Logic**  
![Script section](./img/6.%20Script%20d.jpg)  
**Critical Fix**:  
```diff
- for user in "${IAM_USER_NAME${@}}"; do
+ for user in "${IAM_USER_NAMES[@]}"; do
```  
**Best Practice**:  
- Implement user existence check before assignment  
- Add MFA enforcement during assignment  

---

#### **6. Main Execution Flow**  
![Script main function](./img/6.%20Script%20d.jpg)  
**Dependency Check Enhancement**:  
```bash
if ! command -v jq &>/dev/null; then
  sudo apt install jq -y
fi
```  
**Security Tip**:  
- Add `set -euo pipefail` at script start to fail on errors  

---

#### **7. File Permissions**  
![Script permissions](./img/7.%20Confirming%20the%20file%20creation.jpg)  
```bash
chmod +X iam-manager.sh
```  
**Best Practice**:  
- Use `750` not `777` - never world-writable permissions  
- Set ownership: `chown ubuntu:developers iam-manager.sh`  

---

#### **8. Initial Execution Failure**  
![Execution error](./img/9.%20Script%20executed%20with%20errors.jpg)  
**Error Analysis**:  
```terminal
User not authorized to perform: iam:CreateUser
```  
**Solution**:  
1. Attach `IAMFullAccess` policy to executing user  
2. Verify with:  
```bash
aws iam simulate-principal-policy \
  --policy-source-arn YOUR_ARN \
  --action-names iam:CreateUser
```  

---

#### **9. IAM Console Verification**  
![IAM Dashboard](./img/11.%20Select%20user%20cli-sly.jpg) 
![IAM Dashboard](./img/12.%20Select%20permission.jpg) 
**Security Best Practices**:  
1. Enable **IAM Access Analyzer** for resource monitoring  
2. Activate **Cross-account warning** in account settings  
3. Check **Last activity** for unused credentials  

---

#### **10. User Permission Assignment**  
![Attach permissions](./img/13.%20Attach%20permission%20to%20user.jpg)  
**Principle of Least Privilege**:  
- Prefer groups over direct policy attachments  
- Use permission boundaries for privilege containment  
- Set session duration: 1 hour for admin roles  

---

#### **11. Successful User Policy Creation**  
![User created](./img/14.%20IAMFullAcess%20policy%20added.jpg)  
**Verification Command**:  
```bash
aws iam list-users --query 'Users[].UserName' | jq 'map(select(. | startswith("devops")))'
```  
**Security Enhancement**:  
- Immediately enable MFA for new users  
- Set password reset requirement:  
```bash
aws iam update-login-profile --user-name $user --password-reset-required
```  

---

#### **12. Group Policy Attachment**  
![Policy attachment](./img/15.%20Verifying%20attached%20policy.jpg) 
![Group verification](./img/16.%20User%20created.jpg)  
![Group verification](./img/17.%20User%20created.jpg)   
![Group verification](./img/18.%20User%20created.jpg)   
![Group verification](./img/19.%20User%20verified.jpg) 
**Best Practice**:  
- Replace `AdministratorAccess` with scoped policy:  
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*"
    }
  ]
}
```  
**Audit Command**:  
```bash
aws iam list-attached-group-policies --group-name admin
```  

---

#### **13. Final Group Configuration**  
![Group verification](./img/20.%20Groups.jpg)  
![Group verification](./img/21.%20Groups.jpg)
**MFA Enforcement Policy**:  
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireMFA",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
      }
    }
  ]
}
```  
**Implementation**:  
```bash
aws iam put-group-policy --group-name admin \
  --policy-name "RequireMFA" \
  --policy-document file://mfa-policy.json
```  

---

### Security Best Practices Summary  

| **Area**           | **Implementation**   | **Rationale**                             |
|-------------------------------------------|-------------------------------------------|
| **Authentication** | Enforce MFA, password rotation (90 days), 14+ character complexity                 | Prevents credential compromise            |
| **Authorization**  | Least privilege, permission boundaries, group-based access                         | Limits blast radius                       |
| **Auditing**       | Enable CloudTrail with S3 bucket logging, AWS Config rules                         | Forensic analysis capability              |
| **Infrastructure** | Run script on dedicated EC2 with IAM role (not local machine)                      | Avoids credential leakage                 |
| **Error Handling** | Implement retry logic with exponential backoff, comprehensive logging              | Maintains reliability during API throttling |

---

### Limitations and Mitigations  

| **Limitation**                     | **Risk** **Mitigation**                                                                 |
|------------------------------------|-------------------|--------------------------------------------------------------------------------|
| No resource cleanup in script      | Orphaned resources costing $ | Add `cleanup.sh` with delete commands                                          |
| Hardcoded admin policy             | Overprivileged access       | Replace with custom scoped policies                                            |
| No input validation                | Privilege escalation        | Add username validation: `[[ "$user" =~ ^devops[1-5]$ ]]`                     |
| AWS API rate limits                | Script failures            | Implement exponential backoff (aws-cli-retry-mode=standard)                    |
| No Terraform export                | Manual recreation needed   | Add `aws iam get-* --output json > terraform.tf`                               |
| EC2 instance dependency            | Single point of failure    | Convert to AWS Lambda function with CloudWatch trigger                         |

---

### Lessons Learned  

1. **Idempotency is Critical**  
   - Implement existence checks before resource creation  
   - Use AWS CLI `--query` to verify pre-existing resources  

2. **Permission Boundaries Trump IAM Policies**  
   ```mermaid
   graph LR
   A[Request] --> B{SCP Allow?}
   B -->|No| C[Denied]
   B -->|Yes| D{Permission Boundary}
   D -->|Allow| E{IAM Policy}
   D -->|Deny| C
   E -->|Allow| F[Granted]
   E -->|Deny| C
   ```

3. **Security Must Be Baked In**  
   - MFA enforcement should be script default, not afterthought  
   - Password policies should be set before user creation  

4. **AWS Region Quirks**  
   - IAM is global but CLI configuration affects API endpoints  
   - Always set region explicitly:  
     ```bash
     export AWS_REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
     ```

---

### Cleanup Procedure  

```bash
#!/bin/bash
# cleanup-iam.sh
GROUP="admin"
USERS=("devops1" "devops2" "devops3" "devops4" "devops5")

for user in "${USERS[@]}"; do
  aws iam remove-user-from-group --group-name $GROUP --user-name $user
  aws iam delete-login-profile --user-name $user 2>/dev/null
  aws iam delete-user --user-name $user
done

aws iam detach-group-policy \
  --group-name $GROUP \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
  
aws iam delete-group --group-name $GROUP
```

> **Final Note**: Always test in non-production environments first. For production deployments:  
> 1. Add CloudFormation/Terraform templates  
> 2. Integrate with CI/CD pipeline  
> 3. Implement approval workflows for IAM changes  
> 4. Enable AWS Config compliance checks  


### Review Grading : 900
Very Good
Review
The submitted project aligns well with the instructor's instructions for automating AWS IAM user and group management using shell scripting and the AWS CLI. The provided code and guide demonstrate comprehensive functionality, with notable strengths and some areas requiring attention.

Strengths:

Purpose:

The script automates the onboarding of IAM users, group creation, and policy attachment workflows, aligning with infrastructure-as-code principles essential for a DevOps setup.
MFA enforcement and scoped permissions provide additional security layers.
Implementation Quality:

The IAM_USER_NAMES array fulfills the instruction to define five usernames.
The script has modular functions for user creation, group setup, policy attachment, and user-group association, meeting the structural requirements outlined.
Idempotent checks ensure the admin group is created only if it doesn't already exist.
Error handling (e.g., validating aws CLI installation) is present to some extent, though it could be extended further.
Execution Flow and Logging:

Meaningful internal comments and the main execution function effectively coordinate the invocation of sub-functions for role-based IAM management.
Outputs and success/error messages aid troubleshooting during execution.
Documentation:

Extensive documentation accompanies the script. It explains the logic, security best practices, and includes mitigation steps for various risks. The images provide verification of script outcomes.
Weaknesses:

Security Considerations:

The use of the "AdministratorAccess" policy is overly permissive and introduces risks. A custom scoped policy should replace this.
MFA enforcement policies, while suggested in the guide, are not integrated into the script by default.
Performance and Further Improvements:

Exponential backoff for API retries and AWS rate-limiting mitigation is recommended but not implemented in the script. This could impact reliability in high-usage scenarios.
The cleanup process is provided as a separate script, but a more integrated and automated solution within the main script would improve usability.
Clarifications in Code:

While the images and comments explain the flow, some error handling like checking API permissions (iam:CreateUser) in the script itself should be embedded rather than relying solely on external guides.
Testing Notes:

The script seems focused on local execution (via an EC2 instance or local machine). Migration to Lambda or CloudFormation templates for production deployments would improve maintainability and scalability.
Overall, the project displays a solid understanding of AWS IAM management, with clear evidence of automation success based on the output screenshots and guided logic. Minor adjustments, especially around security and error handling, can further strengthen its application in real-world production environments.


Feed Back
No feedback returned