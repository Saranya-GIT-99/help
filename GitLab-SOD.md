# **GitLab Branch Protection & Merge Approval Rules Guide**  
This document provides a step-by-step guide on configuring **branch protection** and **merge approval rules** in GitLab to enforce security, compliance, and workflow best practices.

---

## **1. Branch Protection Rules**  
Branch protection prevents unauthorized users from pushing directly to critical branches (e.g., `main`, `prod`).  

### **Steps to Configure Protected Branches**  
1. **Navigate to Repository Settings**  
   - Go to your project → **Settings → Repository → Protected Branches**.  
   - Click **"Expand"** under **Protected Branches**.  

2. **Select Branch to Protect**  
   - Enter the branch name (e.g., `main`, `release/*`) or use wildcards (`*-stable`).  
   - Click **"Protect"**.  

3. **Set Permissions**  
   - **Allowed to push**: Choose who can push (No one, Maintainers, Developers).  
   - **Allowed to merge**: Select who can merge (Developers, Maintainers).  
   - **Allow force push**: Enable if needed (risky, use cautiously).  
   - **Code owner approval**: Require approval from `CODEOWNERS`.  

   ![Protected Branch Settings](https://docs.gitlab.com/ee/user/project/protected_branches.png)  

4. **Save Settings**  
   - Click **"Protect"** to apply rules.  

### **Best Practices for Branch Protection**  
✔ **Protect `main`/`master`** – Prevent direct pushes, require MRs.  
✔ **Use wildcards** (e.g., `prod-*`) for multiple branches.  
✔ **Disable force push** unless absolutely necessary.  
✔ **Enable "Code owner approval"** for critical files.  

---

## **2. Merge Request (MR) Approval Rules**  
Merge approval rules enforce mandatory reviews before merging code.  

### **Steps to Configure Approval Rules**  
1. **Go to Project Settings**  
   - Navigate to **Settings → Merge Requests**.  

2. **Configure Merge Request Approvals**  
   - **Approvals required**: Set minimum number of approvals (e.g., `2`).  
   - **Reset approvals on push**: Require re-approval after new commits.  
   - **Prevent approval by author**: Stop self-approval.  
   - **Prevent approvals by users who commit**: Ensure impartial reviews.  

3. **Set Approval Rules (Optional)**  
   - **Code Owners**: Require approval from `CODEOWNERS` of modified files.  
   - **User-based Approvers**: Assign specific users/groups as mandatory reviewers.  

   ![MR Approval Settings](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/settings.png)  

4. **Save Changes**  

### **Best Practices for MR Approvals**  
✔ **Require at least 2 approvals** for critical branches.  
✔ **Use `CODEOWNERS`** for automatic reviewer assignment.  
✔ **Prevent self-approval** to avoid conflicts of interest.  
✔ **Enable "Reset approvals on push"** to ensure fresh reviews.  

---

## **3. Using `CODEOWNERS` for Automated Approvals**  
A `CODEOWNERS` file defines who must review changes to specific files/directories.  

### **How to Set Up `CODEOWNERS`**  
1. **Create a `.gitlab/CODEOWNERS` file** in your repo:  
   ```plaintext
   # Example CODEOWNERS file
   *.js       @frontend-team
   /infra/*   @devops-team
   README.md  @tech-writers
   ```  
2. **Enable in Project Settings**  
   - Go to **Settings → Repository → Protected Branches**.  
   - Check **"Require approval from code owners"**.  

### **How `CODEOWNERS` Works**  
- Any MR touching files in `CODEOWNERS` will **require approval** from listed users.  
- Works with **branch protection** for stricter control.  

---

## **4. Troubleshooting Common Issues**  
| **Issue** | **Solution** |
|-----------|-------------|
| **"Merge blocked: approvals required"** | Ensure enough reviewers approved. |
| **"Pre-receive hook declined"** | Check branch protection rules. |
| **Approvals reset unexpectedly** | Disable "Reset approvals on push" if not needed. |
| **CODEOWNERS not triggering** | Verify file location is `.gitlab/CODEOWNERS` or `docs/CODEOWNERS`. |

---

## **5. Summary of Key Settings**  
| **Feature** | **Where to Configure** | **Purpose** |
|-------------|------------------------|-------------|
| **Protected Branches** | `Settings → Repository → Protected Branches` | Restrict pushes/merges |
| **MR Approvals** | `Settings → Merge Requests` | Require peer reviews |
| **CODEOWNERS** | `.gitlab/CODEOWNERS` | Auto-assign reviewers |
| **Force Push Control** | Protected Branches | Block risky overwrites |

---

## **6. References**  
- [GitLab Protected Branches Docs](https://docs.gitlab.com/ee/user/project/protected_branches.html)  
- [Merge Request Approvals Docs](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/)  
- [CODEOWNERS File Guide](https://docs.gitlab.com/ee/user/project/codeowners/)  

---

### **Final Recommendations**  
✅ **Protect all long-lived branches** (`main`, `prod`, `release/*`).  
✅ **Require at least 2 approvals** for high-risk changes.  
✅ **Combine `CODEOWNERS` + branch protection** for automated compliance.  

Let me know if you need further customization! 🚀
