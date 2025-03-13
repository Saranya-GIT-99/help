package opsmx.spinnaker.pipeline_approver_authz
import future.keywords.in

# Authorized users list (add your approved users here)
allowed_users = ["admin@example.com", "release-manager@example.com"]

# Pipeline initiator (user who triggered the pipeline)
pipeline_initiator = input.pipeline.execution.trigger.user

# Collect all approvers of SUCCEEDED manual judgement stages
judgement_approvers = [approver | 
    some i
    input.stages[i].type == "manualJudgment"
    input.stages[i].status == "SUCCEEDED"
    approver := input.stages[i].context.lastModifiedBy
]

# Deny if ANY approver is unauthorized
deny[sprintf("Unauthorized Approver: '%s'", [approver])] {
    some approver in judgement_approvers
    not approver in allowed_users
}

# Deny if ANY approver is the pipeline initiator
deny[sprintf("Pipeline initiator '%s' cannot approve", [pipeline_initiator])] {
    some approver in judgement_approvers
    approver == pipeline_initiator
}
