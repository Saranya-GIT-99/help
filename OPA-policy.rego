package opsmx.spinnaker.pipeline_approver_authz
import future.keywords.in

# Authorized users (modify this list)
allowed_users = ["userB@example.com", "userC@example.com"]

# Get pipeline initiator (user who triggered the pipeline)
pipeline_initiator = input.pipeline.initiator

# Collect all approvers of SUCCEEDED manual judgement stages
judgement_approvers = [user |
  some i
  input.stages[i].type == "manualJudgment"
  input.stages[i].status == "SUCCEEDED"
  user := input.stages[i].context.lastModifiedBy
]

# Deny if ANY approver is unauthorized
deny[sprintf("Unauthorized Approver: '%s'", [user])] {
  some user in judgement_approvers
  not user in allowed_users
}

# Deny if ANY approver is the pipeline initiator
deny[sprintf("Pipeline initiator '%s' cannot approve their own request", [user])] {
  some user in judgement_approvers
  user == pipeline_initiator
}
