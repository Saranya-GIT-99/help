package spinnaker.pipelines.runtime_approval

default allow = false

# Allow only if the initiator is not the approver
allow {
  input.pipeline.initiator != input.pipeline.stages["Manual Approval"].approver
}

# Deny with a reason (for auditing/logging)
deny[msg] {
  input.pipeline.initiator == input.pipeline.stages["Manual Approval"].approver
  msg := "Pipeline initiator cannot approve their own deployment."
}
