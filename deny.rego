package spinnaker.pipelines.runtime_approval

# Structured decision for Spinnaker
decision = {
  "allow": allow,
  "deny": deny_messages
}

# Default to deny
default allow = false

# Allow only if:
# 1. Initiator and approver are not "unknown"
# 2. Initiator != approver
allow {
  input.pipeline.initiator != "unknown"
  input.pipeline.stages["Manual Judgment"].approver != "unknown"
  input.pipeline.initiator != input.pipeline.stages["Manual Judgment"].approver
}

# Deny messages
deny_messages = [msg] {
  input.pipeline.initiator == "unknown"
  msg := "Pipeline initiator is missing."
}

deny_messages = [msg] {
  input.pipeline.stages["Manual Judgment"].approver == "unknown"
  msg := "Manual judgement approver is missing."
}

deny_messages = [msg] {
  input.pipeline.initiator == input.pipeline.stages["Manual Judgment"].approver
  msg := "Pipeline initiator cannot approve their own deployment."
}

{
  "pipeline": {
    "initiator": "${execution.trigger.user}",
    "stages": {
      "Manual Judgment": {
        "approver": "${stage['Manual Judgment'].lastModifiedBy}"
      }
    }
  }
}


{
  "pipeline": {
    "initiator": "${execution.trigger?.user ?: 'unknown'}",
    "stages": {
      "Manual Judgment": {
        "approver": "${stage['Manual Judgment']?.lastModifiedBy ?: 'unknown'}"
      }
    }
  }
}
