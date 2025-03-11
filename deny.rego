package spinnaker.pipelines.runtime_approval

# Define a decision object combining "allow" and "deny"
decision = {
  "allow": allow,
  "deny": deny_messages
} {
  true
}

# Default to denying requests
default allow = false

# Allow only if the initiator is not the approver
allow {
  input.pipeline.initiator != input.pipeline.stages["Manual Judgment"].approver
}

# Deny messages (if any)
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
  "policyInput": {
    "pipeline": {
      "initiator": "${execution.trigger.user}",
      "stages": {
        "Manual Judgment": {
          "approver": "${stage['Manual Judgment'].lastModifiedBy}"
        }
      }
    }
  }
}
