package spinnaker.pipelines.runtime_approval

default allow = false

# Allow only if the initiator is not the approver
allow {
  input.pipeline.initiator != input.pipeline.stages["Manual Judgment"].approver
}

# Deny with a reason if the initiator approves
deny[msg] {
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
