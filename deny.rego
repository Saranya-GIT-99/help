{
  "testInitiator": "${execution.trigger.user}",
  "testApprover": "${stage['Manual Judgment'].lastModifiedBy}"
}


package opsmx.spinnaker.pipeline_approver_authz

# Deny if initiator == approver
deny[sprintf("Pipeline initiator '%s' cannot approve", [input.pipeline.execution.trigger.user])] {
  input.pipeline.execution.trigger.user != "unknown"
  some i
  input.stages[i].type == "manualJudgment"
  input.stages[i].status == "SUCCEEDED"
  input.stages[i].context.lastModifiedBy != "unknown"
  input.pipeline.execution.trigger.user == input.stages[i].context.lastModifiedBy
}

{
  "policyInput": {
    "pipeline": {
      "execution": {
        "trigger": {
          "user": "${execution.trigger?.user ?: 'unknown'}"
        }
      }
    },
    "stages": [
      {
        "type": "manualJudgment",
        "status": "SUCCEEDED",
        "context": {
          "lastModifiedBy": "${stage['Manual Judgment']?.lastModifiedBy ?: 'unknown'}"
        }
      }
    ]
  }
}
