# Scoring Criteria for VM Detection Techniques

## 1. Reliability (Maximum Weight: 50%) 
*Assess the technique’s consistency in accurately detecting VMs.*
*Ranges from 5 to 40%, with higher scores indicating greater reliability.*
**__1.__ Consistency Across Tests:** Does the technique consistently identify VMs when tested multiple times?
**__2.__ Detection Rate**: What is the probability of accurately detecting a VM versus non-VM?

## 2. Specificity to VMs (Maximum Weight: 50%)
*Measure the likelihood that the technique is specific to VM environments and unlikely to trigger in non-VM contexts.*
*Ranges from 0 to 40%, where a high score indicates high specificity to VM environments.*
**__1.__ Environment Triggering**: How specific is this technique to VMs, or could it potentially trigger in certain non-VM setups?
**__2.__ Context Sensitivity**: Are there specific contexts where this technique might yield inconsistent results, or does it work across various VM platforms and configurations?

## 3. False Positive Likelihood (Penalty Only)
Evaluate the likelihood of the technique yielding false positives in non-VM environments.
This criterion only decreases the final score. If false positives are likely, the final score will be reduced, potentially to a minimum of 5.

**__1.__ Non-VM Triggers:** How often does this technique trigger in a host environment by mistake?
**__2.__ Real-World False Positives:**: Does the technique have a history of false positives in real-world scenarios?

```Each category is assigned a score arbitrarily using the considerations as guidelines. Then, the scores are summed to get a final technique score. If the technique shows a high likelihood of false positives, the final score is reduced, potentially lowering the score to 5 in cases of high false flag likelihood.```


### 3.1 False Positive Likelihood Penalty Criteria
The False Positive Likelihood penalty operates on a four-tier scale. Each level has a specific reduction percentage that will be subtracted from the initial score.
Reduction amounts vary from a small percentage for minor false positive risks to a significant penalty for techniques highly prone to false positives.
The resulting score will never fall below the minimum of 5.

### 3.2 Penalty Levels and Reduction Amounts
**1. Minimal False Positive Risk (0% Reduction)**
Characteristics: The technique is exceptionally reliable, with negligible chances of false positives in non-VM contexts.
Penalty: No reduction applied to the initial score.

**2. Low False Positive Risk (Reduce Final Score by 25%)**
Characteristics: The technique occasionally triggers false positives, usually in rare edge cases or under specific conditions. However, false positives are limited and unlikely in typical non-VM environments.
Penalty: Subtract 25% of the initial score.

**3. Moderate False Positive Risk (Reduce Final Score by 50%)**
Characteristics: The technique has a moderate risk of false positives, potentially triggering in various non-VM contexts or under commonly occurring conditions.
Penalty: Subtract 50% of the initial score.

**4. High False Positive Risk (Reduce Final Score by 80%, Minimum Score of 5)**
Characteristics: The technique frequently triggers false positives in non-VM environments, making it unreliable in many real-world scenarios.
Penalty: Subtract 80% of the initial score. `If the result is lower than 5, the final score is set to 5.`