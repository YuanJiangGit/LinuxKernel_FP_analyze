
# RLFD False Positive Analysis 

This document describes the fields in the manually review of **184 false positive cases** identified by the RLFD detection model,  all of which are derived from Linux kernel version 5.12.

## Field Descriptions

- **func_before**: The source code of the function initially identified as a false positive by the RLFD model. If `label` is `"1"`, the function has been manually verified to be vulnerable.
- **path**: The file system path to the source file containing the function.
- **label**: A manually verified binary label indicating the ground truth vulnerability status of the function (`"1"` denotes a vulnerable function, while `"0"` indicates a non-vulnerable one).
- **description**: Manual analysis and justification explaining whether the function is truly vulnerable or not.

## Purpose

This dataset provides valuable insights into the false positives produced by RLFD, supporting error analysis and guiding model improvements in future iterations.
