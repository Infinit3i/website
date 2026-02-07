---
title: "Detection Wizard"
date: 2024-07-31 14:00:00 -0500
categories: [Detection Engineering, Tooling]
tags: [detection engineering, threat detection, blue team, security monitoring, sigma, splunk, yara, suricata, automation, rule aggregation, rule deduplication, security operations, defensive tooling]
image:
  path: https://raw.githubusercontent.com/Infinit3i/Detection-Wizard/09a7dd892091e11b7548de1730075e723371ce16/assets/detection_wizard.jpeg
---

![Yara Image](https://www.reversinglabs.com/api/media/file/how-to-use-yara-rules.svg)

Detection rules are scattered, duplicated, and unmanaged once scale is introduced. Sigma, YARA, Suricata, and Splunk rules exist across hundreds of repositories, often rewritten with small cosmetic changes and no shared structure. Detection Wizard was created primarily to gather rules, centralize them, and remove duplication across sources.

![Sigma Rule Example](https://cymulate.com/uploaded-files/2022/07/sigma_rules.png)

Once large scale collection became the goal, normalization became unavoidable.  I enjoy defense in depth I will always like more rules rather than less and just remove what has a high false positive rate for your enviroment. Understand coverage, remove redundancy, and avoid importing the same detection idea multiple times under different names. Deduplication made it obvious how frequently identical logic is reused across ecosystems with only variable names or comments changed.

![YARA Rule Example](https://www.threatdown.com/wp-content/uploads/2024/04/examplepcsmartcleanup.webp)

Automation quickly became mandatory. Repositories had to be cloned, parsed by content instead of extension, filtered by rule type, and processed in a deterministic order. Sequential execution was not a design preference. It was required to maintain correctness and operator trust. Parallel execution without strict state control caused inconsistent results and unpredictable behavior.

![Suricata Rule Example](https://cloud-courses.upb.ro/assets/images/suricata-alert-8190414bc9689ce57b9fbc5a0b22643c.png)

The project also reframed how I think about detections as a defensive supply chain. Public rules vary widely in quality, freshness, and intent. Some are well maintained and actionable. Others are outdated or misleading. Treating detections as code that must be curated, reviewed, deduplicated, and tracked became non negotiable once volume increased.

Check out some great links where I gather these rules from

[Awesome Yara](https://github.com/InQuest/awesome-yara)

[Awesome Suricata](https://github.com/satta/awesome-suricata)

[Awesome Detection Rules](https://github.com/jatrost/awesome-detection-rules)