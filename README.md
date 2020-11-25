# xmatters-ebs-automation

This repository holds the individual scripts used as steps within the xMatters workflow to automatically attempt to grow an AWS EBS volume based on a CloudWatch alarm triggering a SNS topic.

An article ["Automated EBS expansion with xMatters"](https://pcmusings.wordpress.com/2020/11/24/automated-ebs-expansion-with-xmatters/) explains the workflow and the steps within the automation.

In addition to the steps, the `jsSHA` library from <https://coursesweb.net/javascript/jssha-hash-hmac> is required as a xMatters library for the workflow. A copy of the minimised code has been added to this repo to ensure that a copy is preserved. It is Copyright (c) 2008-2020 Brian Turek, 1998-2009 Paul Johnston & Contributors.
