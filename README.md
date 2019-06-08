# Check IAM Permissions

This script performs a simular function as AWS Web Console's
[Access Advisor](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html)
but instead generates CSV formatted report containing the identifying Name, Creation Date, Last Used Date, and Unused Permissions

---

### Requirements

Requires the [boto3](https://github.com/boto/boto3 "AWS SDK for Python") library installed

```sh

    $ pip install boto3
```

---

### Usage

> usage: check_iam_permissions.py [-h] [--user] [--role] [--group]

the options `--user` `--role` `--group` can be used to generate the respective reports individually.

Without arguments, all three reports will be generated with the file names
`role_permissions.csv`
`user_permissions.csv`
`group_permissions.csv`.


The script also takes the standard AWS authentication options `--profile`, `--region`, `--key` & '--secret'

---

### Output Example

|Role_Name|Created|Last_Used|Unused_Permissions|
| :--- | :--- | :--- | :--- |
Ec2_backoffice|20190501 20:35:30|20190501 20:42:00|cloudwatch dynamodb kinesis s3
task-role-web|20171102 18:17:06|20190608 02:48:00|cloudwatch firehose sns
ec2-role-batch|20170927 20:54:40|20171010 21:00:00|dynamodb sqs
lambda-role|20170804 20:49:15|Never|cloudwatch elasticache elasticloadbalancing logs rds
ec2-role-jenkins-slave|20170915 20:25:23|20190608 02:48:00|dynamodb ec2


