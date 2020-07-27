# aws-iam-access-key-rotation-enforcer

Enforces AWS IAM User Access Key Rotation by warning to a SNS topic, and then disabling keys after an expiry.

## How do I use this?
___

1. Fork & clone this repository
2. Install serverless, if you haven't got it already.
3. Install the Node dependencies: `$ yarn`
4. Update the notification email address by editing the `serverless.yml` file and changing the `notificationEmailAddress` to your email or a shared mailbox etc.
5. Deploy! `$ sls deploy`

## Disable keys

By default, this the disabling of key is turned off; for good reason! This software doesn't check if the key is in use, so its possible this will revoke/disable a key vital to your production systems. I'd suggest running this without the disabling of keys turned on to see what it would do, had it been turned on.

If you do decide you want this functionality, under the `TOPIC_ARN` line within the `serverless.yml` add:

`ACTUALLY_DISABLE_KEYS=true`

### Disclaimer
___

I take no responsibility for any issues caused by this software, including downtime caused by revoked keys. You have been warned!
