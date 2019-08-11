import "source-map-support/register";
import * as AWS from "aws-sdk";
import { format, subDays } from "date-fns";
import { AccessKeyMetadata } from "aws-sdk/clients/iam";

/*
 * Variables & Configuration
 */
const MAXIMUM_ACCESS_KEY_AGE_IN_DAYS = Number.parseInt(process.env.MAXIMUM_ACCESS_KEY_AGE_IN_DAYS) || 90;
const WARN_ACCESS_KEY_AGE_IN_DAYS = Number.parseInt(process.env.MAXIUM_ACCESS_KEY_AGE_IN_DAYS) || 83;

const ACTUALLY_DISABLE_KEYS = process.env.DISABLE_KEYS == "true" || false;

const iam = new AWS.IAM();
const sns = new AWS.SNS();

interface AccessKey extends AccessKeyMetadata {
  LastUsedDate?: Date;
}

interface KeyCategories {
  expiredKeys: AccessKey[];
  warningKeys: AccessKey[];
}

const getCategorisedKeys = async (
  maxAge: Date,
  warnAge: Date
): Promise<KeyCategories> => {
  const userList = await iam.listUsers().promise();

  const expiredKeys: AccessKey[] = [];
  const warningKeys: AccessKey[] = [];

  await Promise.all(
    userList.Users.map(async user => {
      const accessKeyList = await iam
        .listAccessKeys({UserName: user.UserName})
        .promise();

      await Promise.all(
        accessKeyList.AccessKeyMetadata.map(async accessKey => {

          if(accessKey.Status === "Inactive") return;

          const lastUsed = (await iam
            .getAccessKeyLastUsed({AccessKeyId: accessKey.AccessKeyId})
            .promise()).AccessKeyLastUsed;

          const keyWithLastUsed: AccessKey = {
            ...accessKey,
            LastUsedDate: lastUsed.LastUsedDate
          };

          if (accessKey.CreateDate < maxAge) {
            expiredKeys.push(keyWithLastUsed);
            return;
          }

          if (accessKey.CreateDate < warnAge) {
            warningKeys.push(keyWithLastUsed);
            return;
          }
        })
      );
    })
  );

  return {
    expiredKeys,
    warningKeys
  };
};

const keyString = key =>  {
  return `${key.AccessKeyId} - Owned by: ${key.UserName} - Created: ${format(key.CreateDate, "MM/DD/YYYY HH:mm")} - Last Used: ${key.LastUsedDate ? format(key.LastUsedDate, "MM/DD/YYYY HH:mm") : "Never"}\n\n`;
};

export const check = async () => {
  const maxAge = subDays(new Date(), MAXIMUM_ACCESS_KEY_AGE_IN_DAYS);
  const warnAge = subDays(new Date(), WARN_ACCESS_KEY_AGE_IN_DAYS);

  try {
    const { expiredKeys, warningKeys } = await getCategorisedKeys(maxAge, warnAge);

    if(expiredKeys.length === 0 && warningKeys.length === 0) return;

    let content = `** AWS Access Key Expiry Alert! **\n
For security reasons the script that generates this email is ran regularly to enforce Access Key rotation.
Access Keys older than ${MAXIMUM_ACCESS_KEY_AGE_IN_DAYS} days old will be automatically de-activated.\n\n`;

    if (expiredKeys.length > 0) {
      content += `- Disabled Keys\n
The following keys have been disabled. A user with enough permissions can rotate to a new key. The key has not
been deleted, just encase the key is required for production (can be enabled quickly). Note that any re-activated
keys will be disabled again the next time this script runs.\n\n`;

      expiredKeys.forEach(key => {
        content += keyString(key);
      })
    }

    if (warningKeys.length > 0) {
      content = ` - Upcoming Keys\nThese keys will be disabled soon. You should act early to rotate!\n\n`;

      warningKeys.forEach(key => {
        content += keyString(key);
      })
    }

    console.log(content);

    let response = await sns.publish({
      TopicArn: process.env.TOPIC_ARN,
      Subject: "[ACTION REQUIRED] Access Key Rotation Report",
      Message: content
    }).promise();

    console.log(process.env.TOPIC_ARN, response);
    if (!ACTUALLY_DISABLE_KEYS) return;

    await Promise.all(
      expiredKeys.map(async key => {
        await iam
          .updateAccessKey({
            AccessKeyId: key.AccessKeyId,
            Status: "Inactive"
          })
          .promise();
      })
    );
  } catch (ex) {
    console.log(ex);
  }
};
