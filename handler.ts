import "source-map-support/register";
import * as AWS from "aws-sdk";
import { subDays } from "date-fns";
import { AccessKeyMetadata } from "aws-sdk/clients/iam";

/*
 * Variables & Configuration
 */
const MAXIUM_ACCESS_KEY_AGE_IN_DAYS = 90;
const WARN_ACCESS_KEY_AGE_IN_DAYS = 83;

const ACTUALLY_DISABLE_KEYS = false;

const iam = new AWS.IAM();

interface AccessKey extends AccessKeyMetadata {
  LastUsedDate?: Date;
}

interface KeyCategories {
  outdatedKeys: AccessKey[];
  upcomingKeys: AccessKey[];
}

const getCategorisedKeys = async (
  maxAge: Date,
  warnAge: Date
): Promise<KeyCategories> => {
  const userList = await iam.listUsers().promise();

  const outdatedKeys: AccessKey[] = [];
  const upcomingKeys: AccessKey[] = [];

  await Promise.all(
    userList.Users.map(async user => {
      var accessKeyList = await iam
        .listAccessKeys({ UserName: user.UserName })
        .promise();

      await Promise.all(
        accessKeyList.AccessKeyMetadata.map(async accessKey => {
          var lastUsed = (await iam
            .getAccessKeyLastUsed({ AccessKeyId: accessKey.AccessKeyId })
            .promise()).AccessKeyLastUsed;

          var keyWithLastUsed: AccessKey = {
            ...accessKey,
            LastUsedDate: lastUsed.LastUsedDate
          };

          if (accessKey.CreateDate < maxAge) {
            outdatedKeys.push(keyWithLastUsed);
            return;
          }

          if (accessKey.CreateDate < warnAge) {
            upcomingKeys.push(keyWithLastUsed);
            return;
          }
        })
      );
    })
  );

  return {
    outdatedKeys,
    upcomingKeys
  };
};

export const check = async () => {
  const maxAge = subDays(new Date(), MAXIUM_ACCESS_KEY_AGE_IN_DAYS);
  const warnAge = subDays(new Date(), WARN_ACCESS_KEY_AGE_IN_DAYS);

  try {
    const { outdatedKeys } = await getCategorisedKeys(maxAge, warnAge);

    // send keys warning

    if (!ACTUALLY_DISABLE_KEYS) return;

    Promise.all(
      outdatedKeys.map(async key => {
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
