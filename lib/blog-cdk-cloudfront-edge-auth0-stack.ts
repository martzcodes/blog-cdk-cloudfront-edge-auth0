import * as cdk from "aws-cdk-lib";
import { CfnOutput, RemovalPolicy } from "aws-cdk-lib";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import { CacheHeaderBehavior, CachePolicy, CacheQueryStringBehavior } from "aws-cdk-lib/aws-cloudfront";
import { S3Origin } from "aws-cdk-lib/aws-cloudfront-origins";
import { Effect, PolicyStatement } from "aws-cdk-lib/aws-iam";
import { Code, Runtime } from "aws-cdk-lib/aws-lambda";
import { RetentionDays } from "aws-cdk-lib/aws-logs";
import { BlockPublicAccess, Bucket, ObjectOwnership } from "aws-cdk-lib/aws-s3";
import { BucketDeployment, Source } from "aws-cdk-lib/aws-s3-deployment";
import { Secret } from "aws-cdk-lib/aws-secretsmanager";
import { Construct } from "constructs";
import { join } from "path";

export class BlogCdkCloudfrontEdgeAuth0Stack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const bucket = new Bucket(this, "Bucket", {
      removalPolicy: RemovalPolicy.DESTROY,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      objectOwnership: ObjectOwnership.BUCKET_OWNER_ENFORCED,
      autoDeleteObjects: true,
    });

    new BucketDeployment(this, "BucketDeployment", {
      destinationBucket: bucket,
      sources: [Source.asset(join(__dirname, "../dist"))],
    });

    const originAccessIdentity = new cloudfront.OriginAccessIdentity(
      this,
      "OriginAccessIdentity"
    );
    bucket.grantRead(originAccessIdentity);

    const authFn = new cloudfront.experimental.EdgeFunction(
      this,
      `CloudFrontAuthFn`,
      {
        code: Code.fromAsset(join(__dirname, "./auth-lambda/")),
        handler: "index.handler",
        runtime: Runtime.NODEJS_16_X,
        logRetention: RetentionDays.ONE_DAY,
      }
    );
    const secret = Secret.fromSecretNameV2(
      this,
      "Auth0Secret",
      "blog-cloudformation-edge/auth0"
    );
    secret.grantRead(authFn);

    const cloudFront = new cloudfront.Distribution(this, "Distribution", {
      defaultRootObject: "index.html",
      defaultBehavior: {
        origin: new S3Origin(bucket, { originAccessIdentity }),
        cachePolicy:new CachePolicy(this, `CachePolicy`, {
          cookieBehavior: cloudfront.CacheCookieBehavior.all(),
          queryStringBehavior: CacheQueryStringBehavior.all(),
        }),
        edgeLambdas: [
          {
            functionVersion: authFn.currentVersion,
            eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
          },
        ],
      },
    });

    new CfnOutput(this, `CloudFrontUrl`, {
      value: `https://${cloudFront.distributionDomainName}`,
    });
  }
}
