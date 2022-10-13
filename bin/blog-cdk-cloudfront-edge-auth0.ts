#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { BlogCdkCloudfrontEdgeAuth0Stack } from '../lib/blog-cdk-cloudfront-edge-auth0-stack';

const app = new cdk.App();
new BlogCdkCloudfrontEdgeAuth0Stack(app, 'BlogCdkCloudfrontEdgeAuth0Stack', {
  env: {
    region: 'us-east-1',
  }
});