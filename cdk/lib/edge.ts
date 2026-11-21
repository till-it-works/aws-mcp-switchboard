/** us-east-1 resources CloudFront needs: the ACM certificate and the WAF web ACL (CLOUDFRONT scope). */
import { Stack, Tags, type StackProps } from "aws-cdk-lib";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import type { Construct } from "constructs";

export interface DomainProps {
  /** Hostname of the switchboard, e.g. switchboard.example.com */
  name: string;
  /** Route 53 hosted zone that contains `name`. */
  zoneName: string;
  hostedZoneId: string;
}

export interface SwitchboardEdgeStackProps extends StackProps {
  domain: DomainProps;
  /** Requests per IP per 5 minutes before WAF blocks that IP. Default 300. */
  rateLimitPer5Min?: number;
}

export class SwitchboardEdgeStack extends Stack {
  readonly certificate: acm.ICertificate;
  readonly webAclArn: string;

  constructor(scope: Construct, id: string, props: SwitchboardEdgeStackProps) {
    if (props.env?.region !== "us-east-1") throw new Error("SwitchboardEdgeStack must be deployed to us-east-1 (CloudFront certificate and WAF scope)");
    super(scope, id, { ...props, crossRegionReferences: true });
    Tags.of(this).add("app", "aws-mcp-switchboard");

    const zone = route53.HostedZone.fromHostedZoneAttributes(this, "Zone", { zoneName: props.domain.zoneName, hostedZoneId: props.domain.hostedZoneId });
    // The id follows the domain: a new name gets a new cross-region export (the SSM writer never
    // overwrites an existing one), so CloudFront picks up the new certificate on a domain change.
    this.certificate = new acm.Certificate(this, `Certificate-${props.domain.name}`, { domainName: props.domain.name, validation: acm.CertificateValidation.fromDns(zone) });

    const metrics = (metricName: string) => ({ cloudWatchMetricsEnabled: true, metricName, sampledRequestsEnabled: true });
    const acl = new wafv2.CfnWebACL(this, "WebAcl", {
      scope: "CLOUDFRONT",
      defaultAction: { allow: {} },
      visibilityConfig: metrics("aws-mcp-switchboard"),
      rules: [
        {
          name: "RateLimitPerIp",
          priority: 0,
          action: { block: {} },
          statement: { rateBasedStatement: { limit: props.rateLimitPer5Min ?? 300, aggregateKeyType: "IP", evaluationWindowSec: 300 } },
          visibilityConfig: metrics("aws-mcp-switchboard-rate-limit"),
        },
      ],
    });
    this.webAclArn = acl.attrArn;
  }
}
