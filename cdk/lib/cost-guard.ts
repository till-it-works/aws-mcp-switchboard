/**
 * Hard cost caps for a public deployment:
 * invocation alarm → SNS (email + breaker Lambda that sets the switchboard's concurrency to 0) and a monthly budget.
 * The breaker stays tripped until `npm run breaker:reset`.
 */
import { fileURLToPath } from "node:url";
import { Duration, RemovalPolicy } from "aws-cdk-lib";
import * as budgets from "aws-cdk-lib/aws-budgets";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as actions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as sns from "aws-cdk-lib/aws-sns";
import * as subs from "aws-cdk-lib/aws-sns-subscriptions";
import { NodejsFunction, OutputFormat } from "aws-cdk-lib/aws-lambda-nodejs";
import { Construct } from "constructs";

export interface CostGuardProps {
  /** Receives alarm and budget notifications. */
  email: string;
  /** Monthly budget on tag app=aws-mcp-switchboard (activate the cost allocation tag). Default 5 USD. */
  budgetUsd?: number;
  /** Breaker trips above this many invocations in 5 minutes. Default 1000. */
  invocationsPer5Min?: number;
}

export class CostGuard extends Construct {
  constructor(scope: Construct, id: string, props: CostGuardProps & { target: lambda.IFunction }) {
    super(scope, id);

    const topic = new sns.Topic(this, "Alerts", { displayName: "aws-mcp-switchboard cost guard" });
    topic.addSubscription(new subs.EmailSubscription(props.email));

    const breaker = new NodejsFunction(this, "Breaker", {
      entry: fileURLToPath(new URL("../../lambda/breaker.ts", import.meta.url)),
      handler: "handler",
      runtime: lambda.Runtime.NODEJS_24_X,
      architecture: lambda.Architecture.ARM_64,
      memorySize: 128,
      timeout: Duration.seconds(30),
      environment: { TARGET_FUNCTION_NAME: props.target.functionName },
      logGroup: new logs.LogGroup(this, "BreakerLogs", { retention: logs.RetentionDays.TWO_WEEKS, removalPolicy: RemovalPolicy.DESTROY }),
      bundling: { format: OutputFormat.ESM, target: "node22", minify: true, bundleAwsSDK: true },
    });
    breaker.addToRolePolicy(new iam.PolicyStatement({ actions: ["lambda:PutFunctionConcurrency"], resources: [props.target.functionArn] }));
    topic.addSubscription(new subs.LambdaSubscription(breaker));

    const alarm = new cloudwatch.Alarm(this, "InvocationsAlarm", {
      alarmDescription: "aws-mcp-switchboard: invocation flood; the breaker set reserved concurrency to 0 (npm run breaker:reset)",
      metric: props.target.metricInvocations({ period: Duration.minutes(5), statistic: "Sum" }),
      threshold: props.invocationsPer5Min ?? 1000,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    alarm.addAlarmAction(new actions.SnsAction(topic));

    const notify = (notificationType: "ACTUAL" | "FORECASTED", threshold: number) => ({
      notification: { notificationType, comparisonOperator: "GREATER_THAN", threshold, thresholdType: "PERCENTAGE" },
      subscribers: [{ subscriptionType: "EMAIL", address: props.email }],
    });
    new budgets.CfnBudget(this, "Budget", {
      budget: {
        budgetType: "COST",
        timeUnit: "MONTHLY",
        budgetLimit: { amount: props.budgetUsd ?? 5, unit: "USD" },
        costFilters: { TagKeyValue: ["user:app$aws-mcp-switchboard"] },
      },
      notificationsWithSubscribers: [notify("ACTUAL", 80), notify("FORECASTED", 100)],
    });
  }
}
