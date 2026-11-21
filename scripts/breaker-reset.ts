/**
 * Re-enable the switchboard after the cost breaker tripped: restores the reserved concurrency recorded
 * in the stack outputs (or removes the reservation when it was "none").
 *   AWS_PROFILE=<admin> AWS_REGION=eu-central-1 npm run breaker:reset -- [StackName]
 */
import { CloudFormationClient, DescribeStacksCommand } from "@aws-sdk/client-cloudformation";
import { DeleteFunctionConcurrencyCommand, GetFunctionConcurrencyCommand, LambdaClient, PutFunctionConcurrencyCommand } from "@aws-sdk/client-lambda";

const stackName = process.argv[2] ?? process.env.STACK_NAME ?? "AwsMcpSwitchboard";
const cfn = new CloudFormationClient({});
const lambda = new LambdaClient({});

const { Stacks } = await cfn.send(new DescribeStacksCommand({ StackName: stackName }));
const out = Object.fromEntries((Stacks?.[0]?.Outputs ?? []).map((o) => [o.OutputKey, o.OutputValue]));
const fn = out.FunctionName;
const reserved = out.ReservedConcurrency;
if (!fn || !reserved) throw new Error(`Stack ${stackName} has no FunctionName/ReservedConcurrency outputs`);

const before = (await lambda.send(new GetFunctionConcurrencyCommand({ FunctionName: fn }))).ReservedConcurrentExecutions;
if (reserved === "none") await lambda.send(new DeleteFunctionConcurrencyCommand({ FunctionName: fn }));
else await lambda.send(new PutFunctionConcurrencyCommand({ FunctionName: fn, ReservedConcurrentExecutions: Number(reserved) }));
console.log(`${fn}: reserved concurrency ${before ?? "none"} → ${reserved}`);
if (before !== 0) console.log("(the breaker was not tripped)");
